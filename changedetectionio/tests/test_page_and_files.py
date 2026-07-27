#!/usr/bin/env python3

import asyncio
import concurrent.futures
import hashlib
import json
import os
import threading
import time
from collections import defaultdict
from unittest.mock import Mock, patch

from flask import url_for

from changedetectionio.browser_steps.browser_steps import steppable_browser_interface
from changedetectionio.processors.page_and_files.linked_files import (
    _request_with_redirects,
    _verification_interval,
    discover_file_urls,
    fingerprint_file,
    fingerprint_files,
    render_snapshot,
)
from changedetectionio.processors.page_and_files.processor import perform_site_check
from changedetectionio.processors.text_json_diff.processor import (
    perform_site_check as text_site_check,
)

from .util import wait_for_all_checks


def write_manifest(datastore_path, links, text='Ratings page'):
    path = os.path.join(datastore_path, 'endpoint-test-page-and-files.json')
    with open(path, 'w', encoding='utf-8') as manifest_file:
        json.dump({'links': links, 'text': text}, manifest_file)


def test_page_and_files_discovers_downloads_without_head_checking_navigation():
    html = '''
        <base href="https://downloads.example.com/releases/">
        <a href="/about">About</a>
        <a href="report.PDF?version=2#page=3">Report</a>
        <a href="report.PDF?version=2#page=9">Same report</a>
        <a href="archive.zip">Archive</a>
        <a href="/download?id=42" download>Download</a>
        <a href="/images/logo.png">Logo</a>
        <a href="http://image/broken-report.pdf">Broken single-label host</a>
    '''
    assert discover_file_urls(html, 'https://example.com/path/page') == [
        'https://downloads.example.com/download?id=42',
        'https://downloads.example.com/releases/archive.zip',
        'https://downloads.example.com/releases/report.PDF?version=2',
    ]


class FakeSession:
    def close(self):
        return None


class FakeResponse:
    status_code = 200
    is_redirect = False

    def __init__(self, url):
        self.headers = {'Content-Length': '1', 'ETag': url}

    def close(self):
        return None

    def iter_content(self, chunk_size):
        return [b'x']


class FakeJSONResponse:
    status_code = 200

    def __init__(self, payload):
        self.payload = payload

    def json(self):
        return self.payload

    def close(self):
        return None


def test_kernel_controlled_navigation_is_bounded_and_uses_dom_content_loaded():
    observed = {}

    class Page:
        async def goto(self, url, **kwargs):
            observed.update({'url': url, **kwargs})
            return object()

    browser = steppable_browser_interface('https://example.com')
    browser.page = Page()
    browser.action_timeout = 45000
    asyncio.run(browser.action_goto_url(value='https://example.com/data'))

    assert observed == {
        'url': 'https://example.com/data',
        'timeout': 45000,
        'wait_until': 'domcontentloaded',
    }


def test_page_processor_uses_one_local_fingerprint_batch_call():
    state = {
        'files': {'https://files.example/report.pdf': {'sha256': 'digest'}},
        'discovered_count': 1,
        'truncated': False,
    }
    with (
        patch.dict(os.environ, {'LINKED_FILE_BATCH_URL': 'http://127.0.0.1:3100/fingerprint'}),
        patch('requests.post', return_value=FakeJSONResponse(state)) as post,
    ):
        result = fingerprint_files(
            ['https://files.example/report.pdf'],
            {},
            source_url='https://page.example/data',
            headers={'User-Agent': 'Soria'},
            proxies={'https': 'http://proxy.example:8080'},
            timeout=45,
        )

    assert result == state
    assert post.call_count == 1
    assert post.call_args.kwargs['json']['urls'] == ['https://files.example/report.pdf']
    assert post.call_args.kwargs['json']['source_url'] == 'https://page.example/data'
    assert post.call_args.kwargs['json']['proxies'] == {'https': 'http://proxy.example:8080'}


def test_blocked_metadata_is_resolved_in_one_batch_without_redownloading():
    class BlockedResponse(FakeResponse):
        status_code = 403

    urls = [f'https://files.example/report-{index}.pdf' for index in range(8)]
    previous = {
        'files': {
            url: {
                'url': url,
                'final_url': url,
                'etag': f'etag-{index}',
                'last_modified': '',
                'content_length': '10',
                'content_type': 'application/pdf',
                'sha256': f'sha-{index}',
                'last_hashed_at': time.time(),
                'check_metadata': {
                    'final_url': url,
                    'etag': f'etag-{index}',
                    'last_modified': '',
                    'content_length': '10',
                    'content_type': 'application/pdf',
                },
            }
            for index, url in enumerate(urls)
        }
    }
    batch = FakeJSONResponse({
        'results': [
            {
                'source_url': url,
                'final_url': url,
                'status': 200,
                'tier': 'kernel_stealth',
                'etag': f'etag-{index}',
                'content_length': '10',
                'content_type': 'application/pdf',
            }
            for index, url in enumerate(urls)
        ]
    })

    def request(self, method, url, **kwargs):
        assert method == 'HEAD'
        return BlockedResponse(url)

    with (
        patch.dict(
            os.environ,
            {
                'ALLOW_IANA_RESTRICTED_ADDRESSES': 'true',
                'LINKED_FILE_METADATA_BATCH_FALLBACK_URL': 'http://127.0.0.1:3100/metadata-batch',
                'LINKED_FILE_VERIFY_INTERVAL_SECONDS': '604800',
                'LINKED_FILE_VERIFY_JITTER_SECONDS': '0',
            },
        ),
        patch('requests.Session.request', new=request),
        patch('requests.post', return_value=batch) as post,
        patch('requests.get') as get,
    ):
        result = fingerprint_files(
            urls,
            previous,
            source_url='https://page.example/data',
            headers={'User-Agent': 'Soria'},
            proxies={},
            timeout=45,
        )

    assert len(result['files']) == 8
    assert result['fallback_metadata_count'] == 8
    assert all(not value.get('error') for value in result['files'].values())
    assert post.call_count == 1
    assert set(post.call_args.kwargs['json']['urls']) == set(urls)
    get.assert_not_called()


def test_large_failed_metadata_batch_preserves_hashes_without_individual_fallbacks():
    class BlockedResponse(FakeResponse):
        status_code = 403

    urls = [f'https://files.example/report-{index}.pdf' for index in range(8)]
    previous = {
        'files': {
            url: {
                'url': url,
                'final_url': url,
                'etag': f'etag-{index}',
                'last_modified': '',
                'content_length': '10',
                'content_type': 'application/pdf',
                'sha256': f'sha-{index}',
                'last_hashed_at': time.time(),
            }
            for index, url in enumerate(urls)
        }
    }
    failed_batch = FakeJSONResponse({
        'results': [
            {
                'source_url': url,
                'final_url': url,
                'status': 0,
                'error': 'Kernel metadata batch failed',
            }
            for url in urls
        ]
    })

    def request(self, method, url, **kwargs):
        assert method == 'HEAD'
        return BlockedResponse(url)

    with (
        patch.dict(
            os.environ,
            {
                'ALLOW_IANA_RESTRICTED_ADDRESSES': 'true',
                'LINKED_FILE_METADATA_BATCH_FALLBACK_URL': 'http://127.0.0.1:3100/metadata-batch',
                'LINKED_FILE_METADATA_FALLBACK_URL': 'http://127.0.0.1:3100/metadata',
                'LINKED_FILE_BINARY_FALLBACK_URL': 'http://127.0.0.1:3100/binary',
                'LINKED_FILE_INDIVIDUAL_FALLBACK_MAX_URLS': '4',
            },
        ),
        patch('requests.Session.request', new=request),
        patch('requests.post', return_value=failed_batch) as post,
        patch('requests.get') as fallback,
    ):
        result = fingerprint_files(
            urls,
            previous,
            source_url='https://page.example/data',
            headers={'User-Agent': 'Soria'},
            proxies={},
            timeout=45,
        )

    assert post.call_count == 1
    fallback.assert_not_called()
    assert result['deferred_metadata_count'] == len(urls)
    assert result['error_count'] == len(urls)
    assert all(result['files'][url]['sha256'] == previous['files'][url]['sha256'] for url in urls)
    assert all(
        result['files'][url]['error']
        == 'metadata batch unresolved; preserved previous fingerprint for retry'
        for url in urls
    )


def test_direct_file_checks_reuse_one_session_per_worker():
    created = []

    class Session:
        def __init__(self):
            created.append(self)

        def request(self, method, url, **kwargs):
            return FakeResponse(url)

        def close(self):
            return None

    urls = [f'https://files.example/report-{index}.pdf' for index in range(20)]
    previous = {
        'files': {
            url: {
                'url': url,
                'final_url': url,
                'etag': url,
                'last_modified': '',
                'content_length': '1',
                'content_type': '',
                'sha256': 'existing',
                'last_hashed_at': time.time(),
            }
            for url in urls
        }
    }
    with (
        patch.dict(os.environ, {'ALLOW_IANA_RESTRICTED_ADDRESSES': 'true', 'LINKED_FILE_HEAD_WORKERS': '2'}),
        patch('requests.Session', side_effect=Session),
    ):
        result = fingerprint_files(
            urls,
            previous,
            source_url='https://page.example/data',
            headers={'User-Agent': 'Soria'},
            proxies={},
            timeout=45,
        )

    assert len(result['files']) == 20
    assert 1 <= len(created) <= 2


def test_rate_limited_head_is_not_retried_through_the_waterfall():
    class RateLimitedResponse(FakeResponse):
        status_code = 429

    def request(self, method, url, **kwargs):
        return RateLimitedResponse(url)

    with (
        patch.dict(
            os.environ,
            {
                'ALLOW_IANA_RESTRICTED_ADDRESSES': 'true',
                'LINKED_FILE_METADATA_FALLBACK_URL': 'http://127.0.0.1:3100/metadata',
                'LINKED_FILE_BINARY_FALLBACK_URL': 'http://127.0.0.1:3100/binary',
            },
        ),
        patch('requests.Session.request', new=request),
        patch('requests.get') as fallback,
    ):
        result = fingerprint_file(
            'https://files.example/report.pdf',
            {},
            source_url='https://page.example/data',
            headers={'User-Agent': 'Soria'},
            proxies={},
            timeout=45,
            now=1,
        )

    assert result['error'] == 'HEAD returned HTTP 429; retry later'
    fallback.assert_not_called()


def test_linked_file_snapshot_is_stable_current_state_for_native_diffing():
    previous = {
        'files': [
            {
                'url': f'https://files.example/{index}.pdf',
                'content_length': '10',
                'last_modified': '',
                'etag': f'etag-{index}',
                'sha256': f'old-{index}',
            }
            for index in range(30)
        ],
        'discovered_count': 30,
        'truncated': False,
    }
    current = {
        **previous,
        'files': [
            {**item, 'sha256': item['sha256'].replace('old-', 'new-')}
            for item in previous['files']
        ],
    }

    previous_rendered = render_snapshot(previous)
    current_rendered = render_snapshot(current)

    assert previous_rendered.startswith('LINKED FILES\nhttps://files.example/0.pdf')
    assert current_rendered.startswith('LINKED FILES\nhttps://files.example/0.pdf')
    assert previous_rendered.count('\nhttps://files.example/') == 30
    assert current_rendered.count('\nhttps://files.example/') == 30
    assert 'sha256=old-0' in previous_rendered
    assert 'sha256=new-0' in current_rendered


def test_linked_file_snapshot_does_not_change_for_unchanged_catalog():
    snapshot = {
        'files': [
            {
                'url': 'https://files.example/report.pdf',
                'content_length': '10',
                'last_modified': '',
                'etag': 'etag',
                'sha256': 'same',
            }
        ],
        'discovered_count': 1,
        'truncated': False,
    }

    assert render_snapshot(snapshot) == (
        'LINKED FILES\n'
        'https://files.example/report.pdf | size=10 | modified=unknown | sha256=same'
    )


def test_linked_file_headers_do_not_leak_across_origins():
    observed = []

    def request(self, method, url, **kwargs):
        observed.append((url, dict(kwargs['headers'])))
        return FakeResponse(url)

    headers = {
        'Accept': 'application/octet-stream',
        'Authorization': 'Bearer secret',
        'Cookie': 'session=secret',
        'User-Agent': 'Soria',
        'X-API-Key': 'secret',
    }
    with (
        patch.dict(os.environ, {'ALLOW_IANA_RESTRICTED_ADDRESSES': 'true'}),
        patch('requests.Session.request', new=request),
    ):
        for file_url in ('https://cdn.example/file.pdf', 'https://origin.example/file.pdf'):
            fingerprint_file(
                file_url,
                {},
                source_url='https://origin.example/page',
                headers=headers,
                proxies={},
                timeout=5,
                now=1,
            )

    cross_origin_headers = observed[0][1]
    same_origin_headers = observed[2][1]
    assert cross_origin_headers == {'Accept': 'application/octet-stream', 'User-Agent': 'Soria'}
    assert same_origin_headers['Authorization'] == 'Bearer secret'
    assert same_origin_headers['Cookie'] == 'session=secret'


def test_linked_file_headers_do_not_leak_on_cross_origin_redirect():
    observed = []

    class RedirectResponse(FakeResponse):
        status_code = 302
        is_redirect = True

        def __init__(self, url):
            super().__init__(url)
            self.headers['Location'] = 'https://cdn.example/file.pdf'

    def request(self, method, url, **kwargs):
        observed.append((url, dict(kwargs['headers'])))
        if url == 'https://origin.example/redirect.pdf':
            return RedirectResponse(url)
        return FakeResponse(url)

    with (
        patch.dict(os.environ, {'ALLOW_IANA_RESTRICTED_ADDRESSES': 'true'}),
        patch('requests.Session.request', new=request),
    ):
        fingerprint_file(
            'https://origin.example/redirect.pdf',
            {},
            source_url='https://origin.example/page',
            headers={'Authorization': 'Bearer secret', 'User-Agent': 'Soria'},
            proxies={},
            timeout=5,
            now=1,
        )

    origin_headers = [headers for url, headers in observed if 'origin.example' in url]
    redirected_headers = [headers for url, headers in observed if 'cdn.example' in url]
    assert all(headers['Authorization'] == 'Bearer secret' for headers in origin_headers)
    assert all('Authorization' not in headers for headers in redirected_headers)
    assert all(headers['User-Agent'] == 'Soria' for headers in redirected_headers)


def test_linked_file_requests_keep_tls_verification_enabled():
    observed = []

    def request(self, method, url, **kwargs):
        observed.append(kwargs)
        return FakeResponse(url)

    with (
        patch.dict(os.environ, {'ALLOW_IANA_RESTRICTED_ADDRESSES': 'true'}),
        patch('requests.Session.request', new=request),
    ):
        session, response, _ = _request_with_redirects(
            'HEAD',
            'https://files.example/report.pdf',
            headers={},
            source_url='https://page.example/data',
            proxies={},
            timeout=5,
        )
        response.close()
        session.close()

    assert 'verify' not in observed[0]


def test_blocked_linked_file_uses_binary_waterfall_without_changing_source_identity():
    class BlockedResponse(FakeResponse):
        status_code = 403

    class WaterfallResponse(FakeResponse):
        def __init__(self):
            self.headers = {
                'Content-Length': '20',
                'Content-Type': 'application/zip',
                'X-Soria-Upstream-Final-URL': 'https%3A%2F%2Ffiles.example%2Freport.zip',
                'X-Soria-Waterfall-Tier': 'browser_use_proxy',
            }

        def iter_content(self, chunk_size):
            return [b'blocked file content']

    def request(self, method, url, **kwargs):
        return BlockedResponse(url)

    with (
        patch.dict(
            os.environ,
            {
                'ALLOW_IANA_RESTRICTED_ADDRESSES': 'true',
                'LINKED_FILE_BINARY_FALLBACK_URL': 'http://127.0.0.1:3100/binary',
            },
        ),
        patch('requests.Session.request', new=request),
        patch('requests.get', return_value=WaterfallResponse()) as fallback,
    ):
        result = fingerprint_file(
            'https://files.example/report.zip',
            {},
            source_url='https://page.example/data',
            headers={'User-Agent': 'Soria'},
            proxies={},
            timeout=5,
            now=1,
        )

    assert result['url'] == 'https://files.example/report.zip'
    assert result['final_url'] == 'https://files.example/report.zip'
    assert result['sha256'] == hashlib.sha256(b'blocked file content').hexdigest()
    assert result['fetch_route'] == 'binary_waterfall'
    assert result['waterfall_tier'] == 'browser_use_proxy'
    assert fallback.call_args.args[0] == (
        'http://127.0.0.1:3100/binary?url=https%3A%2F%2Ffiles.example%2Freport.zip'
    )
    assert fallback.call_args.kwargs['timeout'] == 120.0


def test_missing_link_does_not_use_binary_waterfall():
    class MissingResponse(FakeResponse):
        status_code = 404

    def request(self, method, url, **kwargs):
        return MissingResponse(url)

    with (
        patch.dict(
            os.environ,
            {
                'ALLOW_IANA_RESTRICTED_ADDRESSES': 'true',
                'LINKED_FILE_BINARY_FALLBACK_URL': 'http://127.0.0.1:3100/binary',
            },
        ),
        patch('requests.Session.request', new=request),
        patch('requests.get') as fallback,
    ):
        result = fingerprint_file(
            'https://files.example/missing.zip',
            {},
            source_url='https://page.example/data',
            headers={'User-Agent': 'Soria'},
            proxies={},
            timeout=5,
            now=1,
        )

    assert result['error'] == 'GET returned HTTP 404'
    fallback.assert_not_called()


def test_blocked_head_uses_metadata_waterfall_without_redownloading_unchanged_file():
    class BlockedResponse(FakeResponse):
        status_code = 403

    class MetadataResponse(FakeResponse):
        def __init__(self):
            self.headers = {
                'X-Soria-Upstream-Final-URL': 'https%3A%2F%2Ffiles.example%2Freport.zip',
                'X-Soria-Upstream-ETag': 'release-7',
                'X-Soria-Upstream-Last-Modified': 'Tue, 21 Jul 2026 10:00:00 GMT',
                # Some government servers return a stable but incorrect HEAD length.
                'X-Soria-Upstream-Content-Length': '20',
                'X-Soria-Upstream-Content-Type': 'application/zip',
                'X-Soria-Waterfall-Tier': 'kernel_stealth',
            }

    def request(self, method, url, **kwargs):
        return BlockedResponse(url)

    previous = {
        'final_url': 'https://files.example/report.zip',
        'etag': 'release-7',
        'last_modified': 'Tue, 21 Jul 2026 10:00:00 GMT',
        'content_length': '13667',
        'content_type': 'application/zip',
        'sha256': 'existing-sha',
        'last_hashed_at': 100,
        'check_metadata': {
            'final_url': 'https://files.example/report.zip',
            'etag': 'release-7',
            'last_modified': 'Tue, 21 Jul 2026 10:00:00 GMT',
            'content_length': '20',
            'content_type': 'application/zip',
        },
    }
    with (
        patch.dict(
            os.environ,
            {
                'ALLOW_IANA_RESTRICTED_ADDRESSES': 'true',
                'LINKED_FILE_METADATA_FALLBACK_URL': 'http://127.0.0.1:3100/metadata',
                'LINKED_FILE_BINARY_FALLBACK_URL': 'http://127.0.0.1:3100/binary',
                'LINKED_FILE_VERIFY_INTERVAL_SECONDS': '604800',
                'LINKED_FILE_VERIFY_JITTER_SECONDS': '0',
            },
        ),
        patch('requests.Session.request', new=request),
        patch('requests.get', return_value=MetadataResponse()) as fallback,
    ):
        result = fingerprint_file(
            'https://files.example/report.zip',
            previous,
            source_url='https://page.example/data',
            headers={'User-Agent': 'Soria'},
            proxies={},
            timeout=5,
            now=200,
        )

    assert result['sha256'] == 'existing-sha'
    assert result['content_length'] == '13667'
    assert result['check_metadata']['content_length'] == '20'
    assert result['metadata_route'] == 'metadata_waterfall'
    assert result['waterfall_tier'] == 'kernel_stealth'
    assert fallback.call_count == 1
    assert '/metadata?' in fallback.call_args.args[0]
    assert fallback.call_args.kwargs['timeout'] == 120.0


def test_linked_file_concurrency_is_globally_and_per_host_bounded():
    lock = threading.Lock()
    active = 0
    maximum_active = 0
    active_by_method = defaultdict(int)
    maximum_by_method = defaultdict(int)
    active_by_host = defaultdict(int)
    maximum_by_host = defaultdict(int)

    def request(method, url, **kwargs):
        nonlocal active, maximum_active
        host = url.split('/')[2]
        with lock:
            active += 1
            active_by_method[method] += 1
            active_by_host[host] += 1
            maximum_active = max(maximum_active, active)
            maximum_by_method[method] = max(maximum_by_method[method], active_by_method[method])
            maximum_by_host[host] = max(maximum_by_host[host], active_by_host[host])
        time.sleep(0.01)
        with lock:
            active -= 1
            active_by_method[method] -= 1
            active_by_host[host] -= 1
        return FakeSession(), FakeResponse(url), url

    watch_urls = [
        [f'https://host{watch % 3}.example/file-{watch}-{index}.pdf' for index in range(8)]
        for watch in range(10)
    ]
    environment = {
        'LINKED_FILE_GLOBAL_WORKERS': '4',
        'LINKED_FILE_PER_HOST_WORKERS': '2',
        'LINKED_FILE_HEAD_WORKERS': '8',
    }
    with (
        patch.dict(os.environ, environment),
        patch(
            'changedetectionio.processors.page_and_files.linked_files._request_with_redirects',
            side_effect=request,
        ),
        concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor,
    ):
        futures = [
            executor.submit(
                fingerprint_files,
                urls,
                {},
                source_url='https://page.example/data',
                headers={'User-Agent': 'Soria'},
                proxies={},
                timeout=5,
            )
            for urls in watch_urls
        ]
        for future in futures:
            assert len(future.result()['files']) == 8

    assert maximum_active <= 8
    assert maximum_by_method['HEAD'] <= 4
    assert maximum_by_method['GET'] <= 4
    assert max(maximum_by_host.values()) <= 2


def test_head_and_hash_concurrency_are_bounded_separately():
    lock = threading.Lock()
    active = defaultdict(int)
    maximum = defaultdict(int)

    def request(method, url, **kwargs):
        with lock:
            active[method] += 1
            maximum[method] = max(maximum[method], active[method])
        time.sleep(0.02)
        with lock:
            active[method] -= 1
        return FakeSession(), FakeResponse(url), url

    urls = [f'https://host{index % 10}.example/file-{index}.pdf' for index in range(80)]
    previous = {
        'files': {
            url: {
                'url': url,
                'final_url': url,
                'etag': url,
                'last_modified': '',
                'content_length': '1',
                'content_type': '',
                'sha256': 'existing',
                'last_hashed_at': time.time(),
            }
            for url in urls
        }
    }
    environment = {
        'LINKED_FILE_HEAD_GLOBAL_WORKERS': '16',
        'LINKED_FILE_HASH_WORKERS': '4',
        'LINKED_FILE_PER_HOST_WORKERS': '20',
        'LINKED_FILE_HEAD_WORKERS': '20',
    }
    with (
        patch.dict(os.environ, environment),
        patch(
            'changedetectionio.processors.page_and_files.linked_files._request_with_redirects',
            side_effect=request,
        ),
    ):
        fingerprint_files(
            urls,
            previous,
            source_url='https://page.example/data',
            headers={'User-Agent': 'Soria'},
            proxies={},
            timeout=5,
        )
        assert maximum['HEAD'] > 4
        assert maximum['HEAD'] <= 16
        assert maximum['GET'] == 0

        fingerprint_files(
            urls,
            {},
            source_url='https://page.example/data',
            headers={'User-Agent': 'Soria'},
            proxies={},
            timeout=5,
        )

    assert maximum['HEAD'] <= 16
    assert maximum['GET'] <= 4


def test_duplicate_file_checks_are_coalesced_without_crossing_credentials():
    result = {'url': 'https://files.example/shared.pdf', 'sha256': 'digest'}

    def check_once(*args, **kwargs):
        time.sleep(0.05)
        return result

    def call(headers, previous=None):
        return fingerprint_file(
            result['url'],
            previous or {},
            source_url='https://files.example/page',
            headers=headers,
            proxies={},
            timeout=5,
            now=1,
        )

    with (
        patch(
            'changedetectionio.processors.page_and_files.linked_files._fingerprint_file',
            side_effect=check_once,
        ) as underlying,
        concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor,
    ):
        futures = [executor.submit(call, {'Authorization': 'Bearer same'}) for _ in range(20)]
        assert all(future.result() == result for future in futures)
        assert underlying.call_count == 1

        first = executor.submit(call, {'Authorization': 'Bearer first'})
        second = executor.submit(call, {'Authorization': 'Bearer second'})
        assert first.result() == second.result() == result
        assert underlying.call_count == 3

        first = executor.submit(call, {}, {'sha256': 'digest', 'last_hashed_at': 1})
        second = executor.submit(call, {}, {'sha256': 'digest', 'last_hashed_at': 2})
        assert first.result() == second.result() == result
        assert underlying.call_count == 5


def test_full_hash_backstop_is_deterministically_spread():
    with patch.dict(
        os.environ,
        {
            'LINKED_FILE_VERIFY_INTERVAL_SECONDS': '604800',
            'LINKED_FILE_VERIFY_JITTER_SECONDS': '86400',
        },
    ):
        first = _verification_interval('https://files.example/first.pdf')
        assert first == _verification_interval('https://files.example/first.pdf')
        assert 561600 <= first <= 648000
        assert first != _verification_interval('https://files.example/second.pdf')

    with patch.dict(os.environ, {'LINKED_FILE_VERIFY_INTERVAL_SECONDS': '0'}):
        assert _verification_interval('https://files.example/first.pdf') == 0


def test_linked_file_state_is_saved_only_after_page_processing_succeeds():
    handler = object.__new__(perform_site_check)
    handler.linked_files_state = {'files': {}}
    handler.update_extra_watch_config = Mock()
    with patch.object(text_site_check, 'run_changedetection', side_effect=RuntimeError('page failed')):
        try:
            handler.run_changedetection({}, force_reprocess=False)
        except RuntimeError as exc:
            assert str(exc) == 'page failed'
        else:
            raise AssertionError('expected page processing failure')
    handler.update_extra_watch_config.assert_not_called()


def create_watch(client, live_server, datastore_path, *, fixed_metadata=False):
    file_path = os.path.join(datastore_path, 'endpoint-test-checksum.bin')
    with open(file_path, 'wb') as source_file:
        source_file.write(b'first file version')
    file_url = url_for(
        'test_checksum_endpoint',
        fixed_metadata='1' if fixed_metadata else None,
        _external=True,
    ).replace('.bin', '.zip')
    write_manifest(datastore_path, [file_url])

    datastore = client.application.config.get('DATASTORE')
    response = client.post(
        url_for('createwatch'),
        data=json.dumps({
            'url': url_for('test_page_and_files_endpoint', _external=True),
            'processor': 'page_and_files',
        }),
        headers={
            'content-type': 'application/json',
            'x-api-key': datastore.data['settings']['application']['api_access_token'],
        },
        follow_redirects=True,
    )
    assert response.status_code == 201
    wait_for_all_checks(client)
    return response.json['uuid'], file_url


def test_page_and_files_monitors_page_and_linked_file_in_one_watch(client, live_server, datastore_path):
    uuid, file_url = create_watch(client, live_server, datastore_path)
    watch = live_server.app.config['DATASTORE'].data['watching'][uuid]
    counter_path = os.path.join(datastore_path, 'endpoint-test-checksum-counts.json')

    assert len(watch.history) == 1
    first_snapshot = watch.get_history_snapshot(timestamp=list(watch.history.keys())[0])
    assert 'Ratings page' in first_snapshot
    assert 'LINKED FILES' in first_snapshot
    assert hashlib.sha256(b'first file version').hexdigest() in first_snapshot
    with open(counter_path, encoding='utf-8') as counter_file:
        assert json.load(counter_file) == {'GET': 1, 'HEAD': 1}

    client.get(url_for('ui.form_watch_checknow'), follow_redirects=True)
    wait_for_all_checks(client)
    assert len(watch.history) == 1
    with open(counter_path, encoding='utf-8') as counter_file:
        assert json.load(counter_file) == {'GET': 1, 'HEAD': 2}

    write_manifest(datastore_path, [file_url], text='Updated ratings page')
    client.get(url_for('ui.form_watch_checknow'), follow_redirects=True)
    wait_for_all_checks(client)
    assert len(watch.history) == 2
    assert 'Updated ratings page' in watch.get_history_snapshot(timestamp=list(watch.history.keys())[-1])

    with open(os.path.join(datastore_path, 'endpoint-test-checksum.bin'), 'wb') as source_file:
        source_file.write(b'second file version is longer')
    client.get(url_for('ui.form_watch_checknow'), follow_redirects=True)
    wait_for_all_checks(client)
    assert len(watch.history) == 3
    latest = watch.get_history_snapshot(timestamp=list(watch.history.keys())[-1])
    assert hashlib.sha256(b'second file version is longer').hexdigest() in latest
    with open(counter_path, encoding='utf-8') as counter_file:
        assert json.load(counter_file) == {'GET': 2, 'HEAD': 4}

    client.get(url_for('ui.form_watch_checknow'), follow_redirects=True)
    wait_for_all_checks(client)
    assert len(watch.history) == 3


def test_page_and_files_preloaded_first_check_includes_file_baseline(client, live_server, datastore_path):
    from changedetectionio.blueprint.ui.views import run_preloaded_first_check

    file_path = os.path.join(datastore_path, 'endpoint-test-checksum.bin')
    with open(file_path, 'wb') as source_file:
        source_file.write(b'preloaded file version')
    file_url = url_for('test_checksum_endpoint', _external=True).replace('.bin', '.zip')
    datastore = client.application.config.get('DATASTORE')
    uuid = datastore.add_watch(
        url='https://example.com/preloaded-page',
        extras={'paused': True, 'processor': 'page_and_files'},
    )
    watch = datastore.data['watching'][uuid]
    watch.ensure_data_dir_exists()
    with open(os.path.join(watch.data_dir, 'preload-fetch.json'), 'w', encoding='utf-8') as preload_file:
        json.dump({
            'content': f'<html><body><a href="{file_url}">File</a></body></html>',
            'status_code': 200,
            'headers': {'content-type': 'text/html'},
        }, preload_file)

    assert run_preloaded_first_check(datastore, uuid)

    snapshot = watch.get_history_snapshot(timestamp=list(watch.history.keys())[-1])
    assert hashlib.sha256(b'preloaded file version').hexdigest() in snapshot


def test_page_and_files_weekly_hash_catches_same_metadata_replacement(client, live_server, datastore_path):
    with patch.dict(os.environ, {'LINKED_FILE_VERIFY_INTERVAL_SECONDS': '0'}):
        uuid, _ = create_watch(client, live_server, datastore_path, fixed_metadata=True)
        with open(os.path.join(datastore_path, 'endpoint-test-checksum.bin'), 'wb') as source_file:
            source_file.write(b'other file version')
        client.get(url_for('ui.form_watch_checknow'), follow_redirects=True)
        wait_for_all_checks(client)

    watch = live_server.app.config['DATASTORE'].data['watching'][uuid]
    assert len(watch.history) == 2
    latest = watch.get_history_snapshot(timestamp=list(watch.history.keys())[-1])
    assert hashlib.sha256(b'other file version').hexdigest() in latest


def test_page_and_files_detects_link_removal(client, live_server, datastore_path):
    uuid, file_url = create_watch(client, live_server, datastore_path)
    write_manifest(datastore_path, [])
    client.get(url_for('ui.form_watch_checknow'), follow_redirects=True)
    wait_for_all_checks(client)

    watch = live_server.app.config['DATASTORE'].data['watching'][uuid]
    assert len(watch.history) == 2
    latest = watch.get_history_snapshot(timestamp=list(watch.history.keys())[-1])
    assert 'LINKED FILES\n(none discovered)' in latest
    assert file_url not in latest
