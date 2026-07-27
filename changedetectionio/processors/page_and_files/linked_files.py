import concurrent.futures
import hashlib
import json
import os
import threading
import time
from contextlib import contextmanager
from urllib.parse import quote, unquote, urldefrag, urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from changedetectionio import strtobool
from changedetectionio.validate_url import is_url_private_or_parser_confused

FILE_EXTENSIONS = frozenset({
    '.7z', '.csv', '.doc', '.docx', '.gz', '.json', '.ods', '.odt', '.pdf',
    '.ppt', '.pptx', '.rar', '.tar', '.tgz', '.tsv', '.txt', '.xls', '.xlsb',
    '.xlsm', '.xlsx', '.xml', '.zip',
})
METADATA_KEYS = ('final_url', 'etag', 'last_modified', 'content_length', 'content_type')
_SAFE_CROSS_ORIGIN_HEADERS = frozenset({'accept', 'accept-language', 'user-agent'})
_limiter_lock = threading.Lock()
_global_limiters = {}
_host_limiters = {}
_host_rate_lock = threading.Lock()
_host_next_request = {}
_inflight_lock = threading.Lock()
_inflight_fingerprints = {}


def _origin(url):
    parsed = urlparse(url)
    default_port = 443 if parsed.scheme.lower() == 'https' else 80
    return parsed.scheme.lower(), (parsed.hostname or '').lower(), parsed.port or default_port


def _headers_for_url(headers, source_url, request_url):
    if source_url and _origin(source_url) != _origin(request_url):
        return {
            key: value for key, value in headers.items() if key.lower() in _SAFE_CROSS_ORIGIN_HEADERS
        }
    return headers


def _worker_limit(name, default):
    legacy_limit = os.getenv('LINKED_FILE_GLOBAL_WORKERS')
    return max(1, int(os.getenv(name, legacy_limit or default)))


def _wait_for_host_rate(url):
    requests_per_second = float(os.getenv('LINKED_FILE_PER_HOST_RPS', '0') or 0)
    if requests_per_second <= 0:
        return
    hostname = (urlparse(url).hostname or '').lower()
    spacing = 1 / requests_per_second
    with _host_rate_lock:
        now = time.monotonic()
        slot = max(now, _host_next_request.get(hostname, now))
        _host_next_request[hostname] = slot + spacing
    delay = slot - now
    if delay > 0:
        time.sleep(delay)


@contextmanager
def _request_capacity(url, phase):
    setting = 'LINKED_FILE_HEAD_GLOBAL_WORKERS' if phase == 'head' else 'LINKED_FILE_HASH_WORKERS'
    default = '16' if phase == 'head' else '4'
    global_limit = _worker_limit(setting, default)
    per_host_limit = max(1, int(os.getenv('LINKED_FILE_PER_HOST_WORKERS', '2')))
    hostname = (urlparse(url).hostname or '').lower()
    with _limiter_lock:
        global_limiter = _global_limiters.setdefault(
            (phase, global_limit),
            threading.BoundedSemaphore(global_limit),
        )
        host_limiter = _host_limiters.setdefault(
            (per_host_limit, hostname),
            threading.BoundedSemaphore(per_host_limit),
        )
    with global_limiter:
        with host_limiter:
            _wait_for_host_rate(url)
            yield


def _verification_interval(url):
    interval = int(os.getenv('LINKED_FILE_VERIFY_INTERVAL_SECONDS', '604800'))
    if interval <= 0:
        return 0
    jitter = min(interval, max(0, int(os.getenv('LINKED_FILE_VERIFY_JITTER_SECONDS', '86400'))))
    if not jitter:
        return interval
    offset = int.from_bytes(hashlib.sha256(url.encode()).digest()[:8], 'big') % (jitter + 1)
    return max(1, interval - jitter // 2 + offset)


def _fingerprint_key(url, previous, *, source_url, headers, proxies, timeout, now, checked_metadata=None):
    previous = previous or {}
    cache_scope = {
        'url': url,
        'source_origin': _origin(source_url) if source_url else None,
        'headers': sorted(_headers_for_url(headers, source_url, url).items()),
        'proxies': sorted((proxies or {}).items()),
        'timeout': timeout,
        'previous': {
            **{key: previous.get(key, '') for key in (*METADATA_KEYS, 'sha256', 'last_hashed_at')},
            'check_metadata': previous.get('check_metadata') or {},
        },
        'verification_due': now - float(previous.get('last_hashed_at') or 0) >= _verification_interval(url),
        'checked_metadata': checked_metadata,
    }
    return hashlib.sha256(json.dumps(cache_scope, sort_keys=True, default=str).encode()).hexdigest()


def discover_file_urls(html, page_url):
    soup = BeautifulSoup(html, 'html.parser')
    base = soup.find('base', href=True)
    effective_base_url = urljoin(page_url, base.get('href')) if base else page_url
    urls = set()
    for anchor in soup.select('a[href]'):
        href = (anchor.get('href') or '').strip()
        if not href or href.startswith(('#', 'data:', 'javascript:', 'mailto:', 'tel:')):
            continue
        absolute_url = urldefrag(urljoin(effective_base_url, href)).url
        parsed_url = urlparse(absolute_url)
        path = parsed_url.path.lower()
        is_download = anchor.has_attr('download') or any(path.endswith(ext) for ext in FILE_EXTENSIONS)
        hostname = parsed_url.hostname or ''
        if is_download and parsed_url.scheme in ('http', 'https') and '.' in hostname:
            urls.add(absolute_url)
    return sorted(urls)


def _request_with_redirects(
    method,
    url,
    *,
    headers,
    source_url,
    proxies,
    timeout,
    stream=False,
    session=None,
):
    allow_private = strtobool(os.getenv('ALLOW_IANA_RESTRICTED_ADDRESSES', 'false'))
    current_url = url
    owns_session = session is None
    session = session or requests.Session()
    try:
        for _ in range(10):
            if not allow_private and is_url_private_or_parser_confused(current_url):
                raise ValueError(f"Linked-file request blocked for private or reserved URL: {current_url}")
            response = session.request(
                method,
                current_url,
                allow_redirects=False,
                headers=_headers_for_url(headers, source_url, current_url),
                proxies=proxies,
                stream=stream,
                timeout=timeout,
            )
            if not response.is_redirect:
                return session, response, current_url
            location = response.headers.get('Location')
            response.close()
            if not location:
                raise ValueError(f"Linked-file redirect had no Location header: {current_url}")
            current_url = urljoin(current_url, location)
        raise ValueError(f"Too many redirects while checking linked file: {url}")
    except Exception:
        if owns_session:
            session.close()
        raise


def _metadata(url, final_url, headers):
    return {
        'url': url,
        'final_url': final_url,
        'etag': headers.get('ETag') or '',
        'last_modified': headers.get('Last-Modified') or '',
        'content_length': headers.get('Content-Length') or '',
        'content_type': headers.get('Content-Type') or '',
    }


def _fallback_timeout(timeout):
    return max(float(timeout or 0), float(os.getenv('LINKED_FILE_FALLBACK_TIMEOUT_SECONDS', '120')))


def _binary_fallback(url, *, timeout):
    base_url = os.getenv('LINKED_FILE_BINARY_FALLBACK_URL', '').strip()
    if not base_url:
        raise ValueError('binary fallback is not configured')
    separator = '&' if '?' in base_url else '?'
    fallback_url = f'{base_url}{separator}url={quote(url, safe="")}'
    response = requests.get(fallback_url, allow_redirects=False, stream=True, timeout=_fallback_timeout(timeout))
    if not 200 <= response.status_code < 300:
        response.close()
        raise ValueError(f'binary fallback returned HTTP {response.status_code}')
    encoded_final_url = response.headers.get('X-Soria-Upstream-Final-URL') or ''
    final_url = unquote(encoded_final_url) if encoded_final_url else url
    return response, final_url


def _metadata_fallback(url, *, timeout):
    base_url = os.getenv('LINKED_FILE_METADATA_FALLBACK_URL', '').strip()
    if not base_url:
        raise ValueError('metadata fallback is not configured')
    separator = '&' if '?' in base_url else '?'
    fallback_url = f'{base_url}{separator}url={quote(url, safe="")}'
    response = requests.get(fallback_url, allow_redirects=False, timeout=_fallback_timeout(timeout))
    try:
        if not 200 <= response.status_code < 300:
            raise ValueError(f'metadata fallback returned HTTP {response.status_code}')
        encoded_final_url = response.headers.get('X-Soria-Upstream-Final-URL') or ''
        final_url = unquote(encoded_final_url) if encoded_final_url else url
        upstream_headers = {
            'ETag': response.headers.get('X-Soria-Upstream-ETag') or '',
            'Last-Modified': response.headers.get('X-Soria-Upstream-Last-Modified') or '',
            'Content-Length': response.headers.get('X-Soria-Upstream-Content-Length') or '',
            'Content-Type': response.headers.get('X-Soria-Upstream-Content-Type') or '',
        }
        return _metadata(url, final_url, upstream_headers), response.headers.get('X-Soria-Waterfall-Tier') or ''
    finally:
        response.close()


def _metadata_fallback_batch(urls, *, timeout):
    base_url = os.getenv('LINKED_FILE_METADATA_BATCH_FALLBACK_URL', '').strip()
    if not base_url or not urls:
        return {}
    response = requests.post(
        base_url,
        json={'urls': list(urls)},
        timeout=_fallback_timeout(timeout),
    )
    try:
        if not 200 <= response.status_code < 300:
            raise ValueError(f'metadata batch fallback returned HTTP {response.status_code}')
        payload = response.json()
    finally:
        response.close()

    results = {}
    for item in payload.get('results') or []:
        url = str(item.get('source_url') or '')
        if url not in urls:
            continue
        status = int(item.get('status') or 0)
        headers = {
            'ETag': item.get('etag') or '',
            'Last-Modified': item.get('last_modified') or '',
            'Content-Length': item.get('content_length') or '',
            'Content-Type': item.get('content_type') or '',
        }
        results[url] = (
            _metadata(url, str(item.get('final_url') or url), headers),
            200 <= status < 300,
            'metadata_waterfall',
            str(item.get('tier') or ''),
            status,
        )
    return results


def _hash_response(url, response, final_url, *, now, fetch_route):
    max_bytes = int(os.getenv('LINKED_FILE_MAX_BYTES', str(250 * 1024 * 1024)))
    declared_length = response.headers.get('Content-Length')
    try:
        declared_byte_count = int(declared_length) if declared_length else None
    except ValueError:
        declared_byte_count = None
    if declared_byte_count is not None and declared_byte_count > max_bytes:
        raise ValueError(f'file is {declared_byte_count} bytes; limit is {max_bytes} bytes')

    digest = hashlib.sha256()
    byte_count = 0
    for chunk in response.iter_content(chunk_size=1024 * 1024):
        if not chunk:
            continue
        byte_count += len(chunk)
        if byte_count > max_bytes:
            raise ValueError(f'file exceeded the {max_bytes}-byte limit')
        digest.update(chunk)
    metadata = _metadata(url, final_url, response.headers)
    if not metadata['content_length']:
        metadata['content_length'] = str(byte_count)
    return {
        **metadata,
        'sha256': digest.hexdigest(),
        'last_hashed_at': now,
        'fetch_route': fetch_route,
        **(
            {'waterfall_tier': response.headers['X-Soria-Waterfall-Tier']}
            if response.headers.get('X-Soria-Waterfall-Tier')
            else {}
        ),
    }


def _check_metadata(url, *, source_url, headers, proxies, timeout, session, allow_fallback=True):
    metadata_route = 'direct'
    metadata_tier = ''
    try:
        with _request_capacity(url, 'head'):
            _, head, final_url = _request_with_redirects(
                'HEAD',
                url,
                headers=headers,
                source_url=source_url,
                proxies=proxies,
                timeout=timeout,
                session=session,
            )
            try:
                head_supported = 200 <= head.status_code < 300
                head_status = head.status_code
                metadata = _metadata(url, final_url, head.headers)
            finally:
                head.close()
        should_fallback = not head_supported and (
            head_status in {401, 403, 407, 451} or head_status >= 500
        )
    except (requests.RequestException, OSError):
        head_supported = False
        head_status = 0
        metadata = _metadata(url, url, {})
        should_fallback = True

    if allow_fallback and should_fallback and os.getenv('LINKED_FILE_METADATA_FALLBACK_URL', '').strip():
        try:
            metadata, metadata_tier = _metadata_fallback(url, timeout=timeout)
            metadata_route = 'metadata_waterfall'
            head_supported = True
            head_status = 200
        except Exception:
            pass
    return metadata, head_supported, metadata_route, metadata_tier, head_status


def _download_and_hash(url, *, source_url, headers, proxies, timeout, session, now):
    response = None
    with _request_capacity(url, 'hash'):
        try:
            try:
                _, response, final_url = _request_with_redirects(
                    'GET',
                    url,
                    headers=headers,
                    source_url=source_url,
                    proxies=proxies,
                    timeout=timeout,
                    stream=True,
                    session=session,
                )
                if not 200 <= response.status_code < 300:
                    status_code = response.status_code
                    response.close()
                    response = None
                    if status_code == 429:
                        raise ValueError('GET returned HTTP 429; retry later')
                    if status_code not in {401, 403, 407, 429, 451} and status_code < 500:
                        raise ValueError(f'GET returned HTTP {status_code}')
                    raise requests.HTTPError(f'GET returned HTTP {status_code}')
                return _hash_response(url, response, final_url, now=now, fetch_route='direct')
            except (requests.RequestException, OSError):
                if response is not None:
                    response.close()
                if not os.getenv('LINKED_FILE_BINARY_FALLBACK_URL', '').strip():
                    raise
                response, final_url = _binary_fallback(url, timeout=timeout)
                return _hash_response(url, response, final_url, now=now, fetch_route='binary_waterfall')
        finally:
            if response is not None:
                response.close()


def _fingerprint_file(
    url,
    previous,
    *,
    source_url,
    headers,
    proxies,
    timeout,
    now,
    checked_metadata=None,
    request_session=None,
):
    previous = previous or {}
    owns_session = request_session is None
    request_session = request_session or requests.Session()
    try:
        if checked_metadata is None:
            checked_metadata = _check_metadata(
                url,
                source_url=source_url,
                headers=headers,
                proxies=proxies,
                timeout=timeout,
                session=request_session,
            )
        metadata, head_supported, metadata_route, metadata_tier, head_status = checked_metadata
        if head_status == 429:
            raise ValueError('HEAD returned HTTP 429; retry later')
        if metadata_route == 'metadata_deferred':
            raise ValueError('metadata batch unresolved; preserved previous fingerprint for retry')

        previous_check_metadata = previous.get('check_metadata') or {
            key: previous.get(key, '') for key in METADATA_KEYS
        }
        metadata_changed = any(
            str(previous_check_metadata.get(key, '')) != str(metadata[key]) for key in METADATA_KEYS
        )
        reliable_headers = bool(metadata['etag'] or metadata['last_modified'] or metadata['content_length'])
        needs_hash = (
            not previous.get('sha256')
            or metadata_changed
            or not reliable_headers
            or not head_supported
            or now - float(previous.get('last_hashed_at') or 0) >= _verification_interval(url)
        )

        if not needs_hash:
            return {
                'url': url,
                **{key: previous.get(key, metadata[key]) for key in METADATA_KEYS},
                'sha256': previous['sha256'],
                'last_hashed_at': previous['last_hashed_at'],
                'check_metadata': {key: metadata[key] for key in METADATA_KEYS},
                'fetch_route': previous.get('fetch_route', ''),
                'metadata_route': metadata_route,
                **({'waterfall_tier': metadata_tier} if metadata_route == 'metadata_waterfall' else {}),
            }

        result = _download_and_hash(
            url,
            source_url=source_url,
            headers=headers,
            proxies=proxies,
            timeout=timeout,
            session=request_session,
            now=now,
        )
        result['check_metadata'] = {key: metadata[key] for key in METADATA_KEYS}
        result['metadata_route'] = metadata_route
        return result
    except Exception as exc:
        preserved = {
            key: previous.get(key, '')
            for key in (
                *METADATA_KEYS,
                'sha256',
                'last_hashed_at',
                'fetch_route',
                'metadata_route',
                'waterfall_tier',
                'check_metadata',
            )
        }
        if checked_metadata is not None and checked_metadata[2] == 'metadata_deferred':
            preserved['metadata_route'] = 'metadata_deferred'
        return {'url': url, **preserved, 'error': str(exc)[:300]}
    finally:
        if owns_session:
            request_session.close()


def fingerprint_file(
    url,
    previous,
    *,
    source_url,
    headers,
    proxies,
    timeout,
    now,
    checked_metadata=None,
    request_session=None,
):
    key = _fingerprint_key(
        url,
        previous,
        source_url=source_url,
        headers=headers,
        proxies=proxies,
        timeout=timeout,
        now=now,
        checked_metadata=checked_metadata,
    )
    with _inflight_lock:
        future = _inflight_fingerprints.get(key)
        owner = future is None
        if owner:
            future = concurrent.futures.Future()
            _inflight_fingerprints[key] = future
    if not owner:
        return dict(future.result())

    try:
        result = _fingerprint_file(
            url,
            previous,
            source_url=source_url,
            headers=headers,
            proxies=proxies,
            timeout=timeout,
            now=now,
            checked_metadata=checked_metadata,
            request_session=request_session,
        )
        future.set_result(result)
        return result
    except BaseException as exc:
        future.set_exception(exc)
        raise
    finally:
        with _inflight_lock:
            _inflight_fingerprints.pop(key, None)


def _fingerprint_files_remote(urls, previous_state, *, source_url, headers, proxies, timeout):
    batch_url = os.getenv('LINKED_FILE_BATCH_URL', '').strip()
    response = requests.post(
        batch_url,
        json={
            'source_url': source_url,
            'urls': list(urls),
            'previous_state': previous_state or {},
            'headers': dict(headers or {}),
            'proxies': dict(proxies or {}),
            'timeout': timeout,
        },
        timeout=float(os.getenv('LINKED_FILE_BATCH_TIMEOUT_SECONDS', '540')),
    )
    try:
        if not 200 <= response.status_code < 300:
            raise ValueError(f'linked-file batch returned HTTP {response.status_code}')
        state = response.json()
    finally:
        response.close()
    if not isinstance(state, dict) or not isinstance(state.get('files'), dict):
        raise ValueError('linked-file batch returned invalid state')
    return state


def _fingerprint_files_local(urls, previous_state, *, source_url, headers, proxies, timeout):
    scan_started = time.monotonic()
    maximum = max(1, int(os.getenv('LINKED_FILE_MAX_LINKS', '200')))
    selected_urls = list(urls[:maximum])
    if len(selected_urls) > 1:
        offset = (
            int.from_bytes(hashlib.sha256((source_url or '').encode()).digest()[:8], 'big')
            % len(selected_urls)
        )
        selected_urls = selected_urls[offset:] + selected_urls[:offset]
    previous_files = (previous_state or {}).get('files') or {}
    now = time.time()
    worker_limit = max(1, int(os.getenv('LINKED_FILE_HEAD_WORKERS', '2')))
    workers = min(worker_limit, max(1, len(selected_urls)))
    session_local = threading.local()
    sessions = []
    sessions_lock = threading.Lock()

    def worker_session():
        session = getattr(session_local, 'session', None)
        if session is None:
            session = requests.Session()
            session_local.session = session
            with sessions_lock:
                sessions.append(session)
        return session

    def direct_metadata(url):
        return url, _check_metadata(
            url,
            source_url=source_url,
            headers=headers,
            proxies=proxies,
            timeout=timeout,
            session=worker_session(),
            allow_fallback=False,
        )

    def check(url):
        return url, fingerprint_file(
            url,
            previous_files.get(url),
            source_url=source_url,
            headers=headers,
            proxies=proxies,
            timeout=timeout,
            now=now,
            checked_metadata=metadata_results[url],
            request_session=worker_session(),
        )

    files = {}
    metadata_results = {}
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            metadata_results.update(executor.map(direct_metadata, selected_urls))
            fallback_urls = [
                url
                for url, (_, supported, _, _, status) in metadata_results.items()
                if not supported and (status == 0 or status in {401, 403, 407, 451} or status >= 500)
            ]
            batch_fallback_configured = bool(
                os.getenv('LINKED_FILE_METADATA_BATCH_FALLBACK_URL', '').strip()
            )
            try:
                metadata_results.update(_metadata_fallback_batch(fallback_urls, timeout=timeout))
            except Exception:
                pass

            unresolved = [url for url in fallback_urls if not metadata_results[url][1]]

            def individual_fallback(url):
                try:
                    metadata, tier = _metadata_fallback(url, timeout=timeout)
                except Exception:
                    return url, metadata_results[url]
                return url, (metadata, True, 'metadata_waterfall', tier, 200)

            individual_limit = max(
                0,
                int(os.getenv('LINKED_FILE_INDIVIDUAL_FALLBACK_MAX_URLS', '4')),
            )
            individual_urls = (
                unresolved
                if not batch_fallback_configured or len(unresolved) <= individual_limit
                else []
            )
            metadata_results.update(executor.map(individual_fallback, individual_urls))

            deferred_urls = [url for url in unresolved if not metadata_results[url][1]]
            metadata_results.update(
                (
                    url,
                    (
                        metadata_results[url][0],
                        False,
                        'metadata_deferred',
                        metadata_results[url][3],
                        metadata_results[url][4],
                    ),
                )
                for url in deferred_urls
            )
            for url, result in executor.map(check, selected_urls):
                files[url] = result
    finally:
        for session in sessions:
            session.close()

    return {
        'files': files,
        'discovered_count': len(urls),
        'truncated': len(urls) > maximum,
        'scan_duration_seconds': round(time.monotonic() - scan_started, 3),
        'direct_metadata_count': sum(value.get('metadata_route') == 'direct' for value in files.values()),
        'fallback_metadata_count': sum(
            value.get('metadata_route') == 'metadata_waterfall' for value in files.values()
        ),
        'deferred_metadata_count': sum(
            value.get('metadata_route') == 'metadata_deferred' for value in files.values()
        ),
        'error_count': sum(bool(value.get('error')) for value in files.values()),
    }


def fingerprint_files(urls, previous_state, *, source_url, headers, proxies, timeout):
    if os.getenv('LINKED_FILE_BATCH_URL', '').strip():
        return _fingerprint_files_remote(
            urls,
            previous_state,
            source_url=source_url,
            headers=headers,
            proxies=proxies,
            timeout=timeout,
        )
    return _fingerprint_files_local(
        urls,
        previous_state,
        source_url=source_url,
        headers=headers,
        proxies=proxies,
        timeout=timeout,
    )


def stable_snapshot(state):
    files = []
    for url, value in sorted((state.get('files') or {}).items()):
        files.append({
            'url': url,
            **{key: value.get(key, '') for key in (*METADATA_KEYS, 'sha256')},
            **({'error': value['error']} if value.get('error') else {}),
        })
    return {
        'files': files,
        'discovered_count': state.get('discovered_count', len(files)),
        'truncated': bool(state.get('truncated')),
    }


def render_snapshot(snapshot):
    lines = ['LINKED FILES']
    if not snapshot['files']:
        lines.append('(none discovered)')
    for item in snapshot['files']:
        line = item['url']
        if item.get('error'):
            line += f" | error={item['error']}"
        else:
            line += (
                f" | size={item['content_length'] or 'unknown'}"
                f" | modified={item['last_modified'] or 'unknown'}"
                f" | sha256={item['sha256'] or 'unavailable'}"
            )
        lines.append(line)
    if snapshot['truncated']:
        lines.append(
            f"WARNING: only the first {len(snapshot['files'])} of "
            f"{snapshot['discovered_count']} files were checked"
        )
    return '\n'.join(lines)
