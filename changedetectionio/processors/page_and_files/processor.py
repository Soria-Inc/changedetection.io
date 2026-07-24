import asyncio
import hashlib
import json

from requests.structures import CaseInsensitiveDict

from changedetectionio.jinja2_custom import render as jinja_render
from changedetectionio.processors.page_and_files.linked_files import (
    discover_file_urls,
    fingerprint_files,
    render_snapshot,
    stable_snapshot,
)
from changedetectionio.processors.text_json_diff.processor import (
    perform_site_check as text_site_check,
)

name = 'Webpage and linked file changes'
description = 'Detects normal page changes plus byte-level changes to linked documents and archives'
processor_weight = -90
list_badge_text = 'Page + files'


class perform_site_check(text_site_check):
    async def call_browser(self, preferred_proxy_id=None):
        await super().call_browser(preferred_proxy_id=preferred_proxy_id)
        if not isinstance(self.fetcher.content, str):
            return

        urls = discover_file_urls(self.fetcher.content, self.watch.link)
        request_headers = CaseInsensitiveDict()
        default_ua = self.datastore.data['settings']['requests'].get('default_ua') or {}
        request_headers.update({'User-Agent': default_ua.get('html_requests')} if default_ua.get('html_requests') else {})
        request_headers.update(self.watch.get('headers', {}))
        request_headers.update(self.datastore.get_all_base_headers())
        request_headers.update(self.datastore.get_all_headers_in_textfile_for_watch(uuid=self.watch.get('uuid')))
        for header_name in request_headers:
            request_headers[header_name] = jinja_render(template_str=request_headers[header_name])

        proxy_url = getattr(self.fetcher, 'proxy_override', None)
        proxies = {'http': proxy_url, 'https': proxy_url} if proxy_url else {
            scheme: value
            for scheme, value in (
                ('http', getattr(self.fetcher, 'system_http_proxy', None)),
                ('https', getattr(self.fetcher, 'system_https_proxy', None)),
            )
            if value
        }
        timeout = self.datastore.data['settings']['requests'].get('timeout')
        previous = self.get_extra_watch_config('linked_files.json')
        state = await asyncio.to_thread(
            fingerprint_files,
            urls,
            previous,
            headers=request_headers,
            proxies=proxies,
            timeout=timeout,
        )
        snapshot = stable_snapshot(state)
        encoded_snapshot = json.dumps(snapshot, separators=(',', ':'), sort_keys=True)
        snapshot_checksum = hashlib.sha256(encoded_snapshot.encode('utf-8')).hexdigest()
        self.fetcher.content += f'\n<!-- linked-files-sha256:{snapshot_checksum} -->'
        self.fetcher.supplemental_change_content = render_snapshot(snapshot)
        self.linked_files_state = state

    def run_changedetection(self, watch, force_reprocess=False):
        if hasattr(self, 'linked_files_state'):
            self.update_extra_watch_config('linked_files.json', self.linked_files_state, merge=False)
        return super().run_changedetection(watch, force_reprocess=force_reprocess)
