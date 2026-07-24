#!/usr/bin/env python3

import hashlib
import json
import os
from unittest.mock import patch

from flask import url_for

from changedetectionio.processors.page_and_files.linked_files import discover_file_urls

from .util import wait_for_all_checks


def write_manifest(datastore_path, links, text='Ratings page'):
    path = os.path.join(datastore_path, 'endpoint-test-page-and-files.json')
    with open(path, 'w', encoding='utf-8') as manifest_file:
        json.dump({'links': links, 'text': text}, manifest_file)


def test_page_and_files_discovers_downloads_without_head_checking_navigation():
    html = '''
        <a href="/about">About</a>
        <a href="/files/report.PDF?version=2">Report</a>
        <a href="archive.zip">Archive</a>
        <a href="/download?id=42" download>Download</a>
        <a href="/images/logo.png">Logo</a>
    '''
    assert discover_file_urls(html, 'https://example.com/path/page') == [
        'https://example.com/download?id=42',
        'https://example.com/files/report.PDF?version=2',
        'https://example.com/path/archive.zip',
    ]


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
    uuid, _ = create_watch(client, live_server, datastore_path)
    write_manifest(datastore_path, [])
    client.get(url_for('ui.form_watch_checknow'), follow_redirects=True)
    wait_for_all_checks(client)

    watch = live_server.app.config['DATASTORE'].data['watching'][uuid]
    assert len(watch.history) == 2
    latest = watch.get_history_snapshot(timestamp=list(watch.history.keys())[-1])
    assert 'LINKED FILES\n(none discovered)' in latest
