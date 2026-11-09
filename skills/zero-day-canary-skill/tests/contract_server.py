"""LOCAL TEST FIXTURE ONLY. Not a production API or hosted monitoring service."""
import argparse
import hashlib
import http.server
import json
from pathlib import Path
import re
import socket
import sys
import threading

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from canary import canonical, parse_json, validate_bundle, MAX_BYTES

class FixtureServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, address):
        super().__init__(address, Handler)
        self.rows = {}
        self.lock = threading.Lock()
        self.failures = []
        self.calls = 0
        self.commits = 0
        self.drop_after_commit = False
        self.receipt_override = None

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # Never log credentials, source bodies or request identifiers.

    def reply(self, code, value):
        data = canonical(value)
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def authorize(self):
        match = re.fullmatch(r'/api/v1/developer/projects/([A-Za-z0-9_-]+)/evidence(?:/([a-f0-9]{64}))?', self.path)
        if not match:
            self.reply(404, {'error': {'code': 'not_found'}})
            return None
        tenant = {'Bearer fixture-token-a': 'project-a', 'Bearer fixture-token-b': 'project-b'}.get(self.headers.get('Authorization'))
        if tenant is None:
            self.reply(401, {'error': {'code': 'unauthorized'}})
            return None
        if tenant != match[1]:
            self.reply(404, {'error': {'code': 'not_found'}})
            return None
        return tenant, match[2]

    def do_POST(self):
        auth = self.authorize()
        if auth is None:
            return
        tenant, item = auth
        if item is not None:
            return self.reply(405, {'error': {'code': 'method_not_allowed'}})
        self.server.calls += 1
        if self.server.failures:
            code = self.server.failures.pop(0)
            if code == 302:
                self.send_response(302)
                self.send_header('Location', '/do-not-follow')
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
            return self.reply(code, {'error': {'code': 'fixture_failure'}})
        try:
            size = int(self.headers.get('Content-Length', '-1'))
        except ValueError:
            size = -1
        if size < 0 or size > MAX_BYTES:
            return self.reply(413, {'error': {'code': 'payload_too_large'}})
        if self.headers.get('Content-Type') != 'application/json':
            return self.reply(415, {'error': {'code': 'unsupported_media_type'}})
        data = self.rfile.read(size)
        key = self.headers.get('Idempotency-Key', '')
        if re.fullmatch('[a-f0-9]{64}', key) is None:
            return self.reply(400, {'error': {'code': 'invalid_idempotency_key'}})
        body_hash = hashlib.sha256(data).hexdigest()
        with self.server.lock:
            previous = self.server.rows.get((tenant, key))
            if previous:
                if previous['body_hash'] != body_hash:
                    return self.reply(409, {'error': {'code': 'idempotency_conflict'}})
                return self.reply(200, previous['receipt'])
            if key != body_hash:
                return self.reply(422, {'error': {'code': 'hash_mismatch'}})
            try:
                bundle = validate_bundle(parse_json(data))
                if canonical(bundle) != data:
                    raise ValueError()
            except Exception:
                return self.reply(422, {'error': {'code': 'invalid_bundle'}})
            receipt = {'schema_version': 'canary-receipt/1', 'project_id': tenant, 'bundle_sha256': key, 'evidence_id': key, 'monitoring_state': 'integration_fixture_only', 'billing_mode': 'developer_inventory_free'}
            self.server.rows[(tenant, key)] = {'body_hash': body_hash, 'bundle': bundle, 'receipt': receipt}
            self.server.commits += 1
            if self.server.drop_after_commit:
                self.server.drop_after_commit = False
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            return self.reply(201, self.server.receipt_override or receipt)

    def do_GET(self):
        auth = self.authorize()
        if auth is None:
            return
        tenant, key = auth
        row = self.server.rows.get((tenant, key))
        if row is None:
            return self.reply(404, {'error': {'code': 'not_found'}})
        return self.reply(200, {'receipt': row['receipt'], 'bundle': row['bundle']})

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8765)
    args = parser.parse_args()
    server = FixtureServer(('127.0.0.1', args.port))
    print('LOCAL FIXTURE ONLY: http://127.0.0.1:' + str(server.server_port), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
