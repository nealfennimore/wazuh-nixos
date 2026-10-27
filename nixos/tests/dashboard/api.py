"""Minimal TLS API fixture; full manager integration lives in checks.stack."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import base64
import json
import ssl
import sys
from urllib.parse import urlsplit

class API(BaseHTTPRequestHandler):
    def reply(self, data):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"data": data, "error": 0}).encode())

    def do_POST(self):
        expected = "Basic " + base64.b64encode(b"wazuh-wui:Test-password-42!").decode()
        if self.path != "/security/user/authenticate" or self.headers.get("Authorization") != expected:
            self.send_error(401)
            return
        self.reply({"token": "test-token"})

    def do_GET(self):
        if self.headers.get("Authorization") != "Bearer test-token":
            self.send_error(401)
            return
        responses = {
            "/manager/info": {"affected_items": [{"name": "server", "version": "v4.14.8"}]},
            "/agents": {"affected_items": [{"id": "000", "manager": "server"}]},
            "/security/users/me": {"affected_items": [{"username": "wazuh-wui", "allow_run_as": False}]},
            "/cluster/status": {"enabled": "no", "running": "no"},
        }
        data = responses.get(urlsplit(self.path).path)
        if data is None:
            self.send_error(404)
            return
        self.reply(data)

server = HTTPServer(("0.0.0.0", 55000), API)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[1], sys.argv[2])
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
