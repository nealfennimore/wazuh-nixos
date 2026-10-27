"""Minimal TLS API fixture; full manager integration lives in checks.stack."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import base64
import ssl
import sys

class API(BaseHTTPRequestHandler):
    def do_POST(self):
        expected = "Basic " + base64.b64encode(b"wazuh-wui:Test-password-42!").decode()
        if self.path != "/security/user/authenticate" or self.headers.get("Authorization") != expected:
            self.send_error(401)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"data":{"token":"test-token"},"error":0}')

server = HTTPServer(("0.0.0.0", 55000), API)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[1], sys.argv[2])
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
