#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import subprocess


class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if (q.get("code") is None) or (q.get("state") is None):
            self.send_response(404)
            self.end_headers()
            return
        subprocess.run(["plumb", "-s", "httpd", "-d", "oauth", "-t", "text", "-a", f'code={q["code"][0]}', "-a", f'state={q["state"][0]}', ""])
        self.send_response(200)
        self.end_headers()

def run(server_class=HTTPServer, handler_class=BaseHTTPRequestHandler):
    server_address = ('', 4812)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()


run(HTTPServer, MyHandler)





