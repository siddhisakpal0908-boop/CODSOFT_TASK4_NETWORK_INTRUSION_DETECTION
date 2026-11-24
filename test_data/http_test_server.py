
from http.server import BaseHTTPRequestHandler, HTTPServer

class TestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        print("HTTP request received:", self.path)

        if self.path == "/admin":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Test admin page")

        else:
            self.send_response(404)
            self.end_headers()

server = HTTPServer(("127.0.0.1", 8080), TestHandler)

print("Local HTTP test server running on port 8080")

server.serve_forever()
