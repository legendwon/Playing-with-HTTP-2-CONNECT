#!/usr/bin/env python3
"""
Decoy Service 2 - Analytics Service
Has /admin endpoint but provides FAKE flag to mislead participants
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from datetime import datetime


class Decoy2Handler(BaseHTTPRequestHandler):
    """Analytics service decoy handler"""

    def do_GET(self):
        """Handle GET requests"""
        print(f"[{datetime.now().isoformat()}] GET {self.path} from {self.client_address[0]}")

        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            html = """
            <html>
                <head><title>Analytics Service</title></head>
                <body>
                    <h1>Analytics Platform</h1>
                    <p>Real-time data analytics and reporting</p>
                    <p>Version: 3.2.1</p>
                </body>
            </html>
            """
            self.wfile.write(html.encode('utf-8'))

        elif self.path == '/admin':
            # FAKE FLAG - mislead participants!
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            html = """
            <html>
                <head><title>Analytics Admin</title></head>
                <body>
                    <h1>Admin Panel</h1>
                    <p>FLAG: WSL{wrong_service_try_harder}</p>
                    <p>Note: This is a decoy. Keep searching!</p>
                </body>
            </html>
            """
            self.wfile.write(html.encode('utf-8'))

        elif self.path == '/api/stats':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {
                "total_events": 12847,
                "active_users": 234,
                "timestamp": datetime.now().isoformat()
            }
            self.wfile.write(json.dumps(response, indent=2).encode('utf-8'))

        else:
            self.send_response(404)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {"error": "Not found"}
            self.wfile.write(json.dumps(response).encode('utf-8'))

    def log_message(self, format, *args):
        """Suppress default logging"""
        return


def run_server(port=8000):
    """Start the HTTP server"""
    server_address = ('0.0.0.0', port)
    httpd = HTTPServer(server_address, Decoy2Handler)
    print(f"Decoy 2 (Analytics Service) started on port {port}")
    httpd.serve_forever()


if __name__ == '__main__':
    run_server(port=8000)
