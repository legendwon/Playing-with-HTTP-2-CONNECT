#!/usr/bin/env python3
"""
Decoy Service 3 - Monitoring Service
Has /admin endpoint but always returns 403 (no Host header check)
Makes participants think they need different bypass technique
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from datetime import datetime


class Decoy3Handler(BaseHTTPRequestHandler):
    """Monitoring service decoy handler"""

    def do_GET(self):
        """Handle GET requests"""
        print(f"[{datetime.now().isoformat()}] GET {self.path} from {self.client_address[0]}")

        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            html = """
            <html>
                <head><title>Monitoring Service</title></head>
                <body>
                    <h1>System Monitoring Dashboard</h1>
                    <p>Infrastructure monitoring and alerting</p>
                    <p>Status: All systems operational</p>
                </body>
            </html>
            """
            self.wfile.write(html.encode('utf-8'))

        elif self.path == '/admin':
            # Always 403 - red herring!
            # Makes participants think Host header won't work here
            self.send_response(403)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            html = """
            <html>
                <head><title>Access Denied</title></head>
                <body>
                    <h1>403 Forbidden</h1>
                    <p>Admin panel requires authentication token.</p>
                    <p>This endpoint is protected by IP whitelist.</p>
                </body>
            </html>
            """
            self.wfile.write(html.encode('utf-8'))

        elif self.path == '/metrics':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {
                "cpu_usage": 23.5,
                "memory_usage": 67.2,
                "disk_usage": 45.8,
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


def run_server(port=8888):
    """Start the HTTP server"""
    server_address = ('0.0.0.0', port)
    httpd = HTTPServer(server_address, Decoy3Handler)
    print(f"Decoy 3 (Monitoring Service) started on port {port}")
    httpd.serve_forever()


if __name__ == '__main__':
    run_server(port=8888)
