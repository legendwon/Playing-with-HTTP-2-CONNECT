#!/usr/bin/env python3
"""
Decoy Service 1 - Database API
Makes participants think this is a database service
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from datetime import datetime


class Decoy1Handler(BaseHTTPRequestHandler):
    """Database API decoy handler"""

    def do_GET(self):
        """Handle GET requests"""
        print(f"[{datetime.now().isoformat()}] GET {self.path} from {self.client_address[0]}")

        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {
                "service": "Database API",
                "version": "2.1.4",
                "status": "healthy",
                "endpoints": ["/query", "/stats", "/health"],
                "timestamp": datetime.now().isoformat()
            }
            self.wfile.write(json.dumps(response, indent=2).encode('utf-8'))

        elif self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {
                "status": "healthy",
                "uptime": "72h",
                "connections": 42
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


def run_server(port=3000):
    """Start the HTTP server"""
    server_address = ('0.0.0.0', port)
    httpd = HTTPServer(server_address, Decoy1Handler)
    print(f"Decoy 1 (Database API) started on port {port}")
    httpd.serve_forever()


if __name__ == '__main__':
    run_server(port=3000)
