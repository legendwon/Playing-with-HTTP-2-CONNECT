#!/usr/bin/env python3
"""
ACME Corp Backend Service - Vulnerable Application
Demonstrates HTTP/2 :authority header confusion vulnerability
"""

import os
from flask import Flask, request, abort

app = Flask(__name__)

# Get flag from environment variable
FLAG = os.environ.get('FLAG', 'WSL{http2_authority_header_confusion}')


@app.route('/')
def index():
    """Public endpoint"""
    return """
    <html>
        <head><title>ACME Corp Backend</title></head>
        <body>
            <h1>ACME Corp Backend Service</h1>
            <p>Backend API is operational.</p>
            <p>Version: 1.0.0</p>
        </body>
    </html>
    """, 200


@app.route('/health')
def health():
    """Health check endpoint"""
    return "OK", 200


@app.route('/admin')
def admin():
    """
    Admin panel endpoint - VULNERABLE

    VULNERABILITY: Trusts Host header (derived from HTTP/2 :authority pseudo-header)
    without validating source IP or implementing proper authentication.

    Accepts any request where Host header contains 'internal.acme.corp' substring.
    An attacker can spoof this via HTTP/2 :authority header through CONNECT tunnel.
    """
    host = request.headers.get('Host', '')

    # VULNERABLE: Substring match, no IP validation, no authentication
    if 'internal.acme.corp' in host.lower():
        return f"""
        <html>
            <head><title>Admin Panel</title></head>
            <body>
                <h1>Admin Panel</h1>
                <p>Welcome to the internal admin panel.</p>
                <p><strong>FLAG:</strong> {FLAG}</p>
            </body>
        </html>
        """, 200
    else:
        # Return 403 for external access attempts
        # HINT: Leak the required hostname for black-box solving
        abort(403, description="Access denied: Admin panel must be accessed from internal.acme.corp domain")


@app.route('/api/status')
def api_status():
    """API status endpoint"""
    return {
        "status": "operational",
        "service": "ACME Corp Backend",
        "version": "1.0.0"
    }, 200


if __name__ == '__main__':
    # Run on all interfaces, port 8080
    app.run(host='0.0.0.0', port=8080, debug=False)
