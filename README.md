# Playing with HTTP/2 CONNECT

![Difficulty](https://img.shields.io/badge/Difficulty-Hard-red)
![Protocol](https://img.shields.io/badge/Protocol-HTTP%2F2-blue)
![Category](https://img.shields.io/badge/Category-Web%20Security-green)

A CTF/Wargame challenge demonstrating SSRF vulnerabilities through misconfigured HTTP/2 CONNECT proxy settings.

## Overview

**Playing with HTTP/2 CONNECT**는 HTTP/2 CONNECT 메서드의 취약한 설정을 악용한 SSRF 공격 실습 환경입니다.

Direct HTTP 접근은 차단되며, 참가자는 **반드시 HTTP/2 CONNECT tunnel을 통해** 내부 서비스에 접근해야 합니다.

### What You'll Learn

- HTTP/2 CONNECT 메서드를 이용한 TCP 터널링
- **HTTP/2 멀티플렉싱을 활용한 고속 네트워크 스캐닝**
- CONNECT tunnel을 통한 raw HTTP/1.1 요청 전송
- Envoy 프록시 보안 설정 및 취약점
- SSRF 공격 벡터 및 방어 기법
- Host 헤더 조작을 통한 접근 제어 우회

### Challenge Info

- **Difficulty**: Hard
- **Category**: Web Security, Network Exploitation
- **Skills**: HTTP/2, Python, Network Scanning
- **Flag Format**: `WSL{...}`

---

## Quick Start

### 1. Setup Environment

```bash
# Clone repository
git clone <repository-url>
cd Playing-with-HTTP-2-CONNECT

# Start services
docker-compose up -d --build

# Verify services
docker-compose ps
```

### 2. Access Challenge

```bash
# Try direct HTTP access (will be blocked)
curl http://localhost:10000/

# Read challenge description
cat README.txt
```

### 3. Run Exploit (Solution)

```bash
# Install dependencies
pip install h2

# Run exploit chain
cd tools/exploits
python3 scan_network.py      # Step 1: Scan internal network (HTTP/2 multiplexing!)
python3 enumerate_services.py # Step 2: Enumerate services
python3 exploit.py            # Step 3: Get flag
```

### 4. Cleanup

```bash
docker-compose down -v
```

---

## Project Structure

```
Playing-with-HTTP-2-CONNECT/
├── README.md                 # This file
├── README.txt                # Challenge description (black-box)
├── docker-compose.yml        # Infrastructure definition
│
├── docs/                     # Documentation
│   ├── setup/                # Setup guides
│   │   ├── SETUP.md          # English
│   │   └── SETUP.ko.md       # Korean
│   ├── writeup/              # Solutions
│   │   ├── WRITEUP.md        # English (2500+ lines)
│   │   └── WRITEUP.ko.md     # Korean
│   └── archive/              # Archive
│       └── ...
│
├── tools/                    # Tools & Exploits
│   ├── verify_setup.py       # Environment verification
│   └── exploits/             # POC scripts
│       ├── scan_network.py
│       ├── enumerate_services.py
│       └── exploit.py
│
├── envoy/                    # Envoy proxy config (vulnerable)
├── backend/                  # Backend service (flag here!)
└── decoy[1-3]/              # Decoy services
```

---

## Network Architecture

```
External Network (10.0.1.0/24)
┌─────────────────────────────┐
│  Envoy Proxy                │
│  Port: 10000 (exposed)      │
│  HTTP/2 CONNECT enabled     │
└──────────┬──────────────────┘
           │
           │ CONNECT Tunnel (SSRF!)
           ▼
Internal Network (172.20.0.0/24)
┌─────────────────────────────┐
│  Backend (172.20.0.10:8080) │ ← FLAG HERE!
│  Decoy1  (172.20.0.15:3000) │
│  Decoy2  (172.20.0.20:8000) │
│  Decoy3  (172.20.0.25:8888) │
└─────────────────────────────┘
```

---

## Vulnerability Summary

### 1. HTTP/2 CONNECT Tunnel SSRF
- Direct HTTP 접근은 차단됨 (403 Forbidden)
- **HTTP/2 CONNECT 메서드만 허용** → 참가자는 반드시 HTTP/2를 사용해야 함
- Envoy가 CONNECT 터널을 무제한 허용
- 내부 네트워크(172.20.0.0/24)로 TCP 터널링 가능
- **HTTP/2 멀티플렉싱**: 1개 TCP 연결로 수백 개 CONNECT 터널 동시 생성
  - 네트워크 스캔 속도 극적 향상 (1785개 연결 → 18개 연결)
  - HTTP/1.1 대비 실용성 100배 이상

### 2. Host Header Spoofing via CONNECT Tunnel
- Backend가 HTTP/1.1 `Host` 헤더만으로 접근 제어
- CONNECT tunnel 생성 → tunnel 내에서 raw HTTP/1.1 요청 전송
- Host 헤더를 `internal.acme.corp`로 조작하여 `/admin` 접근

### 3. Network Isolation Bypass
- 네트워크 레벨 격리만으로는 불충분
- 프록시를 통한 SSRF로 격리 우회

---

## Documentation

### For Participants
- **[README.txt](README.txt)** - Challenge description (black-box, minimal hints)

### For Organizers
- **[Setup Guide (English)](docs/setup/SETUP.md)** - Detailed setup instructions
- **[Setup Guide (Korean)](docs/setup/SETUP.ko.md)** - 한국어 설정 가이드

### Solutions
- **[Writeup (English)](docs/writeup/WRITEUP.md)** - Complete solution (2500+ lines)
- **[Writeup (Korean)](docs/writeup/WRITEUP.ko.md)** - 완전한 솔루션 가이드

### Tools
- **[Exploit Scripts](tools/exploits/)** - POC scripts for automated exploitation
- **[Verification Script](tools/verify_setup.py)** - Environment validation

---

## Requirements

- **Docker**: 20.10+
- **Docker Compose**: 1.29+
- **Python**: 3.8+ (for exploits)
- **Port**: 10000 (must be available)
- **Memory**: 512MB+ free RAM

---

## Exploitation Flow

```
1. Discover HTTP/2 Requirement
   └─> curl http://localhost:10000/ → 403 Forbidden (Direct HTTP blocked)
   └─> Must use HTTP/2 CONNECT method

2. Network Scanning (HTTP/2 Multiplexing!)
   └─> Establish HTTP/2 connection with h2 library
   └─> Use multiplexing to scan 1785 targets with ~18 TCP connections
   └─> Create multiple CONNECT tunnels simultaneously to 172.20.0.0/24
       └─> Discover active services (172.20.0.10:8080, etc.)
       └─> HTTP/1.1 would require 1785 connections (impractical!)

3. Service Enumeration
   └─> Probe discovered services through CONNECT tunnels
       └─> Find /admin endpoint (403 Forbidden)

4. Access Control Bypass
   └─> Create CONNECT tunnel to 172.20.0.10:8080
   └─> Send raw HTTP/1.1 request through tunnel:
       GET /admin HTTP/1.1
       Host: internal.acme.corp  ← Spoofed!
   └─> Backend validates Host header → Access granted (200 OK)

5. Flag Capture
   └─> Extract flag: WSL{http2_authority_header_confusion}
```

---

## Defense Recommendations

### 1. Restrict CONNECT Destinations
```yaml
# envoy.yaml - Whitelist allowed CONNECT targets
routes:
  - match:
      connect_matcher: {}
      headers:
      - name: ":authority"
        string_match:
          exact: "allowed-backend.com:443"
```

### 2. Validate Connection Context, Not Just Headers
```python
# Backend should verify actual network path
# Use X-Forwarded-For with trusted proxy validation
# Or use mutual TLS for service authentication
if not verify_client_certificate(request):
    abort(403)
```

### 3. Disable CONNECT for Public Proxies
```yaml
# For public-facing proxies, disable CONNECT entirely
upgrade_configs:
  - upgrade_type: CONNECT
    enabled: false
```

### 4. Network Segmentation
- Use firewall rules to restrict proxy → backend paths
- Implement Zero Trust architecture with service mesh
- Use mutual TLS for all service-to-service communication

---

## References

- **HTTP/2 Specification**: [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113.html)
- **CONNECT Method**: [RFC 9110 Section 9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6)
- **Envoy Documentation**: [envoyproxy.io](https://www.envoyproxy.io/)
- **SSRF Prevention**: [OWASP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

---

## License & Disclaimer

### Permitted Use
- ✅ CTF/Wargame competitions
- ✅ Security education & training
- ✅ Authorized penetration testing practice
- ✅ Academic research

### Prohibited Use
- ❌ Unauthorized system attacks
- ❌ Production infrastructure exploitation
- ❌ Illegal hacking activities
- ❌ Privacy violations

**Disclaimer**: The author is not responsible for any illegal use of this project. Users are solely responsible for compliance with applicable laws.

---

**Author**: Claude Code
**Version**: 1.0
**Expected Solve Time**: 2-4 hours (black-box)
**Last Updated**: 2026-03-27
