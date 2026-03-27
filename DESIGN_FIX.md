# HTTP/2 CONNECT Challenge - 설계 개선안

## 현재 문제점

### 치명적 설계 결함
```bash
# 현재: HTTP/1.1 Host 헤더 조작만으로 즉시 풀림
curl -H "Host: internal.acme.corp" http://localhost:10000/admin
# → FLAG 획득 (너무 쉬움)
```

**문제**:
1. Backend가 Envoy와 같은 포트(10000)에 노출됨
2. HTTP/2 CONNECT를 사용할 이유가 없음
3. 내부 네트워크 격리가 의미 없음
4. 난이도: Easy (의도: Hard)

---

## 개선안 1: 네트워크 격리 강화

### 변경 사항

#### 1. Backend를 내부 네트워크에만 격리

**docker-compose.yml 수정**:
```yaml
services:
  proxy:
    image: envoyproxy/envoy:v1.28-latest
    ports:
      - "10000:10000"  # 외부 노출
    networks:
      external_network:
        ipv4_address: 10.0.1.10
      internal_network:  # 양쪽 네트워크 모두 연결
        ipv4_address: 172.20.0.5

  backend:
    build: ./backend
    # ports 제거! 외부 노출 안 함
    networks:
      internal_network:  # 내부 네트워크만 연결
        ipv4_address: 172.20.0.10
    # ✅ 이제 proxy를 통해서만 접근 가능
```

**결과**:
- ✅ 외부에서 backend 직접 접근 불가
- ✅ Envoy를 통해서만 접근 가능
- ✅ CONNECT 터널이 필수가 됨

#### 2. Envoy에서 일반 HTTP 요청 차단

**envoy.yaml 수정**:
```yaml
route_config:
  virtual_hosts:
  - name: backend
    domains: ["*"]
    routes:
    # CONNECT만 허용
    - match:
        connect_matcher: {}
      route:
        cluster: dynamic_forward_proxy_cluster

    # 일반 HTTP 요청은 거부
    - match:
        prefix: "/"
      direct_response:
        status: 403
        body:
          inline_string: "Direct access forbidden. Use CONNECT method."
```

**결과**:
- ❌ `curl http://localhost:10000/` → 403 Forbidden
- ✅ CONNECT 터널이 필수가 됨

#### 3. HTTP/2 강제

**envoy.yaml 수정**:
```yaml
http_connection_manager:
  codec_type: HTTP2  # HTTP/2만 허용
  http2_protocol_options:
    allow_connect: true
  http_protocol_options: {}  # HTTP/1.1 비활성화
```

**결과**:
- ❌ HTTP/1.1 요청 거부
- ✅ HTTP/2 필수

---

## 개선안 2: Backend 검증 강화

### 현재 취약점
```python
# backend/app.py (현재)
host = request.headers.get('Host', '')
if 'internal.acme.corp' in host.lower():
    return FLAG
# 문제: Host 헤더만 체크
```

### 개선 1: IP 검증 추가

```python
@app.route('/admin')
def admin():
    # 실제 연결 IP 확인
    real_ip = request.remote_addr

    # Envoy의 내부 IP만 허용
    ALLOWED_PROXY_IPS = ['172.20.0.5']  # Envoy의 내부 IP

    if real_ip not in ALLOWED_PROXY_IPS:
        abort(403, "Direct access forbidden")

    # Host 헤더 검증
    host = request.headers.get('Host', '')
    if 'internal.acme.corp' in host.lower():
        return FLAG
    else:
        abort(403, "Access from internal.acme.corp only")
```

**하지만**: 이것도 여전히 Envoy를 통하면 우회 가능!

### 개선 2: X-Forwarded-For 검증 (더 현실적)

```python
@app.route('/admin')
def admin():
    # Envoy가 설정한 원본 IP 확인
    forwarded_for = request.headers.get('X-Forwarded-For', '')

    # 내부 네트워크에서만 허용
    if not forwarded_for.startswith('172.20.0.'):
        abort(403, "Internal network only")

    # Host 헤더 검증
    host = request.headers.get('Host', '')
    if 'internal.acme.corp' in host.lower():
        return FLAG
    else:
        abort(403, "Access from internal.acme.corp only")
```

**문제점**: X-Forwarded-For도 조작 가능!

### 개선 3: 다단계 검증 (권장)

```python
@app.route('/admin')
def admin():
    # 1단계: 실제 연결 IP (Envoy여야 함)
    real_ip = request.remote_addr
    if real_ip != '172.20.0.5':  # Envoy IP
        abort(403, "Must access through proxy")

    # 2단계: Envoy가 추가한 커스텀 헤더 검증
    internal_token = request.headers.get('X-Internal-Token', '')
    if internal_token != os.environ.get('INTERNAL_TOKEN'):
        abort(403, "Missing internal token")

    # 3단계: Host 헤더 검증
    host = request.headers.get('Host', '')
    if 'internal.acme.corp' in host.lower():
        return FLAG
    else:
        abort(403, "Access from internal.acme.corp only")
```

**Envoy 설정 추가**:
```yaml
# envoy.yaml
routes:
- match:
    connect_matcher: {}
  route:
    cluster: dynamic_forward_proxy_cluster
  request_headers_to_add:
  - header:
      key: X-Internal-Token
      value: "secret-token-12345"  # 환경 변수로 관리
```

**결과**: 이제 CONNECT + 내부 토큰 + :authority 조작이 모두 필요!

---

## 개선안 3: 더 복잡한 시나리오 (Hard)

### 시나리오: 2단계 인증

1. **1단계**: CONNECT로 내부 네트워크 접근
   - 172.20.0.15 (decoy1)에서 임시 토큰 획득

2. **2단계**: 토큰을 사용하여 backend 접근
   - :authority를 internal.acme.corp로 설정
   - X-Auth-Token 헤더에 토큰 포함

3. **3단계**: Admin 패널에서 FLAG 획득

**구현**:

```python
# decoy1/server.py (토큰 발급 서버)
@app.route('/token')
def get_token():
    # 임시 토큰 발급 (1분 유효)
    token = generate_token(expires_in=60)
    return {"token": token}

# backend/app.py
@app.route('/admin')
def admin():
    # 토큰 검증
    token = request.headers.get('X-Auth-Token', '')
    if not verify_token(token):
        abort(403, "Invalid or expired token")

    # Host 검증
    host = request.headers.get('Host', '')
    if 'internal.acme.corp' in host.lower():
        return FLAG
    else:
        abort(403, "Access from internal.acme.corp only")
```

**풀이 과정**:
```python
# Step 1: Get token
connect_to('172.20.0.15:3000')
token = get('/token')

# Step 2: Use token to access admin
connect_to('172.20.0.10:8080')
headers = {
    ':authority': 'internal.acme.corp',
    'X-Auth-Token': token
}
flag = get('/admin', headers=headers)
```

---

## 최종 권장 설계

### 변경 사항 요약

| 항목 | 현재 | 개선 후 |
|------|------|---------|
| Backend 노출 | ✅ 포트 10000 | ❌ 내부만 |
| HTTP/1.1 허용 | ✅ | ❌ |
| 일반 HTTP 허용 | ✅ | ❌ |
| CONNECT 필수 | ❌ | ✅ |
| IP 검증 | ❌ | ✅ |
| 난이도 | Easy | Hard |

### 구현 우선순위

1. **필수** (난이도 Medium):
   - Backend를 내부 네트워크에만 격리
   - Envoy에서 CONNECT만 허용
   - HTTP/2 강제

2. **권장** (난이도 Hard):
   - Backend에서 IP 검증 추가
   - 커스텀 헤더 검증

3. **고급** (난이도 Very Hard):
   - 2단계 인증 (토큰 시스템)
   - 시간 기반 제약

---

## 빠른 수정 (Minimal Fix)

**docker-compose.yml**:
```yaml
backend:
  # ports 제거 (이것만 해도 큰 차이!)
```

**envoy.yaml**:
```yaml
routes:
# 일반 HTTP 차단
- match:
    prefix: "/"
  direct_response:
    status: 403
    body:
      inline_string: "Use CONNECT method"

# CONNECT만 허용
- match:
    connect_matcher: {}
  route:
    cluster: dynamic_forward_proxy_cluster
```

**테스트**:
```bash
# 실패해야 함
curl -H "Host: internal.acme.corp" http://localhost:10000/admin
# → 403 Forbidden

# CONNECT로만 가능
python3 exploit.py  # HTTP/2 CONNECT 사용
# → FLAG 획득
```

---

**결론**: 현재 설계는 "HTTP/2 CONNECT" 문제가 아니라 "Host 헤더 조작" 문제입니다. 위 개선안을 적용하면 진짜 Hard 난이도가 됩니다.
