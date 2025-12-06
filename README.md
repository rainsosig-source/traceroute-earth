# TCP/UDP Traceroute 🌐

TCP/UDP 기반 네트워크 경로 추적 도구입니다. 기존 ICMP 기반 traceroute와 달리 TCP SYN 또는 UDP 패킷을 사용하여 방화벽을 우회할 수 있습니다.

## ✨ 특징

- **TCP/UDP 기반 추적**: ICMP가 차단된 네트워크에서도 동작
- **다중 프로토콜 지원**: TCP, UDP, 또는 둘 다 사용 가능
- **폴백 포트**: TCP 실패 시 다른 포트로 자동 재시도
- **다중 프로브**: 각 홉에 대해 여러 번 프로빙하여 정확도 향상
- **지리적 위치 정보**: 각 홉의 위도/경도 표시
- **JSON 출력**: 프로그래밍 방식으로 결과 처리 가능
- **크로스 플랫폼**: Windows 및 Linux 지원
- **캐싱**: DNS 역조회 및 위치 정보 캐싱으로 성능 최적화

## 📋 요구사항

- Python 3.7 이상
- **관리자(Administrator) 권한** - Raw 소켓 사용에 필요

## 🚀 사용법

### 기본 사용

```bash
# 기본 (TCP, 포트 80)
python tcp_traceroute.py google.com

# 특정 포트 지정
python tcp_traceroute.py google.com 443
```

### 옵션

| 옵션 | 설명 | 기본값 |
|------|------|--------|
| `-m, --max-hops` | 최대 홉 수 | 30 |
| `-t, --timeout` | 각 홉 타임아웃 (초) | 2.0 |
| `-q, --probes` | 각 홉당 프로브 횟수 | 3 |
| `-P, --protocol` | 프로토콜 모드 (tcp, udp, both) | tcp |
| `-F, --fallback-ports` | TCP 실패 시 시도할 폴백 포트 | - |
| `-v, --verbose` | 상세 디버그 정보 출력 | - |
| `--json` | JSON 형식으로 출력 | - |
| `--no-location` | 위치 정보 비활성화 | - |

### 예시

```bash
# 최대 20홉, 타임아웃 3초
python tcp_traceroute.py google.com -m 20 -t 3.0

# TCP+UDP 모드 (TCP 실패 시 UDP 폴백)
python tcp_traceroute.py naver.com -P both -q 3

# 폴백 포트 사용 (80 실패 시 443, 8080 시도)
python tcp_traceroute.py naver.com -F 443,8080

# UDP만 사용
python tcp_traceroute.py naver.com -P udp

# JSON 출력
python tcp_traceroute.py google.com --json

# 빠른 추적 (위치 정보 없이)
python tcp_traceroute.py google.com --no-location
```

## 📤 출력 예시

### 기본 출력

```
Traceroute to naver.com (223.130.200.236)
Protocol: TCP, Port: 80, Max hops: 30, Probes: 3

1       0.5ms  1.0ms  0.5ms   192.168.1.1
2       3.5ms  3.6ms  4.2ms   218.155.182.1
3       2.0ms  2.5ms  2.9ms   125.141.249.35
4       3.1ms  3.1ms  3.6ms   112.189.72.101
5       *  *  *       Request timed out.
6       6.1ms  *  *   112.174.75.130
7       5.2ms  5.2ms  4.3ms   128.134.40.174
...
11      5.9ms  4.8ms  5.1ms   223.130.200.236 [Open]
```

### JSON 출력

```json
{
  "target_host": "google.com",
  "target_ip": "142.250.207.14",
  "port": 80,
  "max_hops": 30,
  "hops": [
    {
      "ttl": 1,
      "ip_address": "192.168.1.1",
      "hostname": "router.local",
      "rtt_ms": 1.23,
      "probes": [
        {"rtt_ms": 0.5, "success": true, "protocol": "tcp"},
        {"rtt_ms": 1.0, "success": true, "protocol": "tcp"},
        {"rtt_ms": 0.5, "success": true, "protocol": "tcp"}
      ],
      "latitude": null,
      "longitude": null,
      "status": "intermediate"
    }
  ]
}
```

## 🔧 작동 원리

### TCP 모드
1. **TTL 설정**: Time-To-Live 값을 1부터 증가시키며 TCP SYN 패킷 전송
2. **ICMP 수신**: 중간 라우터가 TTL 만료 시 ICMP Time Exceeded 메시지 반환
3. **목적지 도달**: 최종 목적지에서 TCP SYN-ACK(Open) 또는 RST(Closed) 응답

### UDP 모드
1. **TTL 설정**: Time-To-Live 값을 1부터 증가시키며 UDP 패킷 전송 (포트 33434+)
2. **ICMP 수신**: 중간 라우터가 TTL 만료 시 ICMP Time Exceeded 메시지 반환
3. **목적지 도달**: 최종 목적지에서 ICMP Port Unreachable 메시지 반환

### Both 모드
TCP 프로빙 실패 시 자동으로 UDP 프로빙 시도

```
┌──────────┐    TTL=1    ┌──────────┐    ICMP      ┌──────────┐
│   PC     │ ──────────> │ Router 1 │ ──────────>  │   PC     │
└──────────┘             └──────────┘  Time Exceed └──────────┘

┌──────────┐    TTL=2    ┌──────────┐    TTL=1     ┌──────────┐
│   PC     │ ──────────> │ Router 1 │ ──────────>  │ Router 2 │
└──────────┘             └──────────┘              └──────────┘
                                                        │
                         ┌──────────┐    ICMP           │
                         │   PC     │ <─────────────────┘
                         └──────────┘  Time Exceeded
```

## ⚠️ 주의사항

1. **관리자 권한 필요**
   - Windows: PowerShell을 관리자 권한으로 실행
   - Linux: `sudo` 사용

2. **Request timed out 발생 시**
   - 일부 라우터는 ICMP 응답을 의도적으로 차단합니다
   - `-P both` 옵션으로 UDP 폴백을 시도해 볼 수 있습니다
   - `-F 443,8080` 옵션으로 다른 포트를 시도해 볼 수 있습니다
   - 이것은 보안 정책으로 인한 정상적인 현상일 수 있습니다

3. **API 제한**
   - 위치 정보 API(ip-api.com)는 분당 45회 제한이 있습니다
   - 캐싱을 통해 중복 조회를 방지합니다

## 📁 프로젝트 구조

```
트레이스라우터/
├── tcp_traceroute.py       # CLI 도구 (메인 스크립트)
├── test_traceroute.py      # 유닛 테스트 (32개)
├── README.md               # 이 문서
├── LICENSE                 # MIT 라이선스
├── .gitignore              # Git 무시 파일
├── requirements.txt        # 의존성
└── web/                    # 웹 인터페이스 (Flask)
    ├── __init__.py
    ├── route_blueprint.py  # Flask Blueprint
    ├── INTEGRATION.md      # sosig.shop 통합 가이드
    └── templates/
        └── route.html      # 웹 UI (다크 테마)
```

## 🌐 웹 인터페이스

Flask 웹 애플리케이션에 통합할 수 있는 Route Tracer 웹 인터페이스가 포함되어 있습니다.

### 통합 방법

```python
# app.py에 추가
from web.route_blueprint import route_bp
app.register_blueprint(route_bp)
```

자세한 내용은 `web/INTEGRATION.md`를 참고하세요.

## 🧪 테스트

```bash
# 유닛 테스트 실행
python -m pytest test_traceroute.py -v

# 또는
python test_traceroute.py
```

## 📜 라이선스

MIT License

## 🤝 기여

이슈 및 풀 리퀘스트 환영합니다!
