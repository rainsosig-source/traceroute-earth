# Sosig.shop 통합 가이드

이 문서는 Traceroute 웹 인터페이스를 sosig.shop Flask 앱에 통합하는 방법을 설명합니다.

## 📁 파일 구조

```
web/
├── route_blueprint.py      # Flask Blueprint (백엔드)
├── templates/
│   └── route.html          # HTML 템플릿 (프론트엔드)
└── INTEGRATION.md          # 이 문서
```

## 🚀 통합 방법

### 1단계: 파일 복사

서버에 SSH로 접속 후, 다음 파일들을 복사합니다:

```bash
# 1. Blueprint 파일을 app.py와 같은 디렉토리에 복사
scp web/route_blueprint.py your-server:/path/to/sosig.shop/

# 2. 템플릿 파일을 templates 폴더에 복사
scp web/templates/route.html your-server:/path/to/sosig.shop/templates/
```

또는 SFTP로 직접 업로드합니다.

### 2단계: app.py 수정

`app.py` 파일에 다음 코드를 추가합니다:

```python
# 기존 import 부분에 추가
from route_blueprint import route_bp

# app = Flask(__name__) 이후에 추가
app.register_blueprint(route_bp)
```

### 3단계: 서버 재시작

```bash
# systemd를 사용하는 경우
sudo systemctl restart sosig

# 또는 직접 프로세스 재시작
pkill -f "python.*app.py"
python app.py &
```

## 🔧 추가 설정 (선택)

### traceroute 명령어 설치 (Linux)

```bash
# Ubuntu/Debian
sudo apt-get install traceroute

# CentOS/RHEL
sudo yum install traceroute

# Alpine
apk add traceroute
```

### 권한 설정 (선택적)

traceroute는 일반 사용자도 실행 가능하지만, 일부 시스템에서는 추가 권한이 필요할 수 있습니다:

```bash
# traceroute에 CAP_NET_RAW 권한 부여 (선택적)
sudo setcap cap_net_raw+ep $(which traceroute)
```

## 📱 사용 방법

통합 후 다음 URL로 접속합니다:

```
https://sosig.shop/route
```

### API 엔드포인트

| 메서드 | URL | 설명 |
|--------|-----|------|
| GET | `/route` | 웹 인터페이스 |
| POST | `/route/trace` | JSON API (body: `{target, max_hops}`) |
| GET | `/route/api/<target>` | REST API |

### API 예시

```bash
# POST 요청
curl -X POST https://sosig.shop/route/trace \
  -H "Content-Type: application/json" \
  -d '{"target": "google.com", "max_hops": 20}'

# GET 요청
curl https://sosig.shop/route/api/google.com?max_hops=20
```

## 🔒 보안 고려사항

1. **입력 검증**: 호스트명에 특수문자가 포함되면 거부됩니다
2. **타임아웃**: 최대 2분 후 자동 종료됩니다
3. **최대 홉 제한**: 30홉으로 제한됩니다
4. **Rate Limiting**: 필요시 Flask-Limiter 추가를 권장합니다

### Rate Limiting 추가 (선택)

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["10 per minute"]
)

@route_bp.route('/route/trace', methods=['POST'])
@limiter.limit("5 per minute")
def trace():
    ...
```

## ❓ 문제 해결

### "traceroute 명령어를 찾을 수 없습니다"
```bash
# traceroute 설치
sudo apt-get install traceroute  # Debian/Ubuntu
```

### "Permission denied"
```bash
# 권한 확인
which traceroute
ls -la $(which traceroute)
```

### 템플릿을 찾을 수 없음
Blueprint의 `template_folder` 경로가 올바른지 확인하세요:

```python
# route_blueprint.py에서 경로 수정 (필요시)
route_bp = Blueprint('route', __name__, 
                     template_folder='templates')  # 또는 절대 경로
```

## 🎨 커스터마이징

### 스타일 변경
`route.html`의 `:root` CSS 변수를 수정하여 색상 테마를 변경할 수 있습니다:

```css
:root {
    --accent: #6366f1;  /* 메인 색상 */
    --bg-primary: #0a0a0f;  /* 배경색 */
}
```

### 네비게이션 링크 추가
sosig.shop의 메인 페이지에서 /route로 링크:

```html
<a href="/route">🌐 Network Route Tracer</a>
```
