# Traceroute Earth 배포 스크립트
# 사용법: .\deploy.ps1 또는 .\deploy.ps1 -All
# 환경변수: DEPLOY_SERVER (예: root@your-server-ip)

param(
    [switch]$All,      # 모든 파일 배포
    [switch]$Html,     # HTML 템플릿만 배포
    [switch]$Python,   # Python 파일만 배포
    [switch]$Static    # Static 파일만 배포
)

$SERVER = $env:DEPLOY_SERVER
if (-not $SERVER) {
    Write-Host "❌ 환경변수 DEPLOY_SERVER가 설정되지 않았습니다." -ForegroundColor Red
    Write-Host "   예: `$env:DEPLOY_SERVER = 'root@your-server-ip'" -ForegroundColor Yellow
    exit 1
}
$REMOTE_PATH = "/root/flask-app"
$LOCAL_PATH = $PSScriptRoot


Write-Host "🚀 Traceroute Earth 배포 시작..." -ForegroundColor Cyan

# 기본값: HTML만 배포
if (-not $All -and -not $Html -and -not $Python -and -not $Static) {
    $Html = $true
}

# HTML 템플릿 배포
if ($Html -or $All) {
    Write-Host "📄 HTML 템플릿 업로드 중..." -ForegroundColor Yellow
    scp "$LOCAL_PATH\web\templates\route.html" "${SERVER}:${REMOTE_PATH}/templates/"
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ✅ route.html 업로드 완료" -ForegroundColor Green
    }
    else {
        Write-Host "  ❌ route.html 업로드 실패" -ForegroundColor Red
        exit 1
    }
}

# Python 파일 배포
if ($Python -or $All) {
    Write-Host "🐍 Python 파일 업로드 중..." -ForegroundColor Yellow
    scp "$LOCAL_PATH\web\route_blueprint.py" "${SERVER}:${REMOTE_PATH}/"
    scp "$LOCAL_PATH\tcp_traceroute.py" "${SERVER}:${REMOTE_PATH}/"
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ✅ Python 파일 업로드 완료" -ForegroundColor Green
    }
    else {
        Write-Host "  ❌ Python 파일 업로드 실패" -ForegroundColor Red
        exit 1
    }
}

# Static 파일 배포
if ($Static -or $All) {
    Write-Host "🎨 Static 파일 업로드 중..." -ForegroundColor Yellow
    scp -r "$LOCAL_PATH\web\static\*" "${SERVER}:${REMOTE_PATH}/static/"
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ✅ Static 파일 업로드 완료" -ForegroundColor Green
    }
    else {
        Write-Host "  ❌ Static 파일 업로드 실패" -ForegroundColor Red
        exit 1
    }
}

# Flask 앱 재시작
Write-Host "🔄 Flask 앱 재시작 중..." -ForegroundColor Yellow
ssh $SERVER "systemctl restart flask-app"
if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✅ Flask 앱 재시작 완료" -ForegroundColor Green
}
else {
    Write-Host "  ❌ Flask 앱 재시작 실패" -ForegroundColor Red
    exit 1
}

# 상태 확인
Write-Host "`n📊 서버 상태 확인..." -ForegroundColor Cyan
ssh $SERVER "systemctl status flask-app --no-pager | head -5"

Write-Host "`n✨ 배포 완료! https://sosig.shop/route 에서 확인하세요." -ForegroundColor Green
