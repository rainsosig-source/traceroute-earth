# 로컬 테스트용 간단한 서버
from flask import Flask, render_template, jsonify, request
import sys
import os

# 상위 디렉토리 추가 (tcp_traceroute.py 접근용)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

app = Flask(__name__, static_folder='static', static_url_path='/static', template_folder='templates')
app.secret_key = 'test_secret_key'

@app.route('/')
def index():
    return '<h1>Test Server</h1><p><a href="/route">Go to Route Tracer</a></p>'

@app.route('/route')
def route_page():
    return render_template('route.html')

@app.route('/route/trace', methods=['POST'])
def trace():
    """TCP Traceroute 실행"""
    try:
        import subprocess
        import json
        
        data = request.json
        target = data.get('target', '')
        max_hops = data.get('max_hops', 20)
        probes = data.get('probes', 2)
        
        # 입력 검증
        if not target or not all(c.isalnum() or c in '.-_' for c in target):
            return jsonify({'success': False, 'error': '유효하지 않은 대상입니다.'})
        
        # tcp_traceroute.py 실행
        script_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tcp_traceroute.py')
        
        cmd = [
            sys.executable, script_path,
            target,
            '--max-hops', str(max_hops),
            '--probes', str(probes),
            '--json'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        
        # JSON 결과 파싱
        output = result.stdout
        if 'JSON 결과:' in output:
            json_str = output.split('JSON 결과:')[1].strip()
            data = json.loads(json_str)
            return jsonify({'success': True, **data})
        else:
            # JSON 출력 직접 파싱 시도
            try:
                data = json.loads(output)
                return jsonify({'success': True, **data})
            except:
                return jsonify({'success': False, 'error': 'Traceroute 실행 실패', 'details': output})
    
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': '시간 초과 (3분)'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    print("="*50)
    print("테스트 서버 시작")
    print("http://localhost:5000/route 에서 확인하세요")
    print("="*50)
    app.run(host='0.0.0.0', port=5000, debug=True)
