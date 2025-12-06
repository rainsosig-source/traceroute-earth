"""
로컬 테스트용 Flask 서버
DB 연결 없이 /route 페이지만 테스트 가능
"""
from flask import Flask, render_template, request, jsonify
import json
import os

app = Flask(__name__, 
            template_folder='templates',
            static_folder='static')

@app.route('/')
def index():
    return '<h1>테스트 서버</h1><a href="/route">Route Tracer로 이동</a>'

@app.route('/route')
def route_page():
    return render_template('route.html')

@app.route('/route/trace', methods=['POST'])
def trace():
    """Mock traceroute - 테스트용 더미 데이터 반환"""
    data = request.get_json() or {}
    target = data.get('target', 'unknown')
    
    # 테스트용 더미 데이터
    mock_hops = [
        {'ttl': 1, 'ip': '192.168.1.1', 'hostname': 'router.local', 'rtts': [1.2, 1.5], 'latitude': 37.5, 'longitude': 127.0, 'country': 'South Korea', 'status': 'ok'},
        {'ttl': 2, 'ip': '10.0.0.1', 'hostname': 'gateway.isp', 'rtts': [5.3, 6.1], 'latitude': 37.4, 'longitude': 127.1, 'country': 'South Korea', 'status': 'ok'},
        {'ttl': 3, 'ip': '72.14.215.1', 'hostname': 'google-router', 'rtts': [15.2, 14.8], 'latitude': 35.6, 'longitude': 139.7, 'country': 'Japan', 'status': 'ok'},
        {'ttl': 4, 'ip': '142.250.66.46', 'hostname': target, 'rtts': [25.1, 24.5], 'latitude': 37.4, 'longitude': -122.1, 'country': 'United States', 'status': 'ok'},
    ]
    
    return jsonify({
        'success': True,
        'target': target,
        'target_ip': '142.250.66.46',
        'hops': mock_hops
    })

if __name__ == '__main__':
    print("\\n🌐 테스트 서버 시작: http://localhost:5000/route\\n")
    app.run(debug=True, host='0.0.0.0', port=5000)
