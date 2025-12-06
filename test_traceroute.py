#!/usr/bin/env python3
"""
TCP Traceroute 유닛 테스트

실행 방법:
    python -m pytest test_traceroute.py -v
    또는
    python test_traceroute.py
"""

import unittest
import socket
import struct
from unittest.mock import patch, MagicMock

# 테스트 대상 모듈 임포트
from tcp_traceroute import (
    is_private_ip,
    get_target_ip,
    get_local_ip,
    get_hostname,
    get_geolocation,
    get_connection_refused_errno,
    HopResult,
    ProbeResult,
    TracerouteResult,
    PacketParser,
    PROTOCOL_TCP,
    PROTOCOL_UDP,
    PROTOCOL_BOTH,
)


class TestPrivateIPDetection(unittest.TestCase):
    """Private IP 감지 테스트"""
    
    def test_private_ip_class_a(self):
        """10.x.x.x 대역 테스트"""
        self.assertTrue(is_private_ip("10.0.0.1"))
        self.assertTrue(is_private_ip("10.255.255.255"))
    
    def test_private_ip_class_b(self):
        """172.16.x.x - 172.31.x.x 대역 테스트"""
        self.assertTrue(is_private_ip("172.16.0.1"))
        self.assertTrue(is_private_ip("172.31.255.255"))
        self.assertFalse(is_private_ip("172.15.0.1"))
        self.assertFalse(is_private_ip("172.32.0.1"))
    
    def test_private_ip_class_c(self):
        """192.168.x.x 대역 테스트"""
        self.assertTrue(is_private_ip("192.168.0.1"))
        self.assertTrue(is_private_ip("192.168.255.255"))
    
    def test_loopback(self):
        """루프백 주소 테스트"""
        self.assertTrue(is_private_ip("127.0.0.1"))
        self.assertTrue(is_private_ip("127.255.255.255"))
    
    def test_public_ip(self):
        """공인 IP 테스트"""
        self.assertFalse(is_private_ip("8.8.8.8"))
        self.assertFalse(is_private_ip("1.1.1.1"))
        self.assertFalse(is_private_ip("142.250.207.14"))
    
    def test_invalid_ip(self):
        """잘못된 IP 형식 테스트"""
        self.assertFalse(is_private_ip("invalid"))
        self.assertFalse(is_private_ip("256.256.256.256"))


class TestDNSResolution(unittest.TestCase):
    """DNS 관련 함수 테스트"""
    
    def test_get_target_ip_valid(self):
        """유효한 호스트명 테스트"""
        # localhost는 항상 해석 가능
        ip = get_target_ip("localhost")
        self.assertIn(ip, ["127.0.0.1", "::1"])
    
    def test_get_target_ip_ip_passthrough(self):
        """IP 주소 직접 전달 테스트"""
        ip = get_target_ip("8.8.8.8")
        self.assertEqual(ip, "8.8.8.8")
    
    def test_get_local_ip(self):
        """로컬 IP 반환 테스트"""
        local_ip = get_local_ip("8.8.8.8")
        self.assertIsInstance(local_ip, str)
        # IP 형식 검증
        parts = local_ip.split(".")
        if local_ip != "127.0.0.1":
            self.assertEqual(len(parts), 4)
    
    @patch('socket.gethostbyaddr')
    def test_get_hostname_success(self, mock_gethostbyaddr):
        """호스트명 조회 성공 테스트"""
        mock_gethostbyaddr.return_value = ("google.com", [], [])
        # 캐시 클리어
        get_hostname.cache_clear()
        hostname = get_hostname("142.250.207.14")
        self.assertEqual(hostname, "google.com")
    
    @patch('socket.gethostbyaddr')
    def test_get_hostname_failure(self, mock_gethostbyaddr):
        """호스트명 조회 실패 시 IP 반환 테스트"""
        mock_gethostbyaddr.side_effect = socket.herror()
        get_hostname.cache_clear()
        hostname = get_hostname("1.2.3.4")
        self.assertEqual(hostname, "1.2.3.4")


class TestGeolocation(unittest.TestCase):
    """지리적 위치 조회 테스트"""
    
    def test_private_ip_returns_none(self):
        """Private IP는 None 반환"""
        get_geolocation.cache_clear()
        lat, lon = get_geolocation("192.168.1.1")
        self.assertIsNone(lat)
        self.assertIsNone(lon)
    
    @patch('urllib.request.urlopen')
    def test_geolocation_success(self, mock_urlopen):
        """위치 조회 성공 테스트"""
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"status":"success","lat":37.5665,"lon":126.978}'
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response
        
        get_geolocation.cache_clear()
        lat, lon = get_geolocation("8.8.8.8")
        self.assertEqual(lat, 37.5665)
        self.assertEqual(lon, 126.978)
    
    @patch('urllib.request.urlopen')
    def test_geolocation_api_failure(self, mock_urlopen):
        """API 실패 시 None 반환"""
        mock_urlopen.side_effect = TimeoutError()
        get_geolocation.cache_clear()
        lat, lon = get_geolocation("1.1.1.1")
        self.assertIsNone(lat)
        self.assertIsNone(lon)


class TestHopResult(unittest.TestCase):
    """HopResult 데이터 클래스 테스트"""
    
    def test_default_values(self):
        """기본값 테스트"""
        hop = HopResult(ttl=1)
        self.assertEqual(hop.ttl, 1)
        self.assertIsNone(hop.ip_address)
        self.assertIsNone(hop.hostname)
        self.assertIsNone(hop.rtt_ms)
        self.assertEqual(hop.status, "timeout")
    
    def test_full_initialization(self):
        """전체 초기화 테스트"""
        hop = HopResult(
            ttl=5,
            ip_address="8.8.8.8",
            hostname="dns.google",
            rtt_ms=15.5,
            latitude=37.0,
            longitude=127.0,
            status="intermediate"
        )
        self.assertEqual(hop.ttl, 5)
        self.assertEqual(hop.ip_address, "8.8.8.8")
        self.assertEqual(hop.hostname, "dns.google")
        self.assertEqual(hop.rtt_ms, 15.5)
        self.assertEqual(hop.status, "intermediate")


class TestTracerouteResult(unittest.TestCase):
    """TracerouteResult 데이터 클래스 테스트"""
    
    def test_initialization(self):
        """초기화 테스트"""
        result = TracerouteResult(
            target_host="google.com",
            target_ip="142.250.207.14",
            port=80,
            max_hops=30
        )
        self.assertEqual(result.target_host, "google.com")
        self.assertEqual(len(result.hops), 0)
    
    def test_to_dict(self):
        """딕셔너리 변환 테스트"""
        result = TracerouteResult(
            target_host="google.com",
            target_ip="142.250.207.14",
            port=80,
            max_hops=30
        )
        result.hops.append(HopResult(ttl=1, ip_address="192.168.1.1"))
        
        d = result.to_dict()
        self.assertEqual(d["target_host"], "google.com")
        self.assertEqual(len(d["hops"]), 1)
        self.assertEqual(d["hops"][0]["ttl"], 1)
    
    def test_to_json(self):
        """JSON 변환 테스트"""
        result = TracerouteResult(
            target_host="google.com",
            target_ip="142.250.207.14",
            port=80,
            max_hops=30
        )
        
        json_str = result.to_json()
        self.assertIn("google.com", json_str)
        self.assertIn("142.250.207.14", json_str)


class TestPacketParser(unittest.TestCase):
    """PacketParser 클래스 테스트"""
    
    def test_parse_ip_header(self):
        """IP 헤더 파싱 테스트"""
        # 간단한 IP 헤더 (IHL=5, Protocol=ICMP)
        ip_header = struct.pack(
            '!BBHHHBBH4s4s',
            0x45,  # Version=4, IHL=5
            0,     # TOS
            40,    # Total Length
            0,     # ID
            0,     # Flags, Fragment
            64,    # TTL
            1,     # Protocol (ICMP)
            0,     # Checksum
            b'\x08\x08\x08\x08',  # Source IP
            b'\xc0\xa8\x01\x01'   # Dest IP
        )
        
        protocol, header_len, total_len = PacketParser.parse_ip_header(ip_header)
        self.assertEqual(protocol, 1)  # ICMP
        self.assertEqual(header_len, 20)
        self.assertEqual(total_len, 40)
    
    def test_parse_ip_header_short_packet(self):
        """짧은 패킷 예외 테스트"""
        with self.assertRaises(ValueError):
            PacketParser.parse_ip_header(b'\x45\x00')
    
    def test_parse_icmp_header(self):
        """ICMP 헤더 파싱 테스트"""
        icmp_header = struct.pack('!BBHHH', 11, 0, 0, 0, 0)  # Time Exceeded
        icmp_type, icmp_code = PacketParser.parse_icmp_header(icmp_header)
        self.assertEqual(icmp_type, 11)
        self.assertEqual(icmp_code, 0)
    
    def test_parse_tcp_ports(self):
        """TCP 포트 파싱 테스트"""
        tcp_header = struct.pack('!HH', 12345, 80)
        src_port, dst_port = PacketParser.parse_tcp_ports(tcp_header)
        self.assertEqual(src_port, 12345)
        self.assertEqual(dst_port, 80)


class TestConnectionRefusedErrno(unittest.TestCase):
    """Connection Refused 에러 코드 테스트"""
    
    def test_returns_integer(self):
        """정수 반환 테스트"""
        errno_val = get_connection_refused_errno()
        self.assertIsInstance(errno_val, int)


class TestIntegration(unittest.TestCase):
    """통합 테스트 (실제 네트워크 호출 없음)"""
    
    def test_hop_result_lifecycle(self):
        """HopResult 라이프사이클 테스트"""
        # 타임아웃 홉
        timeout_hop = HopResult(ttl=1)
        self.assertEqual(timeout_hop.status, "timeout")
        
        # 중간 홉
        intermediate_hop = HopResult(
            ttl=2,
            ip_address="203.0.113.1",
            hostname="router.example.com",
            rtt_ms=10.5,
            status="intermediate"
        )
        self.assertEqual(intermediate_hop.status, "intermediate")
        
        # 최종 홉
        final_hop = HopResult(
            ttl=3,
            ip_address="93.184.216.34",
            hostname="example.com",
            rtt_ms=25.0,
            status="open"
        )
        self.assertEqual(final_hop.status, "open")
    
    def test_traceroute_result_aggregation(self):
        """TracerouteResult 집계 테스트"""
        result = TracerouteResult(
            target_host="example.com",
            target_ip="93.184.216.34",
            port=80,
            max_hops=30
        )
        
        # 여러 홉 추가
        result.hops.append(HopResult(ttl=1, status="timeout"))
        result.hops.append(HopResult(ttl=2, ip_address="10.0.0.1", rtt_ms=5.0))
        result.hops.append(HopResult(ttl=3, ip_address="93.184.216.34", status="open"))
        
        self.assertEqual(len(result.hops), 3)
        
        # JSON 변환 검증
        json_output = result.to_json()
        self.assertIn("example.com", json_output)
        self.assertIn("timeout", json_output)
        self.assertIn("open", json_output)


class TestProbeResult(unittest.TestCase):
    """ProbeResult 데이터 클래스 테스트"""
    
    def test_default_values(self):
        """기본값 테스트"""
        probe = ProbeResult()
        self.assertIsNone(probe.rtt_ms)
        self.assertFalse(probe.success)
        self.assertEqual(probe.protocol, "tcp")
    
    def test_tcp_probe(self):
        """TCP 프로브 테스트"""
        probe = ProbeResult(rtt_ms=5.5, success=True, protocol="tcp")
        self.assertEqual(probe.rtt_ms, 5.5)
        self.assertTrue(probe.success)
        self.assertEqual(probe.protocol, "tcp")
    
    def test_udp_probe(self):
        """UDP 프로브 테스트"""
        probe = ProbeResult(rtt_ms=10.2, success=True, protocol="udp")
        self.assertEqual(probe.rtt_ms, 10.2)
        self.assertTrue(probe.success)
        self.assertEqual(probe.protocol, "udp")
    
    def test_failed_probe(self):
        """실패한 프로브 테스트"""
        probe = ProbeResult(rtt_ms=None, success=False, protocol="tcp")
        self.assertIsNone(probe.rtt_ms)
        self.assertFalse(probe.success)


class TestProtocolConstants(unittest.TestCase):
    """프로토콜 상수 테스트"""
    
    def test_protocol_values(self):
        """프로토콜 상수값 테스트"""
        self.assertEqual(PROTOCOL_TCP, "tcp")
        self.assertEqual(PROTOCOL_UDP, "udp")
        self.assertEqual(PROTOCOL_BOTH, "both")


class TestHopResultWithProbes(unittest.TestCase):
    """프로브 목록을 포함한 HopResult 테스트"""
    
    def test_hop_with_probes(self):
        """프로브 목록 테스트"""
        probes = [
            ProbeResult(rtt_ms=5.0, success=True, protocol="tcp"),
            ProbeResult(rtt_ms=None, success=False, protocol="tcp"),
            ProbeResult(rtt_ms=6.0, success=True, protocol="udp"),
        ]
        
        hop = HopResult(
            ttl=5,
            ip_address="8.8.8.8",
            hostname="dns.google",
            rtt_ms=5.0,
            probes=probes,
            status="intermediate"
        )
        
        self.assertEqual(len(hop.probes), 3)
        self.assertEqual(hop.probes[0].rtt_ms, 5.0)
        self.assertFalse(hop.probes[1].success)
        self.assertEqual(hop.probes[2].protocol, "udp")


if __name__ == "__main__":
    # 테스트 실행
    unittest.main(verbosity=2)
