"""TCP proxy / VPN detection (real detector, mocked sockets)."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from camera_scanner.scanner import CameraScanner, format_result
from camera_scanner.models import CameraInfo


def _writer():
    w = MagicMock()
    w.wait_closed = AsyncMock()
    return w


@pytest.mark.asyncio
async def test_connect_succeeds_means_proxied():
    seen = {}

    async def fake_open(ip, port):
        seen["ip"], seen["port"] = ip, port
        return MagicMock(), _writer()

    with patch("camera_scanner.scanner.asyncio.open_connection", new=fake_open):
        assert await CameraScanner()._is_tcp_proxied() is True
    assert seen["ip"] == "192.0.2.1"          # TEST-NET-1, never routable
    assert 20000 <= seen["port"] <= 60000      # random high port


@pytest.mark.asyncio
@pytest.mark.parametrize("exc", [ConnectionRefusedError, OSError, asyncio.TimeoutError])
async def test_connect_fails_means_not_proxied(exc):
    async def fake_open(ip, port):
        raise exc()

    with patch("camera_scanner.scanner.asyncio.open_connection", new=fake_open):
        assert await CameraScanner()._is_tcp_proxied() is False


@pytest.mark.asyncio
async def test_hanging_connect_times_out_not_proxied():
    async def fake_open(ip, port):
        await asyncio.sleep(10)

    with patch("camera_scanner.scanner.asyncio.open_connection", new=fake_open):
        assert await CameraScanner()._is_tcp_proxied(timeout=0.05) is False


async def _scan(proxied):
    scanner = CameraScanner()
    with patch.object(scanner, "_is_tcp_proxied", new=AsyncMock(return_value=proxied)), \
         patch.object(scanner, "_check_ports", return_value=[80, 37777, 37778]), \
         patch.object(scanner, "_http_probe", return_value={}), \
         patch.object(scanner, "_rtsp_probe", return_value={}), \
         patch.object(scanner, "_gather_fingerprint_data",
                      return_value={"_network_status": "ok"}), \
         patch.object(scanner, "_test_url_patterns", new=AsyncMock()):
        return await scanner.scan("192.0.2.10")


@pytest.mark.asyncio
async def test_proxied_ports_kept_but_not_used_for_attribution():
    result = await _scan(True)
    assert result.tcp_proxied is True
    assert result.network_status == "ok"                  # decided by probes, not ports
    assert result.open_ports == [80, 37777, 37778]        # kept for information
    assert result.manufacturer is None                    # no port-37777 Dahua guess
    assert result.protocols == []                         # no port-derived protocols
    assert "port_scan: unreliable (tcp proxy detected)" in result.evidence
    assert all("open_port:" not in e for e in result.evidence)


@pytest.mark.asyncio
async def test_not_proxied_behaves_normally():
    result = await _scan(False)
    assert result.tcp_proxied is False
    assert result.manufacturer == "Dahua"                 # guarded fallback still works
    assert result.confidence == 0.40
    assert "DAHUA" in result.protocols
    assert all("tcp proxy" not in e for e in result.evidence)


def test_format_result_marks_proxy():
    out = format_result(CameraInfo(ip="192.0.2.1", network_status="ok",
                                   open_ports=[80, 81], tcp_proxied=True))
    assert "ok (behind TCP proxy" in out
    assert "(proxy-inflated)" in out


def test_format_result_marks_proxy_when_unreachable():
    out = format_result(CameraInfo(ip="192.0.2.1", network_status="unreachable",
                                   open_ports=[80], tcp_proxied=True))
    assert "behind TCP proxy" in out and "(proxy-inflated)" in out


def test_format_result_no_marker_without_proxy():
    out = format_result(CameraInfo(ip="192.0.2.1", network_status="ok", open_ports=[80]))
    assert "proxy" not in out
