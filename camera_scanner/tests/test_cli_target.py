"""ip:port CLI target: parsing and single-port scanning."""
from unittest.mock import AsyncMock, patch

import pytest

from camera_scanner.scanner import CameraScanner, parse_target


def test_cli_parses_ip_port():
    assert parse_target("1.2.3.4") == ("1.2.3.4", None)
    assert parse_target("1.2.3.4:8080") == ("1.2.3.4", 8080)
    assert parse_target("host.local:554") == ("host.local", 554)


def test_ipv6_left_alone():
    assert parse_target("fe80::1") == ("fe80::1", None)


@pytest.mark.parametrize("bad", ["1.2.3.4:0", "1.2.3.4:65536", "1.2.3.4:abc", "1.2.3.4:", ":80"])
def test_invalid_port_rejected(bad):
    with pytest.raises(SystemExit):
        parse_target(bad)


def test_explicit_port_limits_scanner_to_one_port():
    assert CameraScanner(port=7102).common_ports == [7102]
    assert len(CameraScanner().common_ports) > 20


@pytest.mark.asyncio
async def test_explicit_port_reaches_probes_and_urls():
    scanner = CameraScanner(port=7102)
    seen = {}

    async def fake_http(ip, timeout, extra_favicon_paths=None, port=None):
        seen["http"] = (ip, port)
        return {"_status": "ok"}

    async def fake_rtsp(ip, port, timeout):
        seen.setdefault("rtsp", []).append(port)
        return {"_status": "refused"}

    async def fake_check(ip, url, timeout, user="", password=""):
        seen.setdefault("urls", []).append(url)
        return None

    with patch("camera_scanner.probes.http.http_probe", side_effect=fake_http), \
         patch("camera_scanner.probes.rtsp.rtsp_probe", side_effect=fake_rtsp), \
         patch("camera_scanner.scanner.check_http_endpoint", side_effect=fake_check), \
         patch.object(scanner, "_check_ports", AsyncMock(return_value=[7102])) as cp, \
         patch.object(scanner, "_gather_fingerprint_data",
                      AsyncMock(return_value={"_network_status": "ok"})):
        result = await scanner.scan("1.2.3.4")

    assert result.open_ports == [7102]
    assert seen["http"] == ("1.2.3.4", 7102)
    assert seen["rtsp"] == [7102]
    assert seen["urls"] and all("1.2.3.4:7102" in u for u in seen["urls"] if u.startswith("http"))
    cp.assert_awaited_once()


def test_parse_ports():
    from camera_scanner.scanner import parse_ports
    assert parse_ports("7102, 9001,7102") == [7102, 9001]
    assert parse_ports("") == []
    for bad in ("0", "70000", "abc"):
        with pytest.raises(SystemExit):
            parse_ports(bad)


def test_extra_ports_appended_without_duplicates():
    ports = CameraScanner(extra_ports=[80, 7102]).common_ports
    assert ports.count(80) == 1 and ports[-1] == 7102
    assert CameraScanner(port=554, extra_ports=[7102]).common_ports == [554, 7102]


def _run_cli(*args):
    import subprocess, sys, os
    root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    return subprocess.run([sys.executable, "-m", "camera_scanner.scanner", *args],
                          cwd=root, capture_output=True, text=True, timeout=60)


def test_cli_resolve_without_ip_and_with_ip():
    raw = _run_cli("--resolve", "hikvision", "--model", "DS-2CD2143G0-I")
    assert raw.returncode == 0 and "{ip}" in raw.stdout
    filled = _run_cli("1.2.3.4", "--resolve", "hikvision", "--user", "a", "--password", "b")
    assert filled.returncode == 0 and "1.2.3.4" in filled.stdout and "{ip}" not in filled.stdout


def test_cli_requires_ip_or_resolve():
    assert _run_cli().returncode == 2
