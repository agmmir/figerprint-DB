"""
Tests for the CameraScanner class.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from camera_scanner.scanner import CameraScanner, format_result
from camera_scanner.models import CameraInfo


@pytest.mark.asyncio
async def test_scanner_initialization():
    """Test that the scanner initializes correctly."""
    scanner = CameraScanner(timeout=5, semaphore_size=10)
    assert scanner.timeout == 5
    assert scanner.semaphore._value == 10  # Semaphore internal value
    assert scanner.common_ports == [80, 443, 554, 8000, 8080, 34567, 37777, 37778]


@pytest.mark.asyncio
async def test_scan_no_open_ports():
    """Test scanning an IP with no open ports."""
    scanner = CameraScanner()

    # Mock _check_ports to return empty list
    with patch.object(scanner, '_check_ports', return_value=[]):
        result = await scanner.scan("192.168.1.1")

        assert isinstance(result, CameraInfo)
        assert result.ip == "192.168.1.1"
        assert result.open_ports == []
        assert result.protocols == []
        assert result.manufacturer is None
        assert result.model is None


@pytest.mark.asyncio
async def test_scan_with_open_ports():
    """Test scanning an IP with open ports."""
    scanner = CameraScanner()

    # Mock _check_ports to return some open ports
    with patch.object(scanner, '_check_ports', return_value=[80, 554]):
        # Mock _http_probe to return some manufacturer info
        with patch.object(scanner, '_http_probe', return_value={
            'manufacturer': 'Hikvision',
            'server': 'Hikvision Webs'
        }):
            # Mock _rtsp_probe to return empty (we're not testing RTSP here)
            with patch.object(scanner, '_rtsp_probe', return_value={}):
                # Mock _gather_fingerprint_data to return empty
                with patch.object(scanner, '_gather_fingerprint_data', return_value={}):
                    # Mock _get_url_patterns to return empty patterns
                    with patch.object(scanner, '_get_url_patterns', return_value={
                        'snapshot': [], 'stream': [], 'overlay': []
                    }):
                        # Mock _test_url_patterns to do nothing
                        with patch.object(scanner, '_test_url_patterns'):
                            result = await scanner.scan("192.168.1.100")

                            assert isinstance(result, CameraInfo)
                            assert result.ip == "192.168.1.100"
                            assert result.open_ports == [80, 554]
                            assert result.manufacturer == "Hikvision"
                            # Model should be None since we didn't set it in the mock
                            assert result.model is None


@pytest.mark.asyncio
async def test_scan_mode2_with_credentials():
    """Mode 2: credentials fill model/firmware/serial via ISAPI and verify URLs."""
    scanner = CameraScanner(user="admin", password="secret")

    with patch.object(scanner, '_check_ports', return_value=[80, 554]), \
         patch.object(scanner, '_http_probe', return_value={'manufacturer': 'Hikvision',
                                                            'server': 'Hikvision-Webs'}), \
         patch.object(scanner, '_rtsp_probe', return_value={}), \
         patch.object(scanner, '_gather_fingerprint_data', return_value={}), \
         patch.object(scanner, '_get_url_patterns', return_value={
             'snapshot': ['http://{ip}/ISAPI/Streaming/channels/101/picture'],
             'stream': [], 'overlay': []
         }), \
         patch('camera_scanner.probes.isapi.isapi_device_info',
               new=AsyncMock(return_value={'model': 'DS-2CD2043G2-I',
                                           'firmware_version': 'V5.7.3',
                                           'serial_number': 'ABC123'})), \
         patch('camera_scanner.scanner.check_http_endpoint',
               new=AsyncMock(return_value=200)):
        result = await scanner.scan("192.168.1.100")

    assert result.manufacturer == "Hikvision"
    assert result.model == "DS-2CD2043G2-I"
    assert result.firmware_version == "V5.7.3"
    assert result.serial_number == "ABC123"
    assert result.snapshot_urls == ["http://192.168.1.100/ISAPI/Streaming/channels/101/picture"]
    assert result.requires_auth_urls == []


@pytest.mark.asyncio
async def test_scan_mode1_requires_auth():
    """Mode 1: a 401 endpoint goes to requires_auth_urls, not snapshot_urls."""
    scanner = CameraScanner()  # no credentials

    with patch.object(scanner, '_check_ports', return_value=[80]), \
         patch.object(scanner, '_http_probe', return_value={'manufacturer': 'Hikvision'}), \
         patch.object(scanner, '_rtsp_probe', return_value={}), \
         patch.object(scanner, '_gather_fingerprint_data', return_value={}), \
         patch.object(scanner, '_get_url_patterns', return_value={
             'snapshot': ['http://{ip}/ISAPI/Streaming/channels/101/picture'],
             'stream': [], 'overlay': []
         }), \
         patch('camera_scanner.scanner.check_http_endpoint',
               new=AsyncMock(return_value=401)):
        result = await scanner.scan("192.168.1.100")

    assert result.manufacturer == "Hikvision"
    assert result.model is None
    assert result.snapshot_urls == []
    assert result.requires_auth_urls == ["http://192.168.1.100/ISAPI/Streaming/channels/101/picture"]


@pytest.mark.asyncio
async def test_url_patterns_parallel():
    """10 patterns with 1s each must complete in < 3s wall time."""
    import time

    scanner = CameraScanner(url_test_concurrency=10)
    patterns = {
        "stream": [],
        "snapshot": [f"http://x/{i}" for i in range(10)],
        "overlay": [],
    }

    async def slow_check(*args, **kwargs):
        await asyncio.sleep(1)
        return 404

    with patch("camera_scanner.scanner.check_http_endpoint", new=slow_check):
        result = CameraInfo(ip="127.0.0.1")
        t0 = time.monotonic()
        await scanner._test_url_patterns("127.0.0.1", patterns, result)
        elapsed = time.monotonic() - t0

    assert elapsed < 3.0, f"expected <3s, got {elapsed:.2f}s"


@pytest.mark.asyncio
async def test_url_patterns_concurrency_limit():
    """No more than url_test_concurrency checks run simultaneously."""
    scanner = CameraScanner(url_test_concurrency=3)
    patterns = {
        "stream": [],
        "snapshot": [f"http://x/{i}" for i in range(12)],
        "overlay": [],
    }

    state = {"current": 0, "max": 0}

    async def tracking_check(*args, **kwargs):
        state["current"] += 1
        state["max"] = max(state["max"], state["current"])
        await asyncio.sleep(0.05)
        state["current"] -= 1
        return 404

    with patch("camera_scanner.scanner.check_http_endpoint", new=tracking_check):
        result = CameraInfo(ip="127.0.0.1")
        await scanner._test_url_patterns("127.0.0.1", patterns, result)

    assert state["max"] <= scanner.url_test_concurrency, \
        f"max_concurrent {state['max']} exceeded limit {scanner.url_test_concurrency}"


@pytest.mark.asyncio
async def test_stream_early_exit_after_two():
    """Stream checks stop after two working stream URLs are found."""
    scanner = CameraScanner(url_test_concurrency=1)  # serial → deterministic early exit
    patterns = {
        "stream": [f"http://x/s{i}" for i in range(6)],
        "snapshot": [],
        "overlay": [],
    }
    calls = {"n": 0}

    async def ok_check(*args, **kwargs):
        calls["n"] += 1
        return 200

    with patch("camera_scanner.scanner.check_http_endpoint", new=ok_check):
        result = CameraInfo(ip="127.0.0.1")
        await scanner._test_url_patterns("127.0.0.1", patterns, result)

    assert len(result.stream_urls) == 2
    # With concurrency=1, no further stream checks are started after the 2nd success
    assert calls["n"] == 2


@pytest.mark.asyncio
async def test_stream_no_new_requests_after_limit():
    """After the 2-success stream limit is reached, queued stream checks must not
    start a network request; the checks already in flight still finish."""
    scanner = CameraScanner(url_test_concurrency=2)
    patterns = {"stream": [f"http://x/{i}" for i in range(5)], "snapshot": [], "overlay": []}

    started = {"n": 0}
    gate = asyncio.Event()

    async def gated_check(*args, **kwargs):
        # Count every network check that actually starts, then block on the gate.
        started["n"] += 1
        await gate.wait()
        return 200  # success -> stream bucket

    with patch("camera_scanner.scanner.check_http_endpoint", new=gated_check):
        result = CameraInfo(ip="127.0.0.1")
        runner = asyncio.create_task(scanner._test_url_patterns("127.0.0.1", patterns, result))
        # Yield control (no real-time wait) until the 2 semaphore slots are filled
        # and both in-flight checks are blocked on the gate.
        for _ in range(1000):
            if started["n"] >= 2:
                break
            await asyncio.sleep(0)
        assert started["n"] == 2, f"expected 2 in-flight, got {started['n']}"
        # Release the two in-flight checks -> they succeed, limit (2) is reached.
        gate.set()
        await runner

    # In-flight checks finished normally and filled exactly two stream URLs.
    assert set(result.stream_urls) == {"http://x/0", "http://x/1"}
    # The remaining 3 queued stream checks must NOT have started a network request.
    assert started["n"] == 2, f"expected 2 network checks total, got {started['n']}"


def test_generic_rtsp_routes_loaded_unique_and_clean():
    """Cameradar-imported generic RTSP routes load, are unique, and contain no credentials."""
    scanner = CameraScanner()
    patterns = scanner._get_url_patterns("generic", None)
    stream = patterns["stream"]
    # routes loaded and deduplicated
    assert len(stream) > 100
    assert len(stream) == len(set(stream))
    # a representative imported cameradar route is present
    assert any("cam/realmonitor?channel=1&subtype=0" in u for u in stream)
    assert any("axis-media/media.amp" in u for u in stream)
    # credential/example routes must NOT have been imported
    joined = "\n".join(stream).lower()
    for bad in ("password=", "usrnm", "r5xfy888", "@10.0.0.5", "access_code"):
        assert bad not in joined, f"credential-ish token leaked into generic routes: {bad}"


@pytest.mark.asyncio
async def test_dahua_sdk_port_fallback_sets_manufacturer():
    """Port 37777, device reached, no other signal -> Dahua as a weak (0.40) guess."""
    scanner = CameraScanner()
    with patch.object(scanner, '_check_ports', return_value=[80, 37777]), \
         patch.object(scanner, '_http_probe', return_value={}), \
         patch.object(scanner, '_rtsp_probe', return_value={}), \
         patch.object(scanner, '_gather_fingerprint_data', return_value={'_network_status': 'partial'}), \
         patch.object(scanner, '_test_url_patterns', new=AsyncMock()):
        result = await scanner.scan("192.0.2.10")
    assert result.manufacturer == "Dahua"
    assert result.confidence == 0.40
    assert "open_port:37777->dahua-guess" in result.evidence


@pytest.mark.asyncio
async def test_dahua_sdk_port_does_not_override_stronger_signal():
    """A stronger signal (fingerprint) must win; the port fallback must not override it."""
    scanner = CameraScanner()
    with patch.object(scanner, '_check_ports', return_value=[80, 37777]), \
         patch.object(scanner, '_http_probe', return_value={'manufacturer': 'Hikvision'}), \
         patch.object(scanner, '_rtsp_probe', return_value={}), \
         patch.object(scanner, '_gather_fingerprint_data', return_value={'_network_status': 'ok'}), \
         patch.object(scanner, '_test_url_patterns', new=AsyncMock()):
        result = await scanner.scan("192.0.2.11")
    assert result.manufacturer == "Hikvision"
    assert all("open_port:" not in e for e in result.evidence)


async def _scan_real_gather(http_ret, rtsp_ret=None, ports=(37777,)):
    """Run scan() with the real _gather_fingerprint_data; only probes are mocked."""
    scanner = CameraScanner()
    with patch.object(scanner, '_check_ports', return_value=list(ports)), \
         patch.object(scanner, '_http_probe', return_value=http_ret), \
         patch.object(scanner, '_rtsp_probe', return_value=rtsp_ret), \
         patch('camera_scanner.probes.onvif.onvif_probe', new=AsyncMock(return_value=[])), \
         patch('camera_scanner.probes.isapi.isapi_probe', new=AsyncMock(return_value={})), \
         patch.object(scanner, '_test_url_patterns', new=AsyncMock()):
        return await scanner.scan("192.0.2.20")


@pytest.mark.asyncio
async def test_network_unreachable_no_port_fallback():
    result = await _scan_real_gather(None, None)
    assert result.network_status == "unreachable"
    assert result.manufacturer is None
    assert all("open_port:" not in e for e in result.evidence)


@pytest.mark.asyncio
async def test_network_timeout_statuses_are_unreachable():
    result = await _scan_real_gather({'_status': 'timeout'}, {'_status': 'timeout'})
    assert result.network_status == "unreachable"
    assert result.manufacturer is None


@pytest.mark.asyncio
async def test_network_partial_port_fallback_allowed():
    result = await _scan_real_gather({'_status': 'ok', 'server': 'x'})
    assert result.network_status in ("ok", "partial")
    assert result.manufacturer == "Dahua"
    assert result.confidence == 0.40


@pytest.mark.asyncio
async def test_network_ok_strong_signal_wins():
    http = {'_status': 'ok', 'server': 'App-webs/',
            'www_authenticate': 'Digest realm="Hikvision"', 'html_content': ''}
    result = await _scan_real_gather(http)
    assert result.network_status == "ok"
    assert result.manufacturer == "Hikvision"
    assert all("open_port:" not in e for e in result.evidence)


def test_format_result_unreachable():
    out = format_result(CameraInfo(ip="192.0.2.1", network_status="unreachable", open_ports=[80]))
    assert "unreachable" in out and "could not contact device" in out
    assert "Manufacturer" not in out


def test_determine_protocols():
    """Test protocol determination from open ports."""
    scanner = CameraScanner()

    # Test standard ports
    protocols = scanner._determine_protocols([80, 443, 554])
    assert "HTTP" in protocols
    assert "HTTPS" in protocols
    assert "RTSP" in protocols

    # Test non-standard ports
    protocols = scanner._determine_protocols([8000, 8080, 34567])
    assert "HTTP-ALT" in protocols
    assert "HTTP-PROXY" in protocols
    assert "HTTP-HIKVISION" in protocols

    # Test empty list
    assert scanner._determine_protocols([]) == []


def test_format_url():
    """Test URL formatting."""
    scanner = CameraScanner()

    # Test basic IP replacement
    url = scanner._format_url("http://{ip}/path", "192.168.1.1")
    assert url == "http://192.168.1.1/path"

    # Test with user/pass placeholders
    url = scanner._format_url("http://{user}:{pass}@{ip}/path", "192.168.1.1")
    assert url == "http://:@192.168.1.1/path"

    # Test cleaning of double slashes
    url = scanner._format_url("http://{ip}//path//", "192.168.1.1")
    assert url == "http://192.168.1.1/path/"


if __name__ == "__main__":
    pytest.main([__file__])

# ---- public URL API + evidence propagation + formatter (Stage 7) ----

def test_resolve_urls_without_ip_returns_templates():
    sc = CameraScanner()
    pats = sc.resolve_urls(manufacturer="dahua")
    assert pats["stream"]
    assert any("{ip}" in u for u in pats["stream"])


def test_resolve_urls_with_ip_is_filled():
    sc = CameraScanner()
    pats = sc.resolve_urls(manufacturer="hikvision", ip="10.0.0.9")
    allu = pats["snapshot"] + pats["stream"]
    assert allu
    assert any("10.0.0.9" in u for u in allu)
    assert all("{ip}" not in u for u in allu)


def test_resolve_urls_generic_fallback():
    sc = CameraScanner()
    pats = sc.resolve_urls()  # no manufacturer -> generic
    assert any("snapshot.jpg" in u for u in pats["snapshot"])


@pytest.mark.asyncio
async def test_confidence_and_evidence_propagated_to_result():
    sc = CameraScanner()
    dahua_html = ('<html><head><title>WEB SERVICE</title>'
                  '<script src="jsCore/rpcLogin.js"></script></head><body></body></html>')
    with patch.object(sc, "_check_ports", return_value=[80]), \
         patch.object(sc, "_http_probe", return_value={}), \
         patch.object(sc, "_rtsp_probe", return_value={}), \
         patch.object(sc, "_gather_fingerprint_data",
                      return_value={"http_html_content": dahua_html}), \
         patch.object(sc, "_test_url_patterns", new=AsyncMock()):
        res = await sc.scan("192.168.0.5")
    assert res.manufacturer == "Dahua"
    assert res.confidence > 0.0
    assert res.evidence


def test_format_result_renders_sections():
    from camera_scanner.scanner import format_result
    from camera_scanner.models import CameraInfo
    info = CameraInfo(ip="1.2.3.4", manufacturer="Dahua", confidence=0.75,
                      evidence=["html:/webplugin.exe"],
                      stream_urls=["rtsp://1.2.3.4/cam"])
    txt = format_result(info)
    assert "Scan result: 1.2.3.4" in txt
    assert "Dahua" in txt
    assert "rtsp://1.2.3.4/cam" in txt


async def _scan_with_onvif(devices, dev_info, target="192.0.2.50"):
    scanner = CameraScanner()
    with patch.object(scanner, '_check_ports', return_value=[80]), \
         patch.object(scanner, '_http_probe', return_value={'_status': 'ok', 'server': 'x'}), \
         patch.object(scanner, '_rtsp_probe', return_value={}), \
         patch('camera_scanner.probes.onvif.onvif_probe', new=AsyncMock(return_value=devices)), \
         patch('camera_scanner.probes.onvif.onvif_get_device_info', new=AsyncMock(return_value=dev_info)), \
         patch.object(scanner, '_test_url_patterns', new=AsyncMock()):
        return await scanner.scan(target)


@pytest.mark.asyncio
async def test_onvif_result_from_target_reaches_result():
    dev = {'ip': '192.0.2.50', 'xaddr': 'http://192.0.2.50/onvif/device_service', 'onvif_capable': True}
    info = {'manufacturer': 'Hikvision', 'model': 'DS-2CD2043G2-I', 'firmware': 'V5.7.3', 'serial': 'SN1'}
    result = await _scan_with_onvif([dev], info)
    assert result.manufacturer == "Hikvision"
    assert result.model == "DS-2CD2043G2-I"
    assert result.firmware_version == "V5.7.3"
    assert result.serial_number == "SN1"
    assert result.confidence >= 0.99


@pytest.mark.asyncio
async def test_onvif_result_from_other_device_is_ignored():
    """A neighbour answering the multicast probe must not identify the target."""
    dev = {'ip': '192.0.2.99', 'xaddr': 'http://192.0.2.99/onvif/device_service', 'onvif_capable': True}
    info = {'manufacturer': 'Dahua', 'model': 'IPC-X'}
    result = await _scan_with_onvif([dev], info)
    assert result.manufacturer is None
    assert result.model is None


@pytest.mark.asyncio
async def test_isapi_mac_address_reaches_fingerprinter():
    """mac_address found by the ISAPI probe must be exposed at the top level for MAC OUI matching."""
    scanner = CameraScanner()
    http = {'_status': 'ok', 'server': 'Hikvision-Webs'}
    with patch.object(scanner, '_check_ports', return_value=[80]), \
         patch.object(scanner, '_http_probe', return_value=http), \
         patch.object(scanner, '_rtsp_probe', return_value={}), \
         patch('camera_scanner.probes.onvif.onvif_probe', new=AsyncMock(return_value=[])), \
         patch('camera_scanner.probes.isapi.isapi_probe',
               new=AsyncMock(return_value={'mac_address': '44:19:B6:00:11:22'})), \
         patch.object(scanner, '_test_url_patterns', new=AsyncMock()):
        result = await scanner.scan("192.0.2.60")
    assert result.manufacturer == "Hikvision"
    assert result.confidence == 0.95
    assert any(e.startswith("mac_oui:44:19:B6") for e in result.evidence)
