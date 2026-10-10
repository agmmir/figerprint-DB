"""
Tests for chipset-first URL lookup and the (now removed) port-34567 heuristic.
Port 34567 alone no longer infers the Xiongmai chipset.
All network I/O is mocked; no real camera is contacted.
"""

import pytest
from unittest.mock import AsyncMock, patch

from camera_scanner.scanner import CameraScanner


def _mock_scan_internals(scanner, ports, http_info):
    """Context managers patching the network-facing scan internals."""
    return [
        patch.object(scanner, "_check_ports", return_value=ports),
        patch.object(scanner, "_http_probe", return_value=http_info),
        patch.object(scanner, "_rtsp_probe", return_value={}),
        patch.object(scanner, "_gather_fingerprint_data", return_value={}),
    ]


@pytest.mark.asyncio
async def test_port_34567_alone_does_not_infer_chipset():
    # Port 34567 alone is a shared DVRIP/Sofia port, not proof of Xiongmai.
    # It must NOT set result.chipset nor add a "34567->xiongmai" evidence entry.
    scanner = CameraScanner()
    patches = _mock_scan_internals(scanner, [80, 34567], {})
    with patches[0], patches[1], patches[2], patches[3], \
         patch.object(scanner, "_test_url_patterns", new=AsyncMock()):
        result = await scanner.scan("192.168.1.100")

    assert result.chipset is None
    assert not any("34567" in e for e in result.evidence)


def test_xiongmai_url_patterns_load():
    scanner = CameraScanner()
    patterns = scanner._get_url_patterns("xiongmai", None)
    assert "stream" in patterns
    assert len(patterns["stream"]) > 0
    assert len(patterns["snapshot"]) > 0


@pytest.mark.asyncio
async def test_port_34567_with_manufacturer_no_chipset_shortcut():
    # With port 34567 open and manufacturer=Hiseeu detected, there is no longer a
    # chipset shortcut: chipset stays None and URL lookup uses the manufacturer.
    scanner = CameraScanner()
    patches = _mock_scan_internals(scanner, [80, 34567], {"manufacturer": "Hiseeu"})
    captured = AsyncMock()
    with patches[0], patches[1], patches[2], patches[3], \
         patch.object(scanner, "_test_url_patterns", new=captured):
        result = await scanner.scan("192.168.1.100")

    assert result.manufacturer == "Hiseeu"   # OEM brand preserved
    assert result.chipset is None            # no unsupported Xiongmai attribution
    # Lookup must NOT use db/xiongmai.yaml anymore (no chipset set).
    url_patterns = captured.call_args.args[1]
    assert not any("stream=0.sdp" in u for u in url_patterns.get("stream", []))


@pytest.mark.asyncio
async def test_manufacturer_fallback_still_works():
    # chipset = None (no port 34567), manufacturer = Hikvision
    scanner = CameraScanner()
    patches = _mock_scan_internals(scanner, [80], {"manufacturer": "Hikvision"})
    captured = AsyncMock()
    with patches[0], patches[1], patches[2], patches[3], \
         patch.object(scanner, "_test_url_patterns", new=captured):
        result = await scanner.scan("192.168.1.100")

    assert result.chipset is None
    assert result.manufacturer == "Hikvision"
    url_patterns = captured.call_args.args[1]
    assert any("ISAPI" in u for u in url_patterns["snapshot"]), \
        "expected Hikvision patterns from db/hikvision.yaml"


@pytest.mark.asyncio
async def test_unknown_device_uses_generic_fallback():
    # manufacturer = None, chipset = None
    scanner = CameraScanner()
    patches = _mock_scan_internals(scanner, [80], {})
    captured = AsyncMock()
    with patches[0], patches[1], patches[2], patches[3], \
         patch.object(scanner, "_test_url_patterns", new=captured):
        result = await scanner.scan("192.168.1.100")

    assert result.manufacturer is None
    assert result.chipset is None
    url_patterns = captured.call_args.args[1]
    # Generic fallback patterns from db/_generic.yaml
    assert any("snapshot.jpg" in u for u in url_patterns["snapshot"])


if __name__ == "__main__":
    pytest.main([__file__])
