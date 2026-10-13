import pytest
from unittest.mock import patch, AsyncMock

from camera_scanner.probes.uniview import _parse_device_name
from camera_scanner.scanner import CameraScanner

SAMPLE = (
    '{"szhttphost":"176.0.0.1","u32CurrentLang":7,"szDeviceName":"NVR302-32S",'
    '"szCustomerCode":"09","bIsConfigured":true,"code":0,"success":true}'
)


def test_parse_device_name_ok():
    assert _parse_device_name(SAMPLE) == "NVR302-32S"


def test_parse_device_name_rejects_garbage():
    assert _parse_device_name("not json") is None
    assert _parse_device_name('{"success":true}') is None       # no szDeviceName
    assert _parse_device_name('{"szDeviceName":"  "}') is None   # blank


@pytest.mark.asyncio
async def test_scan_fills_uniview_model_from_probe():
    sc = CameraScanner()
    html = {"http_html_content": "<html>/uniview login</html>"}  # -> manufacturer Uniview
    with patch.object(sc, "_check_ports", return_value=[80]), \
         patch.object(sc, "_http_probe", return_value={}), \
         patch.object(sc, "_rtsp_probe", return_value={}), \
         patch.object(sc, "_gather_fingerprint_data", return_value=html), \
         patch("camera_scanner.probes.uniview.uniview_device_info",
               new=AsyncMock(return_value={"model": "NVR302-32S"})), \
         patch.object(sc, "_test_url_patterns", new=AsyncMock()):
        res = await sc.scan("192.0.2.5")
    assert res.manufacturer == "Uniview"
    assert res.model == "NVR302-32S"
    assert "uniview:device_info" in res.evidence


from camera_scanner.probes.uniview import _looks_like_uniview
import json as _json


def test_looks_like_uniview_true_false():
    assert _looks_like_uniview(_json.loads(SAMPLE)) is True
    # a plain object with a szDeviceName but no sibling markers is rejected
    assert _looks_like_uniview({"szDeviceName": "X"}) is False
    assert _looks_like_uniview({"success": True}) is False


@pytest.mark.asyncio
async def test_scan_identifies_uniview_when_http_blank():
    sc = CameraScanner()
    with patch.object(sc, "_check_ports", return_value=[80]), \
         patch.object(sc, "_http_probe", return_value={}), \
         patch.object(sc, "_rtsp_probe", return_value={}), \
         patch.object(sc, "_gather_fingerprint_data",
                      return_value={"_network_status": "ok"}), \
         patch("camera_scanner.probes.uniview.uniview_identify",
               new=AsyncMock(return_value={"manufacturer": "Uniview", "model": "NVR302-32S"})), \
         patch.object(sc, "_test_url_patterns", new=AsyncMock()):
        res = await sc.scan("192.0.2.5")
    assert res.manufacturer == "Uniview"
    assert res.model == "NVR302-32S"
    assert res.confidence >= 0.80
    assert "uniview:main-cgi" in res.evidence
