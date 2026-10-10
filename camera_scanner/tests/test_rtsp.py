"""
Tests for authenticated RTSP verification and check_http_endpoint status semantics.
All network I/O is mocked; no real camera is contacted.
"""

import hashlib
import pytest
from unittest.mock import AsyncMock, patch

from camera_scanner.probes import rtsp as rtsp_mod
from camera_scanner.probes.rtsp import (
    rtsp_check_stream, _build_auth_header,
    RTSP_OK, RTSP_AUTH_REQUIRED, RTSP_UNREACHABLE,
)
from camera_scanner.probes import http as http_mod
from camera_scanner.probes.http import check_http_endpoint
from camera_scanner.scanner import CameraScanner

# Synthetic test credentials only (never a real password)
TEST_USER = "testuser"
TEST_PASS = "P@ss:word/123"
DIGEST_CHALLENGE = {"www-authenticate": 'Digest realm="IP Camera", nonce="abc123", qop="auth"'}
URI = "rtsp://10.0.0.5:554/Streaming/Channels/101"


@pytest.mark.asyncio
async def test_rtsp_anonymous_ok():
    with patch.object(rtsp_mod, "_rtsp_describe_once",
                      new=AsyncMock(side_effect=[(200, {})])):
        verdict = await rtsp_check_stream("10.0.0.5", URI)
    assert verdict == RTSP_OK


@pytest.mark.asyncio
async def test_rtsp_no_credentials_auth_required():
    # 401 challenge, no credentials supplied -> must not be verified
    with patch.object(rtsp_mod, "_rtsp_describe_once",
                      new=AsyncMock(side_effect=[(401, DIGEST_CHALLENGE)])):
        verdict = await rtsp_check_stream("10.0.0.5", URI)
    assert verdict == RTSP_AUTH_REQUIRED


@pytest.mark.asyncio
async def test_rtsp_valid_digest_ok():
    # 401 challenge, then authenticated DESCRIBE succeeds
    with patch.object(rtsp_mod, "_rtsp_describe_once",
                      new=AsyncMock(side_effect=[(401, DIGEST_CHALLENGE), (200, {})])):
        verdict = await rtsp_check_stream("10.0.0.5", URI, user=TEST_USER, password=TEST_PASS)
    assert verdict == RTSP_OK


@pytest.mark.asyncio
async def test_rtsp_invalid_credentials_not_verified():
    # 401 challenge, then still 401 after auth attempt -> not a working stream
    with patch.object(rtsp_mod, "_rtsp_describe_once",
                      new=AsyncMock(side_effect=[(401, DIGEST_CHALLENGE), (401, DIGEST_CHALLENGE)])):
        verdict = await rtsp_check_stream("10.0.0.5", URI, user=TEST_USER, password="wrongpass")
    assert verdict == RTSP_AUTH_REQUIRED


@pytest.mark.asyncio
async def test_rtsp_unreachable():
    with patch.object(rtsp_mod, "_rtsp_describe_once",
                      new=AsyncMock(side_effect=[(None, {})])):
        verdict = await rtsp_check_stream("10.0.0.5", URI)
    assert verdict == RTSP_UNREACHABLE


def test_digest_header_uses_raw_credentials_no_double_encoding():
    # Credentials with special chars must be used verbatim (not URL-encoded)
    www = 'Digest realm="IP Camera", nonce="abc123"'  # no qop -> deterministic
    header = _build_auth_header(TEST_USER, TEST_PASS, "DESCRIBE", URI, www)
    # Recompute the expected digest response from RAW credentials
    ha1 = hashlib.md5(f"{TEST_USER}:IP Camera:{TEST_PASS}".encode()).hexdigest()
    ha2 = hashlib.md5(f"DESCRIBE:{URI}".encode()).hexdigest()
    expected = hashlib.md5(f"{ha1}:abc123:{ha2}".encode()).hexdigest()
    assert f'response="{expected}"' in header
    assert f'username="{TEST_USER}"' in header
    # The raw special-char password must never appear in the header
    assert TEST_PASS not in header


# ---- check_http_endpoint status semantics ----

class _FakeResp:
    def __init__(self, status):
        self.status = status
    async def __aenter__(self):
        return self
    async def __aexit__(self, *a):
        return False


class _FakeSession:
    _status = 200
    _raise = False
    def __init__(self, *a, **kw):
        pass
    async def __aenter__(self):
        return self
    async def __aexit__(self, *a):
        return False
    def get(self, url, ssl=False):
        if _FakeSession._raise:
            raise OSError("connection refused")
        return _FakeResp(_FakeSession._status)


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [200, 401, 403])
async def test_check_http_endpoint_returns_status(status):
    _FakeSession._status = status
    _FakeSession._raise = False
    with patch.object(http_mod.aiohttp, "ClientSession", _FakeSession):
        result = await check_http_endpoint("10.0.0.5", "http://10.0.0.5/x", timeout=1)
    assert result == status


@pytest.mark.asyncio
async def test_check_http_endpoint_unreachable_returns_none():
    _FakeSession._raise = True
    with patch.object(http_mod.aiohttp, "ClientSession", _FakeSession):
        result = await check_http_endpoint("10.0.0.5", "/x", timeout=1)
    _FakeSession._raise = False
    assert result is None


# ---- scanner-level integration: RTSP verdict -> stream_urls / requires_auth_urls ----

@pytest.mark.asyncio
async def test_scan_rtsp_valid_creds_goes_to_stream_urls():
    scanner = CameraScanner(user=TEST_USER, password=TEST_PASS)
    with patch.object(scanner, "_check_ports", return_value=[554]), \
         patch.object(scanner, "_http_probe", return_value={"manufacturer": "Hikvision"}), \
         patch.object(scanner, "_rtsp_probe", return_value={}), \
         patch.object(scanner, "_gather_fingerprint_data", return_value={}), \
         patch.object(scanner, "_get_url_patterns", return_value={
             "snapshot": [], "stream": ["rtsp://{user}:{pass}@{ip}:554/Streaming/Channels/101"],
             "overlay": []
         }), \
         patch("camera_scanner.probes.rtsp.rtsp_check_stream",
               new=AsyncMock(return_value=RTSP_OK)):
        result = await scanner.scan("10.0.0.5")
    assert result.stream_urls == ["rtsp://testuser:P%40ss%3Aword%2F123@10.0.0.5:554/Streaming/Channels/101"]
    assert result.requires_auth_urls == []


@pytest.mark.asyncio
async def test_scan_rtsp_no_creds_goes_to_requires_auth():
    scanner = CameraScanner()  # no credentials
    with patch.object(scanner, "_check_ports", return_value=[554]), \
         patch.object(scanner, "_http_probe", return_value={"manufacturer": "Hikvision"}), \
         patch.object(scanner, "_rtsp_probe", return_value={}), \
         patch.object(scanner, "_gather_fingerprint_data", return_value={}), \
         patch.object(scanner, "_get_url_patterns", return_value={
             "snapshot": [], "stream": ["rtsp://{user}:{pass}@{ip}:554/Streaming/Channels/101"],
             "overlay": []
         }), \
         patch("camera_scanner.probes.rtsp.rtsp_check_stream",
               new=AsyncMock(return_value=RTSP_AUTH_REQUIRED)):
        result = await scanner.scan("10.0.0.5")
    assert result.stream_urls == []
    assert result.requires_auth_urls == ["rtsp://:@10.0.0.5:554/Streaming/Channels/101"]


if __name__ == "__main__":
    pytest.main([__file__])
