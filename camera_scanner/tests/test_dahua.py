"""
Tests for Dahua firmware-version retrieval via the magicBox CGI, and for the
Dahua ports in the scanner's probe configuration.

All network I/O is mocked; no real camera is contacted. The confirmed example
device returned `version=3.200.0001.22` for
GET /cgi-bin/magicBox.cgi?action=getSoftwareVersion, authenticating with HTTP
Basic (curl --basic -u admin:admin).
"""

import asyncio
from contextlib import ExitStack
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from camera_scanner.probes import dahua as dahua_mod
from camera_scanner.probes.dahua import _parse_cgi_version, dahua_firmware_version
from camera_scanner.scanner import CameraScanner, format_result

# Synthetic test credentials only (never a real password)
TEST_USER = "admin"
TEST_PASS = "admin"
EXPECTED_VERSION = "3.200.0001.22"


# ----------------------------------------------------------------------------
# Fake aiohttp session so dahua_firmware_version can be driven without network.
# The probe opens a fresh ClientSession per (scheme, auth-method) attempt, so a
# single shared response queue is consumed in order across all of them. Each
# get() call is recorded with the auth method used (basic vs digest middleware).
# ----------------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, status=200, text="", exc=None):
        self.status = status
        self._text = text
        self._exc = exc

    async def __aenter__(self):
        if self._exc is not None:
            raise self._exc
        return self

    async def __aexit__(self, *args):
        return False

    async def text(self, encoding="utf-8", errors="ignore"):
        return self._text


class _FakeSession:
    def __init__(self, queue, default, has_digest, record):
        self._queue = queue
        self._default = default
        self._has_digest = has_digest
        self._record = record

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    def get(self, url, ssl=False, headers=None, auth=None):
        if self._record is not None:
            has_basic = bool(headers) and "Authorization" in headers
            self._record.append({"basic": has_basic, "digest": bool(self._has_digest)})
        if self._queue:
            return self._queue.pop(0)
        if self._default is not None:
            return self._default
        return _FakeResponse(status=404, text="")


def _patch_session(responses=None, default=None, record=None):
    """Patch aiohttp.ClientSession in the dahua module.

    `responses` is an ordered queue shared across every session created during
    the call (so http->https and basic->digest advance in order). When the queue
    is exhausted, `default` (if given) is returned for every further get(),
    otherwise a 404. `record` collects per-get auth metadata.
    """
    shared_queue = list(responses or [])

    def _factory(*args, **kwargs):
        has_digest = bool(kwargs.get("middlewares"))
        return _FakeSession(shared_queue, default, has_digest, record)

    return patch.object(dahua_mod.aiohttp, "ClientSession", _factory)


# ---- _parse_cgi_version ----------------------------------------------------

def test_parse_plain_version():
    assert _parse_cgi_version("version=3.200.0001.22") == EXPECTED_VERSION


def test_parse_with_whitespace_and_trailing_newline():
    assert _parse_cgi_version("  version=3.200.0001.22  \r\n") == EXPECTED_VERSION


def test_parse_version_preserved_exactly_not_numeric():
    v = _parse_cgi_version("version=3.200.0001.22\n")
    assert v == EXPECTED_VERSION
    assert isinstance(v, str)


def test_parse_missing_key_returns_none():
    assert _parse_cgi_version("type=DVR\nname=DVR") is None


def test_parse_empty_returns_none():
    assert _parse_cgi_version("") is None
    assert _parse_cgi_version("   \r\n  ") is None


def test_parse_empty_value_returns_none():
    assert _parse_cgi_version("version=") is None
    assert _parse_cgi_version("version=   ") is None


def test_parse_ignores_substring_keys():
    assert _parse_cgi_version("hardwareVersion=\nappVersionName=X") is None


# ---- dahua_firmware_version: auth behaviour (network mocked) ---------------

@pytest.mark.asyncio
async def test_firmware_basic_success_is_first_attempt():
    # Basic auth returns the version on the very first request.
    calls = []
    with _patch_session(responses=[_FakeResponse(200, f"version={EXPECTED_VERSION}\r\n")],
                        record=calls):
        fw = await dahua_firmware_version("10.0.0.5", TEST_USER, TEST_PASS, timeout=3)
    assert fw == EXPECTED_VERSION
    # Exactly one request, and it used Basic auth (not a digest middleware).
    assert len(calls) == 1
    assert calls[0] == {"basic": True, "digest": False}


@pytest.mark.asyncio
async def test_firmware_digest_fallback_when_basic_not_200():
    # Basic yields 401, Digest fallback then succeeds on the same scheme.
    calls = []
    with _patch_session(responses=[_FakeResponse(401, "Unauthorized"),
                                   _FakeResponse(200, f"version={EXPECTED_VERSION}")],
                        record=calls):
        fw = await dahua_firmware_version("10.0.0.5", TEST_USER, TEST_PASS, timeout=3)
    assert fw == EXPECTED_VERSION
    assert calls[0] == {"basic": True, "digest": False}   # basic tried first
    assert calls[1] == {"basic": False, "digest": True}   # digest fallback used


@pytest.mark.asyncio
async def test_firmware_no_credentials_returns_none():
    # Must not even construct a session without credentials.
    created = {"n": 0}

    def _factory(*args, **kwargs):
        created["n"] += 1
        return _FakeSession([], None, False, None)

    with patch.object(dahua_mod.aiohttp, "ClientSession", _factory):
        assert await dahua_firmware_version("10.0.0.5", "", "", timeout=3) is None
        assert await dahua_firmware_version("10.0.0.5", TEST_USER, "", timeout=3) is None
    assert created["n"] == 0


@pytest.mark.asyncio
async def test_firmware_auth_failure_returns_none():
    # 401 for every method/scheme -> None, no crash.
    with _patch_session(default=_FakeResponse(401, "Unauthorized")):
        fw = await dahua_firmware_version("10.0.0.5", TEST_USER, "wrongpass", timeout=3)
    assert fw is None


@pytest.mark.asyncio
async def test_firmware_http_error_returns_none():
    with _patch_session(default=_FakeResponse(500, "err")):
        fw = await dahua_firmware_version("10.0.0.5", TEST_USER, TEST_PASS, timeout=3)
    assert fw is None


@pytest.mark.asyncio
async def test_firmware_empty_body_returns_none():
    with _patch_session(default=_FakeResponse(200, "")):
        fw = await dahua_firmware_version("10.0.0.5", TEST_USER, TEST_PASS, timeout=3)
    assert fw is None


@pytest.mark.asyncio
async def test_firmware_malformed_body_returns_none():
    with _patch_session(default=_FakeResponse(200, "<html>garbage</html>")):
        fw = await dahua_firmware_version("10.0.0.5", TEST_USER, TEST_PASS, timeout=3)
    assert fw is None


@pytest.mark.asyncio
async def test_firmware_missing_version_key_returns_none():
    with _patch_session(default=_FakeResponse(200, "type=DVR\nname=DVR")):
        fw = await dahua_firmware_version("10.0.0.5", TEST_USER, TEST_PASS, timeout=3)
    assert fw is None


@pytest.mark.asyncio
async def test_firmware_whitespace_padded_body_parses():
    with _patch_session(default=_FakeResponse(200, "  version=3.200.0001.22  \r\n")):
        fw = await dahua_firmware_version("10.0.0.5", TEST_USER, TEST_PASS, timeout=3)
    assert fw == EXPECTED_VERSION


@pytest.mark.asyncio
async def test_firmware_connection_error_returns_none():
    with _patch_session(default=_FakeResponse(exc=ConnectionError("refused"))):
        fw = await dahua_firmware_version("10.0.0.5", TEST_USER, TEST_PASS, timeout=3)
    assert fw is None


@pytest.mark.asyncio
async def test_firmware_timeout_returns_none():
    with _patch_session(default=_FakeResponse(exc=asyncio.TimeoutError())):
        fw = await dahua_firmware_version("10.0.0.5", TEST_USER, TEST_PASS, timeout=3)
    assert fw is None


@pytest.mark.asyncio
async def test_firmware_falls_back_http_to_https():
    # http basic + digest both error out; https basic returns the version.
    with _patch_session(responses=[_FakeResponse(exc=ConnectionError("refused")),
                                   _FakeResponse(exc=ConnectionError("refused")),
                                   _FakeResponse(200, f"version={EXPECTED_VERSION}")]):
        fw = await dahua_firmware_version("10.0.0.5", TEST_USER, TEST_PASS, timeout=3)
    assert fw == EXPECTED_VERSION


# ---- scanner integration: firmware -----------------------------------------

def _dahua_scan_patches(scanner, dahua_fw_mock, http_status=200):
    return [
        patch.object(scanner, "_check_ports", return_value=[80, 554]),
        patch.object(scanner, "_http_probe",
                     return_value={"manufacturer": "Dahua", "server": "DahuaHttpd"}),
        patch.object(scanner, "_rtsp_probe", return_value={}),
        patch.object(scanner, "_gather_fingerprint_data", return_value={}),
        patch.object(scanner, "_get_url_patterns",
                     return_value={"snapshot": [], "stream": [], "overlay": []}),
        patch("camera_scanner.probes.dahua.dahua_firmware_version", new=dahua_fw_mock),
        patch("camera_scanner.scanner.check_http_endpoint",
              new=AsyncMock(return_value=http_status)),
    ]


@pytest.mark.asyncio
async def test_scan_dahua_populates_firmware():
    scanner = CameraScanner(user=TEST_USER, password=TEST_PASS)
    fw_mock = AsyncMock(return_value=EXPECTED_VERSION)
    with ExitStack() as stack:
        for p in _dahua_scan_patches(scanner, fw_mock):
            stack.enter_context(p)
        result = await scanner.scan("10.0.0.5")

    assert result.manufacturer == "Dahua"
    assert result.firmware_version == EXPECTED_VERSION
    fw_mock.assert_awaited_once()
    assert f"Firmware     : {EXPECTED_VERSION}" in format_result(result)


@pytest.mark.asyncio
async def test_scan_dahua_firmware_unknown_when_retrieval_fails():
    scanner = CameraScanner(user=TEST_USER, password=TEST_PASS)
    fw_mock = AsyncMock(return_value=None)
    with ExitStack() as stack:
        for p in _dahua_scan_patches(scanner, fw_mock):
            stack.enter_context(p)
        result = await scanner.scan("10.0.0.5")

    assert result.manufacturer == "Dahua"
    assert result.firmware_version is None
    assert "Firmware     : —" in format_result(result)


@pytest.mark.asyncio
async def test_scan_dahua_does_not_overwrite_existing_firmware():
    scanner = CameraScanner(user=TEST_USER, password=TEST_PASS)
    fw_mock = AsyncMock(return_value="")
    with ExitStack() as stack:
        stack.enter_context(patch.object(scanner, "_check_ports", return_value=[80]))
        stack.enter_context(patch.object(
            scanner, "_http_probe",
            return_value={"manufacturer": "Dahua", "firmware_version": "2.800.0000.1"}))
        stack.enter_context(patch.object(scanner, "_rtsp_probe", return_value={}))
        stack.enter_context(patch.object(scanner, "_gather_fingerprint_data", return_value={}))
        stack.enter_context(patch.object(
            scanner, "_get_url_patterns",
            return_value={"snapshot": [], "stream": [], "overlay": []}))
        stack.enter_context(patch("camera_scanner.probes.dahua.dahua_firmware_version", new=fw_mock))
        stack.enter_context(patch("camera_scanner.scanner.check_http_endpoint",
                                  new=AsyncMock(return_value=200)))
        result = await scanner.scan("10.0.0.5")

    assert result.firmware_version == "2.800.0000.1"
    fw_mock.assert_not_awaited()


@pytest.mark.asyncio
async def test_scan_non_dahua_does_not_call_dahua_cgi():
    scanner = CameraScanner(user=TEST_USER, password=TEST_PASS)
    fw_mock = AsyncMock(return_value=EXPECTED_VERSION)
    with ExitStack() as stack:
        stack.enter_context(patch.object(scanner, "_check_ports", return_value=[80]))
        stack.enter_context(patch.object(
            scanner, "_http_probe", return_value={"manufacturer": "Hikvision"}))
        stack.enter_context(patch.object(scanner, "_rtsp_probe", return_value={}))
        stack.enter_context(patch.object(scanner, "_gather_fingerprint_data", return_value={}))
        stack.enter_context(patch.object(
            scanner, "_get_url_patterns",
            return_value={"snapshot": [], "stream": [], "overlay": []}))
        stack.enter_context(patch("camera_scanner.probes.dahua.dahua_firmware_version", new=fw_mock))
        stack.enter_context(patch("camera_scanner.probes.isapi.isapi_device_info",
                                  new=AsyncMock(return_value=None)))
        stack.enter_context(patch("camera_scanner.scanner.check_http_endpoint",
                                  new=AsyncMock(return_value=200)))
        result = await scanner.scan("10.0.0.5")

    assert result.manufacturer == "Hikvision"
    fw_mock.assert_not_awaited()


@pytest.mark.asyncio
async def test_scan_dahua_without_credentials_skips_cgi():
    scanner = CameraScanner()  # no credentials
    fw_mock = AsyncMock(return_value=EXPECTED_VERSION)
    with ExitStack() as stack:
        for p in _dahua_scan_patches(scanner, fw_mock):
            stack.enter_context(p)
        result = await scanner.scan("10.0.0.5")

    assert result.manufacturer == "Dahua"
    assert result.firmware_version is None
    fw_mock.assert_not_awaited()


# ---- Dahua ports in the probe configuration --------------------------------

def test_common_ports_includes_dahua_ports():
    scanner = CameraScanner()
    assert 37777 in scanner.common_ports
    assert 37778 in scanner.common_ports
    # Existing camera ports are preserved.
    for p in (80, 443, 554, 8000, 8080, 34567):
        assert p in scanner.common_ports


class _FakeWriter:
    def close(self):
        pass

    async def wait_closed(self):
        return None


@pytest.mark.asyncio
async def test_check_ports_reports_only_confirmed_open():
    """37777 is reported only because the TCP connect succeeds; 37778 is a
    configured candidate but, when the connect is refused, must NOT be reported."""
    scanner = CameraScanner(timeout=1)
    open_set = {80, 37777}  # 37778 intentionally closed/unreachable

    async def fake_open_connection(host, port):
        if port in open_set:
            return (MagicMock(), _FakeWriter())
        raise ConnectionRefusedError()

    with patch("camera_scanner.scanner.asyncio.open_connection",
               new=fake_open_connection):
        open_ports = await scanner._check_ports("10.0.0.5")

    assert 37777 in open_ports          # confirmed open -> reported
    assert 37778 not in open_ports      # configured but refused -> not reported
    assert 80 in open_ports
    assert set(open_ports) == open_set


def test_determine_protocols_labels_dahua_ports():
    scanner = CameraScanner()
    protocols = scanner._determine_protocols([37777, 37778])
    assert "DAHUA" in protocols
    assert "DAHUA-UDP" in protocols
