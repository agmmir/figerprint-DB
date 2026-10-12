"""Shared fixtures.

CameraScanner.scan() runs a TCP-proxy check that opens a real socket to
TEST-NET-1. Tests must never touch the network, so that check is stubbed to
"not proxied" for every test except those in test_proxy_detect.py, which
exercise the real detector with a mocked open_connection.
"""

import pytest

from camera_scanner.scanner import CameraScanner


@pytest.fixture(autouse=True)
def _no_real_proxy_check(request, monkeypatch):
    if request.module.__name__.endswith("test_proxy_detect"):
        return

    async def _not_proxied(self, timeout: float = 2.0) -> bool:
        return False

    monkeypatch.setattr(CameraScanner, "_is_tcp_proxied", _not_proxied)
