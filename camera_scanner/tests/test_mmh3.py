"""Tests for mmh3 (Shodan/FingerprintHub) favicon hashing and matching.

The hash MUST equal Shodan's convention: mmh3.hash(base64.encodebytes(bytes)),
signed 32-bit. If the probe computed it any other way, it would silently never
match FingerprintHub values — so this is the regression that matters.
"""
import base64
import mmh3
import pytest

from camera_scanner.fingerprinter import favicon_mmh3_hash, fingerprint_camera


def test_favicon_mmh3_matches_shodan_convention():
    data = b"\x00\x01\x02 fake favicon bytes \xff\xfe" * 7
    expected = mmh3.hash(base64.encodebytes(data))  # signed, with newline-wrapped b64
    assert favicon_mmh3_hash(data) == expected


def test_favicon_mmh3_differs_from_plain_b64encode():
    # Guard against the classic bug: b64encode (no newlines) != encodebytes.
    data = b"x" * 200  # long enough that encodebytes inserts newlines
    assert base64.b64encode(data) != base64.encodebytes(data)
    assert favicon_mmh3_hash(data) == mmh3.hash(base64.encodebytes(data))


def test_favicon_mmh3_empty_returns_none():
    assert favicon_mmh3_hash(b"") is None
    assert favicon_mmh3_hash(None) is None


def test_dahua_by_favicon_mmh3():
    fp = fingerprint_camera({"http_favicon_mmh3": 2019488876})
    assert fp is not None
    assert fp["manufacturer"] == "Dahua"
    assert "favicon_mmh3:2019488876" in fp["evidence"]


def test_hikvision_by_favicon_mmh3():
    fp = fingerprint_camera({"http_favicon_mmh3": 999357577})
    assert fp is not None
    assert fp["manufacturer"] == "Hikvision"


def test_unknown_favicon_mmh3_returns_none():
    fp = fingerprint_camera({"http_favicon_mmh3": 123456789})
    assert fp is None or fp.get("manufacturer") is None


def test_favicon_mmh3_zero_not_crash():
    # 0 is a valid-ish int; must not be treated as "absent" incorrectly or crash.
    fp = fingerprint_camera({"http_favicon_mmh3": 0})
    assert fp is None or fp.get("manufacturer") is None
