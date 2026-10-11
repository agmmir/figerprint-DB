"""Tests for probes/ssl_cert.py — DN flattening and the CERT_NONE DER fallback.

The DER below is a throwaway self-signed cert (O=DahuaTech) generated only for
this test; it carries no secret and contacts no network.
"""
import base64
from camera_scanner.probes.ssl_cert import _flatten_dn, _decode_der_cert

# self-signed test cert: C=CN O=DahuaTech OU=DAHUATECH CN=Dahua Technology
_DER_B64 = (
    "MIIDgTCCAmmgAwIBAgIUS6qpemfQYwlA8kI9gpvbs9BkgbswDQYJKoZIhvcNAQELBQAwUDEL"
    "MAkGA1UEBhMCQ04xEjAQBgNVBAoMCURhaHVhVGVjaDESMBAGA1UECwwJREFIVUFURUNIMRkw"
    "FwYDVQQDDBBEYWh1YSBUZWNobm9sb2d5MB4XDTI2MTAxMTE2MTIxM1oXDTM2MTAwODE2MTIx"
    "M1owUDELMAkGA1UEBhMCQ04xEjAQBgNVBAoMCURhaHVhVGVjaDESMBAGA1UECwwJREFIVUFU"
    "RUNIMRkwFwYDVQQDDBBEYWh1YSBUZWNobm9sb2d5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"
    "MIIBCgKCAQEAsCgMaNUcwoaAbYZHp3AKTX0Yv43aChDCIifLMLEbzqY0Gx6G0xtEo66Qx/Q"
    "I1Tq4IIOGY6nlLiuaKniJPwmW2pcveKRZoFvxW/UF2dxlHa3MNwk/lAIkcBy6xuLO7SmOV+"
    "i8cfmBuTdaiI5L/DjJKneLSNIez+GkHTN74MifR56eyFCRnT2E1e9GivGXqaD0Ke/coXGqGT"
    "PEpt0rCbq4r4rMH3htgqpXTT+xgHlm3f306mAKad0TBfv2ajgWPgC7wrMfifvZioZvd0Hru"
    "ctW5C3jarn/CUZvfqYeeVPGz8M8S6dBASDf2UB95WYea/IGVzJAbgQ8GwfZffYG/VUc4wID"
    "AQABo1MwUTAdBgNVHQ4EFgQUapo92k9EksjmphyRY8XeyLhalIUwHwYDVR0jBBgwFoAUapo9"
    "2k9EksjmphyRY8XeyLhalIUwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEA"
    "cgtJLEQ9JVQom5+Hu8SOJDbq8A3G340Z+2pqKc0MRHDwn6nKV8R8si9h65vS5rS0D78DOQv"
    "WRkZGve8Bzc/NHfMnbNHHN5B5k+fNKPSNTTod8xoYIf5HpRuj7sqM7yB8emqRM9ckYIusTl"
    "wIKdYo57HWNKRVP3urai4OuqBpxa9c4jHuk7869l7dNmtdEvf8pgkkjRRaqUMm033NjSuDo"
    "EfvM7glZljpeOwDxmwCzPq64q6j8/o6U4RkiHXwd0uTyA/cQSv4sieZycHJtKKEhjCS196p"
    "R78PKeyXJW341+7Pj9MxAT3zDQsj/GdZgFe6UUkHx2oZBOwevqlUSvZepQ=="
)


def test_flatten_dn_tuple_form():
    dn = ((("organizationName", "DahuaTech"),), (("commonName", "Dahua"),))
    assert _flatten_dn(dn) == "organizationName=DahuaTech commonName=Dahua"


def test_flatten_dn_empty():
    assert _flatten_dn(None) == ""
    assert _flatten_dn(()) == ""


def test_decode_der_recovers_issuer_subject_under_cert_none():
    # Regression for the CERT_NONE bug: getpeercert() returns {} unverified, so
    # the probe must recover issuer/subject from the DER form.
    cert = _decode_der_cert(base64.b64decode(_DER_B64))
    assert cert, "DER decode returned empty"
    issuer = _flatten_dn(cert.get("issuer"))
    subject = _flatten_dn(cert.get("subject"))
    assert "DahuaTech" in issuer
    assert "DahuaTech" in subject


def test_decode_der_empty_input():
    assert _decode_der_cert(b"") == {}
    assert _decode_der_cert(None) == {}
