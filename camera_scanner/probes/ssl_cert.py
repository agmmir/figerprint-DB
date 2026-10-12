"""
SSL/TLS certificate probing.

Fetches the peer certificate from a TLS port and flattens its issuer and
subject Distinguished Names into plain strings (e.g. "O=DahuaTech OU=DAHUATECH
C=CN"). The certificate issuer is a very stable brand signal for professional
camera vendors (Dahua, Hikvision, Axis, Uniview, ...), unlike favicon/HTML
markers which change with firmware or web theme.

Standard library only (ssl, socket, asyncio) — no new dependencies. The
blocking ssl handshake runs in the default executor so the scan stays async.
Verification is intentionally disabled (CERT_NONE / check_hostname=False):
cameras ship self-signed certs and we only read the DN, never trust it.
"""

import asyncio
import logging
import socket
import ssl
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def _flatten_dn(dn: Any) -> str:
    """
    Flatten a cert DN (getpeercert() tuple-of-tuples form) into "K=V K=V ..."
    preserving original order and case. Returns "" for anything unexpected.
    """
    if not dn:
        return ""
    parts = []
    try:
        for rdn in dn:                       # dn: tuple of RDNs
            for item in rdn:                 # rdn: tuple of (key, value)
                if isinstance(item, (tuple, list)) and len(item) == 2:
                    key, value = item
                    parts.append(f"{key}={value}")
    except (TypeError, ValueError):
        return ""
    return " ".join(parts)


def _decode_der_cert(der: Optional[bytes]) -> Dict[str, Any]:
    """Parse issuer/subject from a DER certificate WITHOUT verification.

    getpeercert() returns {} under CERT_NONE (the cert is not validated), so we
    decode the always-available DER form via the standard library's own X.509
    decoder on a temporary PEM file. Stdlib only — no extra dependency.
    Returns {} on any failure.
    """
    if not der:
        return {}
    import tempfile
    import os
    import _ssl
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        tmp = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
        try:
            tmp.write(pem)
            tmp.close()
            return _ssl._test_decode_cert(tmp.name) or {}
        finally:
            os.unlink(tmp.name)
    except Exception as e:
        logger.debug(f"DER cert decode failed: {e}")
        return {}


def _modern_context() -> ssl.SSLContext:
    """Unverified context that still negotiates modern TLS (incl. TLS 1.3).
    Used first so current cameras (Axis/Hikvision on 1.3) keep working."""
    ctx = ssl._create_unverified_context()  # check_hostname=False, CERT_NONE
    return ctx


def _legacy_context() -> ssl.SSLContext:
    """Permissive context for legacy cameras that falsely advertise TLS 1.3 but
    only really speak TLS 1.0-1.2, often with weak ciphers. Verification stays
    off (we only read the DN, never trust it)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Old cameras lie about TLS 1.3 support: pin negotiation to <= 1.2.
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    # Allow weak ciphers used by 2010s firmware.
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    # Legacy (unsafe) renegotiation some cameras require.
    try:
        ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
    except (AttributeError, ValueError):
        pass
    return ctx


def _handshake_get_cert(ip: str, port: int, timeout: int,
                        context: ssl.SSLContext) -> Optional[Dict[str, Any]]:
    """One TLS handshake with `context`; returns the parsed peer cert or raises."""
    with socket.create_connection((ip, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=ip) as ssock:
            # Under CERT_NONE getpeercert() returns {} (cert not validated),
            # so fall back to parsing the always-available DER form.
            cert = ssock.getpeercert()
            if not cert:
                cert = _decode_der_cert(ssock.getpeercert(binary_form=True))
            return cert


def _get_cert_sync(ip: str, port: int, timeout: int) -> Optional[Dict[str, Any]]:
    """Blocking TLS handshake with a modern-then-legacy fallback.

    Attempt 1 (modern) keeps TLS 1.3-capable cameras working; attempt 2 (legacy)
    rescues old cameras that advertise but break TLS 1.3 and only speak <= 1.2.
    Returns the parsed peer certificate dict, or None if both attempts fail.
    """
    last_error = None
    for make_ctx in (_modern_context, _legacy_context):
        try:
            return _handshake_get_cert(ip, port, timeout, make_ctx())
        except (ssl.SSLError, socket.timeout, socket.gaierror, OSError) as e:
            last_error = e
            logger.debug(f"ssl_cert_probe {ip}:{port} handshake failed "
                         f"({make_ctx.__name__}): {type(e).__name__}: {e}")
            continue
        except Exception as e:  # unexpected, but never break the scan
            last_error = e
            logger.debug(f"ssl_cert_probe {ip}:{port} unexpected error "
                         f"({make_ctx.__name__}): {type(e).__name__}: {e}")
            continue
    if last_error is not None:
        logger.debug(f"ssl_cert_probe {ip}:{port} gave up after fallback: "
                     f"{type(last_error).__name__}: {last_error}")
    return None


async def ssl_cert_probe(ip: str, port: int = 443, timeout: int = 5) -> Optional[Dict[str, str]]:
    """
    Probe a TLS port and return {"ssl_issuer": "...", "ssl_subject": "..."}.

    Returns None if the host is unreachable, the handshake fails, or no
    certificate DN could be read. Never raises. Runs the blocking handshake in
    the event loop's default executor to stay non-blocking.
    """
    loop = asyncio.get_event_loop()
    try:
        cert = await loop.run_in_executor(None, _get_cert_sync, ip, port, timeout)
    except Exception as e:  # defensive: executor should not raise, but never break the scan
        logger.debug(f"SSL cert probe executor error for {ip}:{port}: {e}")
        return None

    if not cert:
        return None

    issuer = _flatten_dn(cert.get("issuer"))
    subject = _flatten_dn(cert.get("subject"))
    if not issuer and not subject:
        return None
    return {"ssl_issuer": issuer, "ssl_subject": subject, "_status": "ok"}
