"""
Dahua CGI (magicBox) probing.

Mirrors the Hikvision ISAPI authenticated device-info path: a manufacturer-gated,
authenticated HTTP GET that fills gaps the fingerprinter left empty.

Authentication: Dahua DVR firmware (e.g. the confirmed 3.200.x DVR) answers HTTP
Basic auth; newer Dahua IP cameras commonly use Digest. We therefore try Basic
first (the demonstrated method) and fall back to Digest, per scheme, stopping at
the first usable version. Credentials are never logged.
"""

import aiohttp
import base64
import logging
from typing import Optional

try:
    from aiohttp import DigestAuthMiddleware
except ImportError:  # aiohttp < 3.11
    DigestAuthMiddleware = None

logger = logging.getLogger(__name__)

# Dahua devices expose firmware/version metadata via the magicBox CGI.
SOFTWARE_VERSION_PATH = '/cgi-bin/magicBox.cgi?action=getSoftwareVersion'


def _parse_cgi_version(text: str) -> Optional[str]:
    """
    Extract the ``version`` value from a Dahua magicBox CGI response.

    The response is a set of ``key=value`` lines, e.g. ``version=3.200.0001.22``.
    Surrounding whitespace and line endings are handled safely; the value itself
    is preserved exactly as returned (no normalisation or numeric conversion).
    Returns None if there is no usable, non-empty ``version`` value.
    """
    if not text:
        return None
    for line in text.splitlines():
        key, sep, value = line.partition('=')
        if not sep:
            continue
        if key.strip().lower() == 'version':
            value = value.strip()
            if value:
                return value
    return None


def _basic_auth_header(user: str, password: str) -> dict:
    """Build an HTTP Basic ``Authorization`` header (no credentials logged)."""
    token = base64.b64encode(f"{user}:{password}".encode()).decode('ascii')
    return {"Authorization": f"Basic {token}"}


async def _get_version_once(url: str, timeout: int, *,
                            headers: Optional[dict] = None,
                            digest=None) -> Optional[str]:
    """
    Issue one authenticated GET and parse the version, or return None.

    Pass either ``headers`` (Basic auth) or ``digest`` (a DigestAuthMiddleware).
    Only a 200 response is parsed; any other status yields None. Raises on
    transport errors (the caller treats those as "try the next method/scheme").
    """
    timeout_obj = aiohttp.ClientTimeout(total=timeout)
    session_kwargs = {}
    if digest is not None:
        session_kwargs['middlewares'] = (digest,)
    async with aiohttp.ClientSession(timeout=timeout_obj, **session_kwargs) as session:
        async with session.get(url, ssl=False, headers=headers) as response:
            if response.status == 200:
                text = await response.text(encoding='utf-8', errors='ignore')
                return _parse_cgi_version(text)
    return None


async def dahua_firmware_version(ip: str, user: str, password: str,
                                 timeout: int = 10) -> Optional[str]:
    """
    Fetch the firmware/software version from a Dahua device via magicBox CGI.

    Tries HTTP Basic auth first (confirmed for Dahua DVR firmware), then Digest
    as a controlled fallback, over http then https. Returns the version string
    exactly as reported by the device, or None when credentials are missing, the
    request fails (auth/connection/timeout/HTTP error), or the response has no
    usable version. Never raises: any failure degrades to None so the scan
    continues. Credentials are never logged.
    """
    if not user or not password:
        return None

    # (method label, factory) pairs; stop at the first one that yields a version.
    basic_header = _basic_auth_header(user, password)
    methods = [("basic", lambda: {"headers": basic_header})]
    if DigestAuthMiddleware is not None:
        methods.append(("digest",
                        lambda: {"digest": DigestAuthMiddleware(login=user, password=password)}))

    for scheme in ('http', 'https'):
        url = f"{scheme}://{ip}{SOFTWARE_VERSION_PATH}"
        for label, make_kwargs in methods:
            try:
                version = await _get_version_once(url, timeout, **make_kwargs())
                if version:
                    return version
            except Exception as e:
                # Log scheme/ip/method only — never credentials.
                logger.debug(f"Dahua getSoftwareVersion ({label}) failed for {scheme}://{ip}: {e}")
                continue
    return None
