"""
HTTP/HTTPS probing for IP cameras.
"""

import aiohttp
import asyncio
import hashlib
import logging
from typing import Dict, Any, Optional

try:
    from aiohttp import DigestAuthMiddleware
except ImportError:  # aiohttp < 3.11
    DigestAuthMiddleware = None

logger = logging.getLogger(__name__)

# Probe outcome ranking (best first) used to merge per-scheme results.
_STATUS_RANK = {"ok": 0, "empty": 1, "refused": 2, "timeout": 3, "unknown": 4}


def _classify_error(exc: BaseException) -> str:
    """Map a connection exception to a probe status."""
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return "timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(exc, aiohttp.ClientConnectorError) and \
            isinstance(getattr(exc, "os_error", None), ConnectionRefusedError):
        return "refused"
    return "unknown"


async def http_probe(ip: str, timeout: int = 10, extra_favicon_paths=None) -> Dict[str, Any]:
    """
    Probe HTTP/HTTPS endpoints on an IP address for camera information.

    Args:
        ip: Target IP address
        timeout: Request timeout in seconds

    Returns:
        Dictionary with any discovered information plus a "_status" key:
        ok (camera-like response), empty (device answered, nothing useful),
        refused, timeout or unknown. "_status" is not a fingerprint field.
    """
    info = {}
    probe_status = "unknown"
    schemes = ['http', 'https']

    for scheme in schemes:
        url = f"{scheme}://{ip}"
        try:
            timeout_obj = aiohttp.ClientTimeout(total=timeout)
            async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                # Fetch the root page, then capture what we need and CLOSE the
                # response before issuing any follow-up requests.
                status = None
                server = ''
                www_auth = ''
                text = ''
                async with session.get(url, ssl=False) as response:
                    # We consider 200, 401, 403 as potential camera responses
                    if response.status in (200, 401, 403):
                        status = response.status
                        server = response.headers.get('Server', '')
                        www_auth = response.headers.get('WWW-Authenticate', '')
                        # Try to get some HTML content (limited size)
                        try:
                            text = await response.text(encoding='utf-8', errors='ignore')
                            # Limit to first 2048 chars to avoid huge pages
                            if len(text) > 2048:
                                text = text[:2048]
                        except Exception:
                            text = ""

                # Not a camera-like response on this scheme: try the next one.
                if status is None:
                    # The host did answer, so it is reachable, just not useful.
                    if _STATUS_RANK["empty"] < _STATUS_RANK[probe_status]:
                        probe_status = "empty"
                    continue

                # Favicon requests are issued AFTER the main response context is
                # closed. Many cameras send "Connection: close", which can abort a
                # follow-up request made while the first response is still open.
                favicon_md5 = None
                favicon_mmh3 = None
                try:
                    favicon_url = f"{scheme}://{ip}/favicon.ico"
                    async with session.get(favicon_url, ssl=False) as fav_resp:
                        if fav_resp.status == 200:
                            favicon_bytes = await fav_resp.read()
                            favicon_md5 = hashlib.md5(favicon_bytes).hexdigest()
                            try:
                                from ..fingerprinter import favicon_mmh3_hash
                            except Exception:
                                try:
                                    from fingerprinter import favicon_mmh3_hash
                                except Exception:
                                    favicon_mmh3_hash = None
                            if favicon_mmh3_hash is not None:
                                favicon_mmh3 = favicon_mmh3_hash(favicon_bytes)
                except Exception:
                    pass

                # Favicon/image hashes on non-standard, signature-specified
                # paths (e.g. a vendor logo). Collected only when requested.
                favicon_md5_paths = {}
                for extra_path in (extra_favicon_paths or []):
                    try:
                        extra_url = f"{scheme}://{ip}{extra_path}"
                        async with session.get(extra_url, ssl=False) as ex_resp:
                            if ex_resp.status == 200:
                                ex_bytes = await ex_resp.read()
                                favicon_md5_paths[extra_path] = hashlib.md5(ex_bytes).hexdigest()
                    except Exception:
                        continue

                # Store the information
                info = {
                    'status': status,
                    'server': server,
                    'www_authenticate': www_auth,
                    'html_content': text,
                    'favicon_md5': favicon_md5,
                    'favicon_mmh3': favicon_mmh3,
                    'favicon_md5_paths': favicon_md5_paths,
                    'url': url,
                    '_status': 'ok',
                }

                # If we got useful info, we can break
                if info:
                    break
        except Exception as e:
            logger.debug(f"HTTP probe failed for {scheme}://{ip}: {e}")
            err_status = _classify_error(e)
            if _STATUS_RANK[err_status] < _STATUS_RANK[probe_status]:
                probe_status = err_status
            continue

    if not info:
        info = {'_status': probe_status}
    return info

async def check_http_endpoint(ip: str, path: str, timeout: int = 10,
                              user: str = "", password: str = "") -> Optional[int]:
    """
    Check a specific HTTP endpoint and return its status code.

    Args:
        ip: Target IP address
        path: Either a full URL ("http(s)://...") or a path (prefixed with "/")
        timeout: Request timeout
        user: Optional username for HTTP Digest auth
        password: Optional password for HTTP Digest auth

    Returns:
        The HTTP status code (int) for the first reachable candidate, or None if
        the endpoint could not be reached. The caller decides how to treat 200 vs
        401/403.
    """
    # Build candidate URLs: use a full URL as-is, otherwise try http then https.
    if path.startswith(('http://', 'https://')):
        candidates = [path]
    else:
        if not path.startswith('/'):
            path = '/' + path
        candidates = [f"{scheme}://{ip}{path}" for scheme in ('http', 'https')]

    middlewares = ()
    if (user or password) and DigestAuthMiddleware is not None:
        middlewares = (DigestAuthMiddleware(login=user, password=password),)

    for url in candidates:
        try:
            timeout_obj = aiohttp.ClientTimeout(total=timeout)
            async with aiohttp.ClientSession(timeout=timeout_obj, middlewares=middlewares) as session:
                async with session.get(url, ssl=False) as response:
                    if response.status < 500:
                        return response.status
        except Exception:
            continue
    return None