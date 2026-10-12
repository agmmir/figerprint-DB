"""
RTSP probing for IP cameras.
"""

import asyncio
import base64
import hashlib
import logging
import os
import re
from typing import Dict, Any, Optional, Tuple

logger = logging.getLogger(__name__)

# RTSP stream verification verdicts
RTSP_OK = "ok"                      # DESCRIBE succeeded (anonymous or authenticated)
RTSP_AUTH_REQUIRED = "auth_required"  # challenge returned, no creds or creds rejected
RTSP_UNREACHABLE = "unreachable"    # connection/timeout/no RTSP response


def _parse_rtsp_status(text: str) -> Optional[int]:
    """Extract the numeric status code from an RTSP status line."""
    m = re.match(r'RTSP/\d\.\d\s+(\d+)', text)
    return int(m.group(1)) if m else None


def _auth_field(www_auth: str, name: str) -> Optional[str]:
    """Pull a single field value out of a WWW-Authenticate header."""
    m = re.search(name + r'\s*=\s*"?([^",]+)"?', www_auth)
    return m.group(1) if m else None


def _build_auth_header(user: str, password: str, method: str, uri: str, www_auth: str) -> Optional[str]:
    """
    Build an Authorization header value for an RTSP challenge.

    Supports Digest (MD5, with or without qop=auth) and Basic. Credentials are
    used verbatim (raw) so they must not be URL-encoded by the caller.
    """
    scheme = www_auth.strip().split(' ', 1)[0].lower()
    if scheme == 'basic':
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        return f"Basic {token}"
    if scheme != 'digest':
        return None

    realm = _auth_field(www_auth, 'realm') or ''
    nonce = _auth_field(www_auth, 'nonce') or ''
    qop = _auth_field(www_auth, 'qop')
    opaque = _auth_field(www_auth, 'opaque')
    algorithm = _auth_field(www_auth, 'algorithm') or 'MD5'

    ha1 = hashlib.md5(f"{user}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()

    if qop:
        nc = "00000001"
        cnonce = os.urandom(8).hex()
        response = hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()).hexdigest()
        header = (f'Digest username="{user}", realm="{realm}", nonce="{nonce}", uri="{uri}", '
                  f'response="{response}", qop={qop}, nc={nc}, cnonce="{cnonce}", algorithm={algorithm}')
    else:
        response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
        header = (f'Digest username="{user}", realm="{realm}", nonce="{nonce}", uri="{uri}", '
                  f'response="{response}", algorithm={algorithm}')
    if opaque:
        header += f', opaque="{opaque}"'
    return header


def _prefer_digest(values) -> str:
    """Pick the Digest challenge when a 401 offers several WWW-Authenticate
    values (commonly Digest AND Basic). Some devices — including some Dahua —
    reject Basic for RTSP, so Digest must win. Falls back to the first value."""
    for v in values:
        if v.strip().lower().startswith("digest"):
            return v
    return values[0] if values else ""


async def _rtsp_describe_once(ip: str, port: int, uri: str, cseq: int, timeout: int,
                             auth_header: Optional[str] = None) -> Tuple[Optional[int], Dict[str, str]]:
    """
    Send a single RTSP DESCRIBE and return (status_code, headers).

    status_code is None if the endpoint is unreachable or returns no RTSP response.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
    except Exception:
        return None, {}
    try:
        lines = [
            f"DESCRIBE {uri} RTSP/1.0",
            f"CSeq: {cseq}",
            "User-Agent: CameraScanner",
            "Accept: application/sdp",
        ]
        if auth_header:
            lines.append(f"Authorization: {auth_header}")
        request = "\r\n".join(lines) + "\r\n\r\n"
        writer.write(request.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
    except Exception:
        return None, {}
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    if not data:
        return None, {}
    text = data.decode('utf-8', errors='ignore')
    status = _parse_rtsp_status(text)
    headers: Dict[str, str] = {}
    www_auth_values = []
    for line in text.split('\r\n')[1:]:
        if line == '':
            break
        if ':' in line:
            k, v = line.split(':', 1)
            key = k.strip().lower()
            val = v.strip()
            if key == 'www-authenticate':
                www_auth_values.append(val)
            else:
                headers[key] = val
    if www_auth_values:
        # A 401 may carry several challenges (Digest and Basic). Prefer Digest.
        headers['www-authenticate'] = _prefer_digest(www_auth_values)
    return status, headers


async def rtsp_check_stream(ip: str, uri: str, port: int = 554, timeout: int = 10,
                            user: str = "", password: str = "") -> str:
    """
    Verify an RTSP stream via DESCRIBE, performing Digest/Basic auth when credentials
    are supplied. `uri` must be a credential-free RTSP URL (e.g. rtsp://host:port/path);
    raw (non-URL-encoded) `user`/`password` are used only to compute the auth header.

    Returns one of RTSP_OK, RTSP_AUTH_REQUIRED, RTSP_UNREACHABLE.
    """
    status, headers = await _rtsp_describe_once(ip, port, uri, 1, timeout)
    if status is None:
        return RTSP_UNREACHABLE
    if 200 <= status < 300:
        return RTSP_OK
    if status not in (401, 403):
        # Unsupported method / unavailable stream / other RTSP error
        return RTSP_UNREACHABLE

    www_auth = headers.get('www-authenticate', '')
    if not (user or password) or not www_auth:
        # Challenge present but we cannot (or were not asked to) authenticate
        return RTSP_AUTH_REQUIRED

    auth_header = _build_auth_header(user, password, "DESCRIBE", uri, www_auth)
    if not auth_header:
        return RTSP_AUTH_REQUIRED

    status2, _ = await _rtsp_describe_once(ip, port, uri, 2, timeout, auth_header)
    if status2 is not None and 200 <= status2 < 300:
        return RTSP_OK
    # Includes invalid credentials (another 401) → not a verified stream
    return RTSP_AUTH_REQUIRED

async def rtsp_probe(ip: str, port: int = 554, timeout: int = 10) -> Dict[str, Any]:
    """
    Probe an RTSP endpoint on an IP address and port.

    Args:
        ip: Target IP address
        port: RTSP port (default 554)
        timeout: Connection timeout in seconds

    Returns:
        Dictionary with any discovered information
    """
    info = {'_status': 'unknown'}
    try:
        # Open connection to the RTSP port
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )

        # Send RTSP OPTIONS request
        request = (
            f"OPTIONS rtsp://{ip}/ RTSP/1.0\r\n"
            f"CSeq: 1\r\n"
            f"User-Agent: CameraScanner\r\n"
            f"\r\n"
        )
        writer.write(request.encode())
        await writer.drain()

        # Read response (with limit to avoid large responses)
        response = await asyncio.wait_for(reader.read(1024), timeout=timeout)

        # Close connection
        writer.close()
        await writer.wait_closed()

        info['_status'] = 'empty'  # TCP connect succeeded
        if response:
            response_str = response.decode('utf-8', errors='ignore')
            # Check if it's a valid RTSP response
            if 'RTSP' in response_str and '200' in response_str:
                info['rtsp_available'] = True
                info['_status'] = 'ok'
                info['raw_response'] = response_str

                # Try to extract server information from headers
                # RTSP headers are similar to HTTP
                server_match = re.search(r'Server:\s*(.+)', response_str, re.IGNORECASE)
                if server_match:
                    info['server'] = server_match.group(1).strip()
                    # Also expose under 'rtsp_server' for fingerprint matching
                    info['rtsp_server'] = info['server']

                # Extract CSeq for validation
                cseq_match = re.search(r'CSeq:\s*(\d+)', response_str, re.IGNORECASE)
                if cseq_match:
                    info['cseq'] = cseq_match.group(1)

    except asyncio.TimeoutError:
        logger.debug(f"RTSP probe timeout on {ip}:{port}")
        info['_status'] = 'timeout'
    except ConnectionRefusedError:
        info['_status'] = 'refused'
        logger.debug(f"RTSP connection refused on {ip}:{port}")
    except Exception as e:
        logger.debug(f"RTSP probe error on {ip}:{port}: {e}")

    return info

async def rtsp_describe(ip: str, path: str, port: int = 554, timeout: int = 10) -> Dict[str, Any]:
    """
    Send RTSP DESCRIBE request to a specific path to get stream information.

    Args:
        ip: Target IP address
        path: RTSP path (e.g., /Streaming/Channels/101)
        port: RTSP port
        timeout: Request timeout

    Returns:
        Dictionary with DESCRIBE response information
    """
    info = {}
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )

        # Build RTSP DESCRIBE request
        request = (
            f"DESCRIBE rtsp://{ip}{path} RTSP/1.0\r\n"
            f"CSeq: 2\r\n"
            f"User-Agent: CameraScanner\r\n"
            f"Accept: application/sdp\r\n"
            f"\r\n"
        )
        writer.write(request.encode())
        await writer.drain()

        # Read response
        response = await asyncio.wait_for(reader.read(2048), timeout=timeout)

        writer.close()
        await writer.wait_closed()

        if response:
            response_str = response.decode('utf-8', errors='ignore')
            if 'RTSP' in response_str and ('200' in response_str or '401' in response_str):
                info['success'] = True
                info['raw_response'] = response_str

                # Extract SDP content if present
                # SDP starts after a blank line
                parts = response_str.split('\r\n\r\n', 1)
                if len(parts) > 1:
                    info['sdp'] = parts[1]

                # Extract Server header
                import re
                server_match = re.search(r'Server:\s*(.+)', response_str, re.IGNORECASE)
                if server_match:
                    info['server'] = server_match.group(1).strip()

    except Exception as e:
        logger.debug(f"RTSP DESCRIBE error on {ip}:{port}{path}: {e}")

    return info