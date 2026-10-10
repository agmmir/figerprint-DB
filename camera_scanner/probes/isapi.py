"""
Hikvision ISAPI probing.
"""

import aiohttp
import asyncio
import logging
import re
from typing import Dict, Any, List, Optional

try:
    from aiohttp import DigestAuthMiddleware
except ImportError:  # aiohttp < 3.11
    DigestAuthMiddleware = None

logger = logging.getLogger(__name__)

# Common ISAPI endpoints for Hikvision cameras
ISAPI_ENDPOINTS = {
    'system_info': '/ISAPI/System/deviceInfo',
    'version': '/ISAPI/System/version',
    'channels': '/ISAPI/System/Video/inputs/channels',
    'snapshot_channel_1': '/ISAPI/Streaming/channels/101/picture',
    'snapshot_channel_2': '/ISAPI/Streaming/channels/102/picture',
    'rtsp_channel_1': '/ISAPI/Streaming/channels/101',
    'rtsp_channel_2': '/ISAPI/Streaming/channels/102',
    'overlays': '/ISAPI/System/Video/inputs/channels/1/overlays/text',
}

async def isapi_probe(ip: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Probe ISAPI endpoints on a Hikvision camera.

    Args:
        ip: Target IP address
        timeout: Request timeout in seconds

    Returns:
        Dictionary with any discovered information
    """
    info = {}
    schemes = ['http', 'https']

    for scheme in schemes:
        base_url = f"{scheme}://{ip}"
        try:
            timeout_obj = aiohttp.ClientTimeout(total=timeout)
            async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                # Try to get system info first
                url = f"{base_url}{ISAPI_ENDPOINTS['system_info']}"
                async with session.get(url, ssl=False) as response:
                    if response.status == 200:
                        # Try to parse XML response
                        text = await response.text(encoding='utf-8', errors='ignore')
                        info = _parse_isapi_xml(text)
                        info['base_url'] = base_url
                        if info:
                            break
        except Exception as e:
            logger.debug(f"ISAPI probe failed for {scheme}://{ip}: {e}")
            continue

    return info

async def isapi_device_info(ip: str, user: str, password: str,
                            timeout: int = 10) -> Optional[Dict[str, Any]]:
    """
    Fetch authenticated device info from /ISAPI/System/deviceInfo (Hikvision).

    Uses HTTP Digest auth. Returns a dict with any of model, firmware_version,
    serial_number, device_name (plus whatever _parse_isapi_xml extracts), or None
    if credentials are missing, the request fails, or nothing could be parsed.
    """
    if not user or not password:
        return None
    if DigestAuthMiddleware is None:
        logger.warning("aiohttp DigestAuthMiddleware unavailable; cannot do authenticated ISAPI")
        return None

    for scheme in ('http', 'https'):
        url = f"{scheme}://{ip}/ISAPI/System/deviceInfo"
        try:
            timeout_obj = aiohttp.ClientTimeout(total=timeout)
            digest = DigestAuthMiddleware(login=user, password=password)
            async with aiohttp.ClientSession(timeout=timeout_obj, middlewares=(digest,)) as session:
                async with session.get(url, ssl=False) as response:
                    if response.status == 200:
                        text = await response.text(encoding='utf-8', errors='ignore')
                        info = _parse_isapi_xml(text)
                        name_match = re.search(r'<deviceName>(.*?)</deviceName>', text, re.IGNORECASE)
                        if name_match:
                            info['device_name'] = name_match.group(1).strip()
                        return info or None
        except Exception as e:
            logger.debug(f"ISAPI deviceInfo failed for {scheme}://{ip}: {e}")
            continue
    return None


def _parse_isapi_xml(xml_text: str) -> Dict[str, Any]:
    """
    Parse ISAPI XML response to extract device information.
    This is a simplified parser - a full implementation would use XML parsing.
    """
    info = {}
    if not xml_text:
        return info

    # Extract device information using simple regex (for demonstration)
    import re

    # Look for device description
    desc_match = re.search(r'<description>(.*?)</description>', xml_text, re.IGNORECASE)
    if desc_match:
        info['description'] = desc_match.group(1).strip()

    # Look for model
    model_match = re.search(r'<model>(.*?)</model>', xml_text, re.IGNORECASE)
    if model_match:
        info['model'] = model_match.group(1).strip()

    # Look for firmware version
    fw_match = re.search(r'<firmwareVersion>(.*?)</firmwareVersion>', xml_text, re.IGNORECASE)
    if fw_match:
        info['firmware_version'] = fw_match.group(1).strip()

    # Look for serial number
    sn_match = re.search(r'<serialNumber>(.*?)</serialNumber>', xml_text, re.IGNORECASE)
    if sn_match:
        info['serial_number'] = sn_match.group(1).strip()

    # Look for MAC address
    mac_match = re.search(r'<macAddress>(.*?)</macAddress>', xml_text, re.IGNORECASE)
    if mac_match:
        info['mac_address'] = mac_match.group(1).strip()

    return info

async def check_isapi_endpoint(ip: str, endpoint_key: str, timeout: int = 10) -> bool:
    """
    Check if a specific ISAPI endpoint exists.

    Args:
        ip: Target IP address
        endpoint_key: Key from ISAPI_ENDPOINTS dict
        timeout: Request timeout

    Returns:
        True if endpoint returns 200 or 401 (indicating presence)
    """
    if endpoint_key not in ISAPI_ENDPOINTS:
        logger.warning(f"Unknown ISAPI endpoint key: {endpoint_key}")
        return False

    path = ISAPI_ENDPOINTS[endpoint_key]
    schemes = ['http', 'https']

    for scheme in schemes:
        url = f"{scheme}://{ip}{path}"
        try:
            timeout_obj = aiohttp.ClientTimeout(total=timeout)
            async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                async with session.get(url, ssl=False) as response:
                    # Consider 200, 401, 403 as "found"
                    if response.status in (200, 401, 403):
                        return True
        except Exception:
            continue
    return False