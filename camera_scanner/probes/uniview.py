"""
Uniview device-info probing.

Reads the device MODEL (and confirms the brand) from Uniview's web RPC endpoint
``/cgi-bin/main-cgi?json={"cmd":116}``. The reply is a small JSON object whose
``szDeviceName`` field is the model (e.g. "NVR302-32S"); the surrounding keys
(``szCustomerCode``, ``au32LangAbility``, ``u32PublicKey`` …) form a shape that
is distinctive to Uniview's web stack.

Only the model/identification fields are read. No credentials are sent and no
user/account or configuration data is requested or returned. Never raises: any
failure degrades to None so the scan continues.
"""

import json
import logging
from typing import Optional, Dict, Any

import aiohttp

logger = logging.getLogger(__name__)

# Uniview web RPC: cmd 116 returns basic device info (incl. szDeviceName = model).
DEVICE_INFO_PATH = '/cgi-bin/main-cgi?json={"cmd":116}'

# Keys (besides szDeviceName) characteristic of the Uniview main-cgi reply.
_UNIVIEW_MARKER_KEYS = (
    "szhttphost", "u32CurrentLang", "szCustomerCode",
    "au32LangAbility", "u32PublicKey", "u64PublicElement", "bIsConfigured",
)


def _device_name(data: Any) -> Optional[str]:
    if isinstance(data, dict):
        name = data.get("szDeviceName")
        if isinstance(name, str) and name.strip():
            return name.strip()
    return None


def _parse_device_name(text: str) -> Optional[str]:
    """Extract szDeviceName (the model) from a Uniview main-cgi JSON reply."""
    try:
        return _device_name(json.loads(text))
    except Exception:
        return None


def _looks_like_uniview(data: Any) -> bool:
    """True if the JSON has the distinctive Uniview main-cgi shape: a model name
    plus at least two of the characteristic sibling keys (guards against a
    generic object that merely happens to carry a szDeviceName)."""
    if not isinstance(data, dict) or not _device_name(data):
        return False
    return sum(1 for k in _UNIVIEW_MARKER_KEYS if k in data) >= 2


async def _fetch(ip: str, timeout: int, port: Optional[int]) -> Optional[Any]:
    authority = f"{ip}:{port}" if port else ip
    for scheme in ("http", "https"):
        url = f"{scheme}://{authority}{DEVICE_INFO_PATH}"
        try:
            timeout_obj = aiohttp.ClientTimeout(total=timeout)
            async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                async with session.get(url, ssl=False) as resp:
                    if resp.status != 200:
                        continue
                    text = await resp.text(encoding="utf-8", errors="ignore")
            data = json.loads(text)
            return data
        except Exception as e:
            logger.debug(f"Uniview probe failed for {scheme}://{ip}: {e}")
            continue
    return None


async def uniview_device_info(ip: str, timeout: int = 10,
                              port: Optional[int] = None) -> Optional[Dict[str, str]]:
    """Fetch the model for an already-identified Uniview device.
    Returns {"model": "<szDeviceName>"} or None. Unauthenticated; model only."""
    data = await _fetch(ip, timeout, port)
    name = _device_name(data)
    return {"model": name} if name else None


async def uniview_identify(ip: str, timeout: int = 10,
                           port: Optional[int] = None) -> Optional[Dict[str, str]]:
    """Identify an unknown device as Uniview from the distinctive main-cgi reply.
    Returns {"manufacturer": "Uniview", "model": "<szDeviceName>"} only when the
    response has the characteristic Uniview shape, else None."""
    data = await _fetch(ip, timeout, port)
    if _looks_like_uniview(data):
        return {"manufacturer": "Uniview", "model": _device_name(data)}
    return None
