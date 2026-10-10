"""
Camera fingerprinting: rule-based, multi-signal, with confidence scoring.
"""

import re
import os
import hashlib
import yaml
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional


@dataclass
class Fingerprint:
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    serial_number: Optional[str] = None
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "manufacturer": self.manufacturer,
            "model": self.model,
            "firmware_version": self.firmware_version,
            "serial_number": self.serial_number,
            "confidence": round(self.confidence, 2),
            "evidence": self.evidence,
        }


def _load_signatures() -> Dict[str, Any]:
    path = os.path.join(os.path.dirname(__file__), "db", "signatures.yaml")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


SIGNATURES = _load_signatures()


def _marker_in(marker, haystack_lower: str) -> bool:
    """Substring match. A list/tuple marker means AND: every part must be present."""
    if isinstance(marker, (list, tuple)):
        return all(str(p).lower() in haystack_lower for p in marker)
    return str(marker).lower() in haystack_lower


def _marker_label(marker) -> str:
    if isinstance(marker, (list, tuple)):
        return "&&".join(str(p) for p in marker)
    return str(marker)


def fingerprint_camera(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Main entry point. `data` may contain any of:
      - onvif_manufacturer, onvif_model, onvif_firmware, onvif_serial
      - http_server
      - http_www_authenticate
      - http_html_content
      - http_favicon_md5
      - rtsp_server
      - mac_address
    """
    fp = Fingerprint()

    # ---------- 1. ONVIF — самый надёжный источник ----------
    if data.get("onvif_manufacturer"):
        fp.manufacturer = _normalize_brand(data["onvif_manufacturer"])
        fp.model = data.get("onvif_model")
        fp.firmware_version = data.get("onvif_firmware")
        fp.serial_number = data.get("onvif_serial")
        fp.confidence = max(fp.confidence, 0.99)
        fp.evidence.append("onvif:device_info")

    # ---------- 2. MAC OUI ----------
    mac = (data.get("mac_address") or "").upper()
    if mac:
        oui = ":".join(mac.split(":")[:3])
        for brand, sig in SIGNATURES["manufacturers"].items():
            if oui in [o.upper() for o in sig.get("mac_oui", [])]:
                if not fp.manufacturer:
                    fp.manufacturer = _brand_display(brand, sig)
                fp.confidence = max(fp.confidence, 0.95)
                fp.evidence.append(f"mac_oui:{oui}->{_brand_display(brand, sig)}")
                break

    # ---------- 3. HTTP Server ----------
    server = (data.get("http_server") or "").lower()
    for brand, sig in SIGNATURES["manufacturers"].items():
        for marker in sig.get("http_server", []):
            if _marker_in(marker, server):
                if not fp.manufacturer:
                    fp.manufacturer = _brand_display(brand, sig)
                fp.confidence = max(fp.confidence, 0.80)
                fp.evidence.append(f"http_server:{_marker_label(marker)}")
                break

    # ---------- 3b. RTSP Server (same semantics as HTTP Server) ----------
    rtsp_server = (data.get("rtsp_server") or "").lower()
    for brand, sig in SIGNATURES["manufacturers"].items():
        for marker in sig.get("rtsp_server", []):
            if _marker_in(marker, rtsp_server):
                if not fp.manufacturer:
                    fp.manufacturer = _brand_display(brand, sig)
                fp.confidence = max(fp.confidence, 0.80)
                fp.evidence.append(f"rtsp_server:{_marker_label(marker)}")
                break

    # ---------- 4. WWW-Authenticate realm ----------
    auth = (data.get("http_www_authenticate") or "")
    for brand, sig in SIGNATURES["manufacturers"].items():
        for marker in sig.get("www_auth_realm", []):
            if _marker_in(marker, auth.lower()):
                if not fp.manufacturer:
                    fp.manufacturer = _brand_display(brand, sig)
                fp.confidence = max(fp.confidence, 0.90)
                fp.evidence.append(f"www_auth_realm:{_marker_label(marker)}")
                break

    # ---------- 5. Favicon hash ----------
    favicon = data.get("http_favicon_md5")
    if favicon:
        for brand, sig in SIGNATURES["manufacturers"].items():
            if favicon in sig.get("favicon_md5", []):
                if not fp.manufacturer:
                    fp.manufacturer = _brand_display(brand, sig)
                fp.confidence = max(fp.confidence, 0.90)
                fp.evidence.append(f"favicon:{favicon[:8]}")
                break

    # ---------- 5b. Favicon hash on non-standard paths ----------
    fav_paths = data.get("http_favicon_paths") or {}
    if fav_paths:
        for brand, sig in SIGNATURES["manufacturers"].items():
            matched = False
            for path, md5s in (sig.get("favicon_paths") or {}).items():
                got = fav_paths.get(path)
                if got and got in md5s:
                    if not fp.manufacturer:
                        fp.manufacturer = _brand_display(brand, sig)
                    fp.confidence = max(fp.confidence, 0.90)
                    fp.evidence.append(f"favicon_path:{path}:{got[:8]}")
                    matched = True
                    break
            if matched:
                break

    # ---------- 6. HTML markers ----------
    html = (data.get("http_html_content") or "")
    html_lower = html.lower()
    for brand, sig in SIGNATURES["manufacturers"].items():
        for marker in sig.get("html_markers", []):
            if _marker_in(marker, html_lower):
                if not fp.manufacturer:
                    fp.manufacturer = _brand_display(brand, sig)
                fp.confidence = max(fp.confidence, 0.75)
                fp.evidence.append(f"html:{_marker_label(marker)[:40]}")
                break

    # ---------- 7. Model extraction ----------
    if not fp.model:
        if fp.manufacturer:
            brand_key = _brand_key(fp.manufacturer)
            candidates = [(brand_key, SIGNATURES["manufacturers"].get(brand_key, {}))]
        else:
            # No manufacturer yet: try every brand's model_regex and infer the brand from a hit.
            candidates = list(SIGNATURES["manufacturers"].items())
        for brand, sig in candidates:
            matched = False
            for pattern in sig.get("model_regex", []):
                m = re.search(pattern, html) or re.search(pattern, auth) or re.search(pattern, server, re.I)
                if m:
                    fp.model = m.group(1).upper()
                    if not fp.manufacturer:
                        fp.manufacturer = _brand_display(brand, sig)
                    fp.confidence = min(fp.confidence + 0.05, 1.0)
                    fp.evidence.append(f"model_regex:{pattern}")
                    matched = True
                    break
            if matched:
                break

    # ---------- 8. Firmware version ----------
    if not fp.firmware_version:
        fp.firmware_version = _extract_firmware(html, server, auth)
        if fp.firmware_version:
            fp.evidence.append("firmware:regex")

    # ---------- 9. Финальная проверка ----------
    if not (fp.manufacturer or fp.model or fp.firmware_version):
        return None
    return fp.to_dict()


# ---------- helpers ----------

def _brand_key(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _normalize_brand(name: str) -> str:
    key = _brand_key(name)
    for brand, sig in SIGNATURES["manufacturers"].items():
        if key == _brand_key(brand):
            return _brand_display(brand, sig)
        for alias in sig.get("names", []):
            if key == _brand_key(alias):
                return _brand_display(brand, sig)
    return name.strip()


def _brand_display(key: str, sig: Dict[str, Any]) -> str:
    names = sig.get("names") or [key]
    return names[0]


def _extract_firmware(html: str, server: str, auth: str) -> Optional[str]:
    text = f"{server}\n{auth}\n{html}"
    patterns = [
        r"V\d+\.\d+\.\d+(?:\s+build\s+\d+)?",
        r"Firmware[:\s]+V?[\d\.]+",
        r"fw_ver[:\s]+[\d\.]+",
        r"Build\s+\d{6,}",
    ]
    for p in patterns:
        m = re.search(p, text, re.I)
        if m:
            return m.group(0).strip()
    return None


def extra_favicon_paths() -> List[str]:
    """Non-standard favicon/image paths referenced by any signature's
    `favicon_paths`. The scanner fetches these so path-specific favicon hashes
    can be matched. `/favicon.ico` is collected separately by the HTTP probe."""
    paths = set()
    for sig in SIGNATURES["manufacturers"].values():
        for path in (sig.get("favicon_paths") or {}):
            paths.add(path)
    return sorted(paths)


def favicon_hash(raw_bytes: bytes) -> str:
    """MD5 от содержимого favicon.ico — используется как сигнатура."""
    return hashlib.md5(raw_bytes).hexdigest()