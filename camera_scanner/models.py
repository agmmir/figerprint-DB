from pydantic import BaseModel, ConfigDict, HttpUrl
from typing import List, Optional


class CameraInfo(BaseModel):
    """Information about a discovered IP camera."""
    ip: str
    manufacturer: Optional[str] = None
    # Underlying firmware/hardware family (e.g. "Xiongmai"), independent of manufacturer
    chipset: Optional[str] = None
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    serial_number: Optional[str] = None
    # Aggregated detection confidence and human-readable evidence trail
    confidence: float = 0.0
    evidence: List[str] = []
    snapshot_urls: List[str] = []
    stream_urls: List[str] = []
    osd_urls: List[str] = []
    # Endpoints that exist but returned 401/403 (need credentials to access)
    requires_auth_urls: List[str] = []
    open_ports: List[int] = []
    protocols: List[str] = []

    # Allow extra fields for flexibility
    model_config = ConfigDict(extra="allow")