"""
Build ready-to-run capture commands (ffmpeg / curl) for discovered camera URLs.

These helpers ONLY build command strings / argument lists. They never execute
anything and never touch the network — the caller runs the returned command.

Typical use:

    from camera_scanner.capture import capture_command
    cmd = capture_command(url, output="snap.jpg", user="admin", password="secret")
    # -> "ffmpeg -y -rtsp_transport tcp -i 'rtsp://admin:secret@host/...' -frames:v 1 snap.jpg"
"""

import shlex
from urllib.parse import quote
from typing import List, Optional


def _inject_rtsp_credentials(url: str, user: str, password: str) -> str:
    """Insert user:pass@ into an rtsp:// URL if credentials are given and none
    are already embedded. Credentials are URL-encoded."""
    if not (user or password) or "://" not in url:
        return url
    scheme, rest = url.split("://", 1)
    authority = rest.split("/", 1)[0]
    if "@" in authority:
        return url  # credentials already present
    cred = f"{quote(user, safe='')}:{quote(password, safe='')}@"
    return f"{scheme}://{cred}{rest}"


def ffmpeg_snapshot(url: str, output: str = "snapshot.jpg", user: str = "",
                    password: str = "", rtsp_transport: str = "tcp") -> List[str]:
    """ffmpeg argument list to grab a single still frame from `url`."""
    args = ["ffmpeg", "-y"]
    if url.startswith("rtsp://"):
        url = _inject_rtsp_credentials(url, user, password)
        if rtsp_transport:
            args += ["-rtsp_transport", rtsp_transport]
    args += ["-i", url, "-frames:v", "1", output]
    return args


def ffmpeg_record(url: str, output: str = "clip.mp4", seconds: int = 10, user: str = "",
                  password: str = "", rtsp_transport: str = "tcp") -> List[str]:
    """ffmpeg argument list to record `seconds` of the stream (stream copy)."""
    args = ["ffmpeg", "-y"]
    if url.startswith("rtsp://"):
        url = _inject_rtsp_credentials(url, user, password)
        if rtsp_transport:
            args += ["-rtsp_transport", rtsp_transport]
    args += ["-i", url, "-t", str(int(seconds)), "-c", "copy", output]
    return args


def curl_snapshot(url: str, output: str = "snapshot.jpg", user: str = "",
                  password: str = "", digest: bool = True) -> List[str]:
    """curl argument list for an HTTP(S) snapshot endpoint.

    Uses HTTP Digest auth by default (Dahua/Hikvision snapshot CGIs expect it).
    `-k` is included so self-signed HTTPS cameras work.
    """
    args = ["curl", "-sS", "-k"]
    if user or password:
        if digest:
            args.append("--digest")
        args += ["-u", f"{user}:{password}"]
    args += [url, "-o", output]
    return args


def as_shell(args: List[str]) -> str:
    """Render an argument list as a copy-pasteable, properly quoted shell command."""
    return " ".join(shlex.quote(a) for a in args)


def capture_command(url: str, output: Optional[str] = None, user: str = "",
                    password: str = "", prefer: str = "auto") -> str:
    """Pick a sensible capture command for `url` and return it as a shell string.

    - rtsp://           -> ffmpeg single frame
    - http(s) snapshot  -> curl (handles HTTP Digest auth cleanly)

    `prefer` may be "auto" (default), "ffmpeg", or "curl" to force a tool.
    """
    is_rtsp = url.startswith("rtsp://")
    if output is None:
        output = "snapshot.jpg"
    if prefer not in ("auto", "ffmpeg", "curl"):
        raise ValueError("prefer must be 'auto', 'ffmpeg', or 'curl'")
    if prefer == "ffmpeg" or (prefer == "auto" and is_rtsp):
        return as_shell(ffmpeg_snapshot(url, output, user, password))
    return as_shell(curl_snapshot(url, output, user, password))
