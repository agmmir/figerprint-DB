# camera_scanner

Async Python library and CLI that identifies IP cameras on a network and resolves working URLs for video streams, snapshots and OSD control.

Give it an IP address (and optional credentials). It detects open camera ports, works out the **manufacturer / model / firmware / serial**, and returns ready-to-use integration links.

It is aimed at sysadmins and developers who auto-discover cameras and wire them into video-surveillance systems. Use it only on networks and devices you are authorized to scan.

- **Async**: built on `asyncio` / `aiohttp`.
- **Rule-based, no ML**: logic lives in Python, knowledge lives in YAML (`camera_scanner/db/`).
- **Honest results**: every detection carries a confidence score and an evidence trail. If the device could not be reached, the scanner says so instead of guessing.

## Install

```bash
git clone https://github.com/agmmir/figerprint-DB.git
cd figerprint-DB
python3 -m venv camera_scanner/venv
camera_scanner/venv/bin/pip install -r camera_scanner/requirements.txt
```

Dependencies: `aiohttp>=3.11`, `pydantic>=2`, `PyYAML`, `mmh3>=4`, plus `pytest` / `pytest-asyncio` for tests. If `mmh3` is missing, favicon MMH3 matching is skipped and the scan still works.

## Usage

### CLI

Run from the repository root:

```bash
python -m camera_scanner.scanner 192.168.1.64 \
    --timeout 10 --semaphore 50 --concurrency 10 \
    --user admin --password 'secret'
```

Add `--json` for raw JSON output. Illustrative report (values are examples):

```
=== Scan result: 192.168.1.64 ===
  Network      : ok
  Manufacturer : Hikvision
  Model        : DS-2CD2143G0-I
  Firmware     : V5.5.82
  Confidence   : 0.99
  Open ports   : 80, 554, 8000
  Evidence     : onvif:manufacturer, http_server:hikvision
  Stream URLs (2):
    - rtsp://192.168.1.64/Streaming/Channels/101
    ...
```

### Library

```python
import asyncio
from camera_scanner.scanner import CameraScanner

async def main():
    scanner = CameraScanner(user="admin", password="secret", url_test_concurrency=10)
    info = await scanner.scan("192.168.1.64")
    print(info.manufacturer, info.model, info.confidence)
    print(info.stream_urls, info.snapshot_urls)

asyncio.run(main())
```

To get candidate URL patterns without scanning:

```python
scanner.resolve_urls(manufacturer="hikvision", ip="192.168.1.64", user="admin", password="secret")
```

`capture.py` builds (does not run) `ffmpeg` / `curl` command lines for snapshots and recording from a resolved URL.

## How it works

`CameraScanner.scan()` is a staged pipeline. Each stage only fills fields that a more trusted earlier stage left empty.

1. **Port check**: 80, 443, 554, 8000, 8080, 34567, 37777, 37778.
2. **HTTP probe**: `Server` header, `WWW-Authenticate`, HTML, favicon MD5 and MMH3.
3. **RTSP probe**: `OPTIONS` banner.
4. **Data gathering**: SSL certificate issuer/subject, ISAPI (Hikvision hint), ONVIF WS-Discovery.
5. **Fingerprinting**: multi-signal scoring against `db/signatures.yaml`. With credentials, Hikvision (ISAPI) and Dahua (magicBox CGI) can fill model, firmware and serial.
6. **URL resolution**: patterns picked by chipset, then manufacturer, then `generic`, and verified live (HTTP status, RTSP `DESCRIBE` with Digest/Basic auth).

Signal confidence (strongest single signal wins): ONVIF 0.99, MAC OUI 0.95, SSL issuer 0.95, WWW-Authenticate realm 0.90, favicon hashes 0.90, SSL subject 0.90, HTTP/RTSP server header 0.80, HTML markers 0.75.

### Network status

Each probe reports whether it reached the device. `network_status` on the result is one of:

| Value | Meaning |
|---|---|
| `ok` | at least one probe got a real answer |
| `partial` | the host answered at the transport level (refused / empty) but nothing useful came back |
| `unreachable` | no probe reached the host |
| `unknown` | status not determined |

The weak Dahua guess from open port 37777/37778 (confidence 0.40) runs only when `network_status` is `ok` or `partial`, and never overrides a stronger signal.

## Knowledge base

- `camera_scanner/db/signatures.yaml`: brand fingerprints (names, server headers, realms, HTML markers, model regexes, MAC OUIs, favicon MD5/MMH3, SSL markers). Rules carry `# source:` provenance comments.
- `camera_scanner/db/<brand>.yaml`: URL patterns, one brand per file.
- `camera_scanner/db/_generic.yaml`: shared generic patterns, including common RTSP routes.

Adding a camera brand needs no code change: add verified rules to `signatures.yaml` and a `db/<brand>.yaml` file, then add a positive test and, for any short or ambiguous marker, a negative test.

## Tests

```bash
camera_scanner/venv/bin/python -m pytest camera_scanner/tests/ -q
```

Tests mock all network and subprocess I/O and never touch real hosts.

## Project layout

```
camera_scanner/
  scanner.py        pipeline, URL testing, CLI
  fingerprinter.py  rule-based matcher
  models.py         CameraInfo (Pydantic v2)
  capture.py        ffmpeg / curl command builders
  probes/           http, rtsp, onvif, isapi, dahua, ssl_cert
  db/               signatures and URL patterns (YAML)
  tests/
vendor/             read-only third-party source material
```

`vendor/` holds upstream reference data (WhatWeb, Cameradar, Nuclei templates, BishopFox/Favicons). It is read-only source material, not a runtime dependency.
