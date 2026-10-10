# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`camera_scanner` is a Python library for automatically identifying IP cameras on a network and resolving working URLs for video stream, snapshots, and OSD control. Given an IP (and optional credentials), it detects open camera ports, identifies the manufacturer / model / firmware / serial, and returns ready-to-use integration links. It targets sysadmins and developers who auto-discover cameras and wire them into video-surveillance systems; public/authorized targets are in scope (no separate public/private mode).

It is **async** (built on `aiohttp`/`asyncio`), and all identification is **rule-based and data-driven** — no ML. Logic lives in Python; knowledge lives in YAML under `camera_scanner/db/`.

## Commands

`camera_scanner` is a Python package; run everything from the repo root (`GAMA_recognizer/`) so imports resolve as `camera_scanner.*`. Use the project venv (`camera_scanner/venv/`) — bare `python`/`python3` on this machine lack the deps.

```bash
# Install deps
pip install -r camera_scanner/requirements.txt          # aiohttp>=3.11, pydantic>=2, PyYAML, pytest, pytest-asyncio

# Run tests (from repo root)
camera_scanner/venv/bin/python -m pytest camera_scanner/tests/ -q

# Single test
camera_scanner/venv/bin/python -m pytest camera_scanner/tests/test_fingerprinter.py::test_hikvision_by_onvif

# Scan an IP (also runnable as `python scanner.py <ip>` from inside camera_scanner/)
python -m camera_scanner.scanner <ip> --timeout 10 --semaphore 50 \
    --concurrency 10 --user <USER> --password '<PASS>' --json
```

Tests are `pytest` + `pytest-asyncio` (async tests marked `@pytest.mark.asyncio`) and **mock all network/subprocess I/O** — they never hit real hosts. Not a git repo: `git diff`/`status` are unavailable here; verify changes by reading files.

`scanner.py` supports **dual execution** (package `-m` or direct `python scanner.py`): top-level imports use a `try: from .x … except ImportError: from x …` fallback; keep that pattern.

## Architecture

Staged pipeline in `CameraScanner.scan(ip, user=None, password=None)` (`scanner.py`); each stage only fills fields an earlier, more-trusted stage left empty. Credentials come from the constructor (`CameraScanner(user=, password=, url_test_concurrency=10)`) or `scan()` args (explicit args win).

1. **Port check** → `_check_ports()` over `common_ports` (80, 443, 554, 8000, 8080, 34567).
2. **HTTP probe** (`probes/http.py`): Server header, WWW-Authenticate, HTML, favicon MD5.
3. **RTSP probe** (`probes/rtsp.py`): OPTIONS banner, exposes `rtsp_server`.
4. **Fingerprint-data gather** → `_gather_fingerprint_data()`; conditionally runs `probes/isapi.py` (HTTP hints Hikvision) and `probes/onvif.py` (WS-Discovery).
5. **Fingerprinting** → `fingerprint_camera()` resolves manufacturer/model/firmware + confidence/evidence.
   - **5b**: with credentials + manufacturer Hikvision → `isapi_device_info()` (Digest auth) fills model/firmware/serial.
6. **URL resolution**: lookup key is **chipset → manufacturer → `generic`**; `_get_url_patterns()` selects patterns, `_test_url_patterns()` verifies them live.

**Trust ordering is central** — ONVIF first, weaker signals only fill gaps; never let a weaker signal overwrite a stronger one. Probes are imported **lazily inside methods** (optional/conditional) — preserve that; the exception is `check_http_endpoint`, imported at module top so tests can patch `camera_scanner.scanner.check_http_endpoint`.

### Credentials, URL testing & RTSP auth

- `_format_url(pattern, ip, user, password)` substitutes `{ip}` and URL-encodes `{user}`/`{pass}` via `urllib.parse.quote(safe='')` (empty when absent); collapses duplicate slashes. Never double-encode.
- `_test_url_patterns()` tests candidates **concurrently**, bounded by `asyncio.Semaphore(url_test_concurrency)` (per single target — no multi-IP concurrency), using a `lock` for result mutations. Per-URL timeout is `min(self.timeout, 3)`; `self.timeout` stays for port scans. Classification: HTTP `2xx` → bucket; `401/403` → `requires_auth_urls`; failures ignored. **Stream early-exit**: stop starting new stream checks once 2 working stream URLs are found (re-checked after acquiring the semaphore; in-flight checks finish, never cancelled). Don't change these without a regression test.
- `check_http_endpoint()` returns the HTTP **status code** (`Optional[int]`), accepts creds (aiohttp `DigestAuthMiddleware`), and takes a full URL or path.
- `_check_rtsp_url()` → `rtsp_check_stream()` verifies via RTSP DESCRIBE with Digest/Basic auth, returning verdicts `RTSP_OK` / `RTSP_AUTH_REQUIRED` / `RTSP_UNREACHABLE` (constants in `probes/rtsp.py`). Raw creds are used for the auth header; credential-bearing URLs are never logged.

### Fingerprinting (`fingerprinter.py`)

Rule-based multi-signal scoring against **`db/signatures.yaml`**, which has three top-level sections: `manufacturers` (the only one the engine iterates), plus `engines` and `chipsets` (reference data, **not** read by the matcher). Per-brand fields the matcher evaluates: `names`, `http_server`, `rtsp_server`, `www_auth_realm`, `html_markers`, `model_regex`, `mac_oui`, `favicon_md5`, `favicon_paths`. Matching is **case-insensitive substring** for header/HTML markers — avoid short/generic markers (a bare 3-char `rvi` matched "se**rvi**ce"; such markers were removed). Confidence uses **`max()`** aggregation (strongest single signal) — do **not** reintroduce noisy-OR. Returns `None` when nothing matches.

- Model extraction: if manufacturer known, uses that brand's `model_regex`; else scans all brands. Note `_brand_key()` strips non-alphanumerics, so hyphenated keys (e.g. `d-link`) are **not** reachable via the manufacturer path — model_regex there won't fire.
- No fake data ever: `favicon_md5`/`mac_oui` are left empty unless a real hash/OUI is verified. Signatures carry `# source: …` provenance comments (WhatWeb / Nuclei / Shodan observations) under `vendor/`.

### URL pattern database (`db/`)

- **One brand per file**, filename = lowercase brand (`hikvision.yaml`, …). A file may hold just `<brand>: {}` (brand known, no models yet).
- `_generic.yaml` holds the shared generic patterns (incl. the Cameradar-derived RTSP route candidates) and is the **canonical** generic source. The legacy monolith `db/url_patterns.yaml` was **deleted** (fully redundant); only `db/url_patterns.yaml.bak` remains — do not reload or restore it.
- `scanner._load_url_patterns()` loads **every `*.yaml`/`*.yml`** in `db/` via `os.listdir` (order **not** sorted/guaranteed) and merges by brand with `dict.update()` (overlapping pattern keys are replaced, not merged). `.bak` is excluded by extension. Adding a brand = adding a file; no code change.
- `_get_url_patterns(key, model)`: exact model → **longest-prefix** match (upper-cased, spaces stripped, `_`-keys skipped) → explicit `default:` sub-dict → brand-level categories (works even when `model` is `None`). Use a `default:` block for chipset/brand-wide patterns and prefix keys (e.g. `DS-2CD`) for many-model brands.
- Placeholders: `{ip}`, `{user}`, `{pass}` (some legacy entries also contain `[USERNAME]`/`[PASSWORD]`/`[CHANNEL]`). Categories: `snapshot`, `stream`, `overlay`; per-model entries also use `ptz`, `other`.

### Models (`models.py`) & capture (`capture.py`)

`CameraInfo` (Pydantic v2, `model_config = ConfigDict(extra="allow")`) is the single result object threaded through `scan()`. Fields include `chipset`, `confidence`, `evidence`, `serial_number`, `requires_auth_urls` alongside manufacturer/model/urls/ports/protocols. **`chipset` is currently never set** by the pipeline (the port-34567→Xiongmai heuristic was removed as unsupported; 34567 is a shared DVRIP port), so chipset-first URL selection stays dormant until trustworthy chipset evidence is wired in.

`capture.py` builds (does not run) `ffmpeg`/`curl` command argv for snapshots/recording (`ffmpeg_snapshot`, `ffmpeg_record`, `curl_snapshot`, `capture_command`), injecting URL-encoded RTSP creds without double-injection.

## Conventions

- Code, identifiers, filenames, commands: English. Many comments and reports are in Russian — match the surrounding file.
- `_archive/` = one-off migration scripts (not runtime). `testing/` = ad-hoc import staging; brand YAMLs dropped in `testing/db/` are normalized and moved into `db/` (one brand per file). `vendor/` (WhatWeb, cameradar, nuclei-templates) is **read-only source material** — never modify or add as a runtime dependency.
- Adding a camera: add verified rules to `db/signatures.yaml` **and** a `db/<brand>.yaml`; add a focused positive test, plus a negative test for any short/ambiguous marker. Prefer removing an unsafe marker over inventing a speculative one.
