# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`camera_scanner` is a Python library for automatically identifying IP cameras on a network and resolving working URLs for video stream, snapshots, and OSD control. Given an IP (and optional credentials), it detects open camera ports, identifies the manufacturer / model / firmware / serial, and returns ready-to-use integration links. It targets sysadmins and developers who auto-discover cameras and wire them into video-surveillance systems; public/authorized targets are in scope (no separate public/private mode).

It is **async** (built on `aiohttp`/`asyncio`), and all identification is **rule-based and data-driven** — no ML. Logic lives in Python; knowledge lives in YAML under `camera_scanner/db/`.

## Commands

`camera_scanner` is a Python package; run everything from the repo root (`GAMA_recognizer/`) so imports resolve as `camera_scanner.*`. Use the project venv (`camera_scanner/venv/`) — bare `python`/`python3` on this machine lack the deps.

```bash
# Install deps
pip install -r camera_scanner/requirements.txt    # aiohttp>=3.11, pydantic>=2, PyYAML, pytest, pytest-asyncio, mmh3>=4

# Run tests (from repo root)
camera_scanner/venv/bin/python -m pytest camera_scanner/tests/ -q

# Single test
camera_scanner/venv/bin/python -m pytest camera_scanner/tests/test_fingerprinter.py::test_hikvision_by_onvif

# Scan an IP (also runnable as `python scanner.py <ip>` from inside camera_scanner/)
python -m camera_scanner.scanner <ip> --timeout 10 --semaphore 50 \
    --concurrency 10 --user <USER> --password '<PASS>' --json
```

Tests are `pytest` + `pytest-asyncio` (async tests marked `@pytest.mark.asyncio`) and **mock all network/subprocess I/O** — they never hit real hosts. The repo is a git repository, but keep changes verifiable by reading files too. `mmh3` is a real dependency now (Shodan-style favicon hashing); it is imported lazily/defensively so a missing `mmh3` degrades gracefully rather than breaking the scan.

`scanner.py` supports **dual execution** (package `-m` or direct `python scanner.py`): top-level imports use a `try: from .x … except ImportError: from x …` fallback; keep that pattern.

## Architecture

Staged pipeline in `CameraScanner.scan(ip, user=None, password=None)` (`scanner.py`); each stage only fills fields an earlier, more-trusted stage left empty. Credentials come from the constructor (`CameraScanner(user=, password=, url_test_concurrency=10)`) or `scan()` args (explicit args win).

1. **Port check** → `_check_ports()` over `common_ports` (28 deduplicated TCP candidates: web alternates 80-85/88/443/8443, RTSP 554/8554/10554, Hikvision 8000/8001/8081/9000/9010, Dahua 37777/37778/50000, 34567, 8080/8088/8090/5000, legacy 21/22/23), run **concurrently** under the scanner semaphore with a per-port timeout of `min(self.timeout, 3)`. Note: only TCP connect is used and the HTTP probe still targets 80/443 only. `scan()` first runs `_is_tcp_proxied()` (connect to a random high port on TEST-NET-1 192.0.2.1; success = VPN/proxy intercepting TCP). If proxied: `result.tcp_proxied=True`, evidence `port_scan: unreliable (tcp proxy detected)`, `open_ports` kept for information only, no port-derived protocols, no port-37777 fallback. Tests stub the detector via `tests/conftest.py` (only `test_proxy_detect.py` exercises the real one). 37777 (Dahua TCP/DHIP) and 37778 (Dahua UDP SDK) are Dahua-SDK defaults.
2. **HTTP probe** (`probes/http.py`): Server header, WWW-Authenticate, HTML (first 2 KB), favicon **MD5** and favicon **MMH3** (Shodan hash), plus favicon-by-path hashes for signature-specified non-standard paths. Favicon requests are issued **after the root response context closes** (many cameras send `Connection: close`, which aborts a follow-up request made while the first response is still open).
3. **RTSP probe** (`probes/rtsp.py`): OPTIONS banner, exposes `rtsp_server`.
4. **Fingerprint-data gather** → `_gather_fingerprint_data()`; merges probe output, pulls the **SSL certificate** issuer/subject via `probes/ssl_cert.py` when **443** is open, and conditionally runs `probes/isapi.py` (HTTP hints Hikvision) and `probes/onvif.py` (WS-Discovery).
5. **Fingerprinting** → `fingerprint_camera()` resolves manufacturer/model/firmware and **propagates confidence + evidence (+ serial)** into `CameraInfo`.
   - **5b (authenticated device info, creds + brand gated):** Hikvision → `isapi_device_info()` (Digest); Dahua → `dahua_firmware_version()` (`probes/dahua.py`, magicBox CGI, Basic→Digest fallback) fills model/firmware/serial.
   - **Dahua SDK-port fallback:** if 37777/37778 is open, **no manufacturer was identified**, **and `network_status` is `ok`/`partial`** (the device was actually reached), set `manufacturer="Dahua"` at low confidence **0.40** with evidence `open_port:<n>->dahua-guess` (weak, last-resort; OEM clones reusing the Dahua SDK may be mislabeled — kept intentionally, see note below).
6. **URL resolution**: lookup key is **chipset → manufacturer → `generic`**; `_get_url_patterns()` selects patterns, `_test_url_patterns()` verifies them live.

**Trust ordering is central** — ONVIF first, weaker signals only fill gaps; never let a weaker signal overwrite a stronger one. Probes are imported **lazily inside methods** (optional/conditional) — preserve that; the exception is `check_http_endpoint`, imported at module top so tests can patch `camera_scanner.scanner.check_http_endpoint`.

### Public helpers & CLI output

- `CameraScanner.resolve_urls(manufacturer=None, model=None, chipset=None, ip=None, user="", password="")` returns candidate URL patterns **without scanning** (same chipset→manufacturer→generic priority). With `ip` it fills `{ip}/{user}/{pass}`; without `ip` it returns raw templates.
- `format_result(CameraInfo) -> str` renders a readable sectioned CLI report; the CLI prints it by default and emits raw JSON with `--json`.

### Credentials, URL testing & RTSP auth

- `_format_url(pattern, ip, user, password)` substitutes `{ip}` and URL-encodes `{user}`/`{pass}` via `urllib.parse.quote(safe='')` (empty when absent); collapses duplicate slashes. Never double-encode.
- `_test_url_patterns()` tests candidates **concurrently**, bounded by `asyncio.Semaphore(url_test_concurrency)` (per single target — no multi-IP concurrency), using a `lock` for result mutations. Per-URL timeout is `min(self.timeout, 3)`; `self.timeout` stays for port scans. Classification: HTTP `2xx` → bucket; `401/403` → `requires_auth_urls`; failures ignored. **Stream early-exit**: stop starting new stream checks once 2 working stream URLs are found (re-checked after acquiring the semaphore; in-flight checks finish, never cancelled). Don't change these without a regression test.
- `check_http_endpoint()` returns the HTTP **status code** (`Optional[int]`), accepts creds (aiohttp `DigestAuthMiddleware`), and takes a full URL or path.
- `_check_rtsp_url()` → `rtsp_check_stream()` verifies via RTSP DESCRIBE with Digest/Basic auth, returning verdicts `RTSP_OK` / `RTSP_AUTH_REQUIRED` / `RTSP_UNREACHABLE` (constants in `probes/rtsp.py`). Raw creds build the auth header; credential-bearing URLs are never logged. When a 401 offers **both** `Digest` and `Basic`, `_prefer_digest()` picks Digest (some Dahua reject Basic for RTSP).

### SSL certificate probe (`probes/ssl_cert.py`)

Reads the peer cert DN as a stable brand signal. Verification is intentionally **off** (`CERT_NONE`, `check_hostname=False`) — cameras are self-signed and we only read the DN. Two subtleties, both load-bearing:
- Under `CERT_NONE`, `ssl.getpeercert()` returns `{}`, so the probe parses the **DER** form (`getpeercert(binary_form=True)`) via the stdlib decoder `_ssl._test_decode_cert` on a temp PEM. Without this the probe returns nothing on real cameras.
- Handshake uses **modern-then-legacy fallback**: `_modern_context()` (keeps TLS 1.3-capable cameras working) then `_legacy_context()` (`PROTOCOL_TLS_CLIENT`, `min=TLSv1`, `max=TLSv1_2`, `set_ciphers("DEFAULT:@SECLEVEL=0")`, `OP_LEGACY_SERVER_CONNECT`) for old cameras that advertise but break TLS 1.3. Stdlib only. Expect a benign `DeprecationWarning` for TLSv1.

### Fingerprinting (`fingerprinter.py`)

Rule-based multi-signal scoring against **`db/signatures.yaml`**, which has three top-level sections: `manufacturers` (the only one the engine iterates — currently 34 brands) plus `engines` and `chipsets` (reference data, **not** read by the matcher). Per-brand fields the matcher evaluates: `names`, `http_server`, `rtsp_server`, `www_auth_realm`, `html_markers`, `model_regex`, `mac_oui`, `favicon_md5`, `favicon_paths`, `favicon_mmh3`, `ssl_issuer`, `ssl_subject`.

- Matching is **case-insensitive substring** for header/HTML/SSL markers — avoid short/generic markers (a bare 3-char `rvi` matched "se**rvi**ce"; such markers were removed). A marker may be a **list → AND** (all parts must be present), handled by `_marker_in()`/`_marker_label()` (evidence `field:a&&b`).
- Signal confidence (via `max()` aggregation — do **not** reintroduce noisy-OR): ONVIF 0.99 · MAC OUI 0.95 · `ssl_issuer` 0.95 · `www_auth_realm` 0.90 · `favicon_md5`/`favicon_paths`/`favicon_mmh3` 0.90 · `ssl_subject` 0.90 · `http_server`/`rtsp_server` 0.80 · `html_markers` 0.75; `model_regex` adds +0.05. Returns `None` when nothing matches.
- Favicon hashing lives here: `favicon_hash()` (MD5) and `favicon_mmh3_hash()` = `mmh3.hash(base64.encodebytes(bytes))`, **signed** 32-bit (Shodan / FingerprintHub convention — base64 **with** newlines, not `b64encode`; returns `None` if mmh3 is missing). `http.py` reuses `favicon_mmh3_hash` so probe and signatures stay consistent.
- Model extraction: if manufacturer known, uses that brand's `model_regex`; else scans all brands. Note `_brand_key()` strips non-alphanumerics, so hyphenated keys (e.g. `d-link`) are **not** reachable via the manufacturer path — model_regex there won't fire.
- No fake data ever: `favicon_md5`/`favicon_mmh3`/`mac_oui`/`ssl_*` are left empty unless a real, verified value exists. Signatures carry `# source: …` provenance comments (WhatWeb / Nuclei / Shodan / FingerprintHub / Ingram observations) from `vendor/`.

### URL pattern database (`db/`)

- **One brand per file**, filename = lowercase brand (`hikvision.yaml`, …). A file may hold just `<brand>: {}` (brand known, no models yet).
- `_generic.yaml` holds the shared generic patterns (incl. the Cameradar-derived RTSP route candidates) and is the **canonical** generic source. The legacy monolith `db/url_patterns.yaml` was **deleted** (fully redundant); only `db/url_patterns.yaml.bak` remains — do not reload or restore it. Snapshot backups like `signatures.yaml.old_snapshot` / `*.pre_fingerprinthub_merge.bak` are backups — do not load or commit them.
- `scanner._load_url_patterns()` loads **every `*.yaml`/`*.yml`** in `db/` via `os.listdir` (order **not** sorted/guaranteed) and merges by brand with `dict.update()` (overlapping pattern keys are replaced, not merged). `.bak` is excluded by extension. Adding a brand = adding a file; no code change.
- `_get_url_patterns(key, model)`: exact model → **longest-prefix** match (upper-cased, spaces stripped, `_`-keys skipped) → explicit `default:` sub-dict → brand-level categories (works even when `model` is `None`). Use a `default:` block for chipset/brand-wide patterns and prefix keys (e.g. `DS-2CD`) for many-model brands.
- Placeholders: `{ip}`, `{user}`, `{pass}` (some legacy entries also contain `[USERNAME]`/`[PASSWORD]`/`[CHANNEL]`). Categories: `snapshot`, `stream`, `overlay`; per-model entries also use `ptz`, `other`.

### Models (`models.py`) & capture (`capture.py`)

`CameraInfo` (Pydantic v2, `model_config = ConfigDict(extra="allow")`) is the single result object threaded through `scan()`. Fields include `chipset`, `confidence`, `evidence`, `serial_number`, `requires_auth_urls` alongside manufacturer/model/urls/ports/protocols. **`chipset` is never set** by the pipeline (the port-34567→Xiongmai heuristic was removed as unsupported; 34567 is a shared DVRIP port), so chipset-first URL selection stays dormant until trustworthy chipset evidence is wired in. The Dahua SDK-port fallback sets **`manufacturer`**, not `chipset`.

`capture.py` builds (does not run) `ffmpeg`/`curl` command argv for snapshots/recording (`ffmpeg_snapshot`, `ffmpeg_record`, `curl_snapshot`, `capture_command`), injecting URL-encoded RTSP creds without double-injection.

## FingerprintHub import (`scripts/import_fingerprinthub.py`)

Extracts fingerprints from FingerprintHub under `vendor/` into `scripts/imported/`. It imports MD5 favicon hashes and HTML/header markers but **skips MMH3/integer favicon hashes** (recorded as "incompatible" in its report). The runtime engine *does* match `favicon_mmh3` now, and a couple of brands carry verified MMH3 values (Dahua, Hikvision) — but the bulk import of FingerprintHub MMH3 values is intentionally **not** wired in (most are web products, not cameras; would need a relevance filter). Enable that as a separate, reviewed step.

## Conventions

- Code, identifiers, filenames, commands: English. Many comments and reports are in Russian — match the surrounding file.
- `_archive/` = one-off migration scripts (not runtime). `testing/` = ad-hoc import staging; brand YAMLs dropped in `testing/db/` are normalized and moved into `db/` (one brand per file). `vendor/` (WhatWeb, cameradar, nuclei-templates, FingerprintHub, Ingram) is **read-only source material** — never modify or add as a runtime dependency; it includes attack tooling, from which only identification signatures / benign media paths are ever taken (never exploitation, password-guessing or backdoor logic).
- Adding a camera: add verified rules to `db/signatures.yaml` **and** a `db/<brand>.yaml`; add a focused positive test, plus a negative test for any short/ambiguous marker. Prefer removing an unsafe marker over inventing a speculative one. Prefer a clear `unknown` over a false positive.

## Engineering rules (learned from past integration bugs)

- **Never swallow exceptions silently.** Every `except` logs at least `logger.debug`.
- **Mocked tests check logic, not contracts between modules.** Where one module's output feeds another (probe -> `_gather_fingerprint_data` -> `fingerprint_camera`), add a test that runs the real glue code with only the I/O mocked. Run against a real device periodically.
- **When renaming a key in a probe, update every consumer.** Grep the key name across the whole project first. ONVIF details are namespaced `onvif_*` in `scanner.py` before they reach the fingerprinter; ONVIF replies are accepted only from the scanned IP (WS-Discovery is multicast).
- `import_fingerprinthub.py` writes candidates to `scripts/imported/`, never `db/` (`db/*.yaml` is loaded at runtime).
