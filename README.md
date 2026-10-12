# camera_scanner

Async Python library and CLI that identifies IP cameras on a network and resolves working URLs for video streams, snapshots and OSD control.

Give it an IP address (and optional credentials). It detects open camera ports, works out the **manufacturer / model / firmware / serial**, and returns ready-to-use integration links.

It is aimed at sysadmins and developers who auto-discover cameras and wire them into video-surveillance systems. **Use it only on networks and devices you are authorized to scan** (see [Licensing, attribution and responsible use](#5-licensing-attribution-and-responsible-use)).

- **Async**: built on `asyncio` / `aiohttp`.
- **Rule-based, no ML**: logic lives in Python, knowledge lives in YAML (`camera_scanner/db/`).
- **Honest results**: every detection carries a confidence score and an evidence trail. If the device could not be reached, the scanner says so instead of guessing.
- **Transparent data**: this README documents where the rules come from and how well each brand is covered. Coverage is uneven; read [Supported brands](#2-supported-brands-and-device-families) before relying on a brand.

## Contents

- [Install](#install) · [Usage](#usage) · [How it works](#how-it-works) · [Network status](#network-status)
- [1. Data sources and provenance](#1-data-sources-and-provenance)
- [2. Supported brands and device families](#2-supported-brands-and-device-families)
- [3. Protocol and identification coverage](#3-protocol-and-identification-coverage)
- [4. Confidence and evidence](#4-confidence-and-evidence)
- [5. Licensing, attribution and responsible use](#5-licensing-attribution-and-responsible-use)
- [6. Adding or updating a brand](#6-adding-or-updating-a-brand)
- [Tests](#tests) · [Project layout](#project-layout)

## Install

```bash
git clone https://github.com/agmmir/figerprint-DB.git
cd figerprint-DB
python3 -m venv camera_scanner/venv
camera_scanner/venv/bin/pip install -r camera_scanner/requirements.txt
```

Dependencies: `aiohttp>=3.11`, `pydantic>=2`, `PyYAML`, `mmh3>=4`, plus `pytest` / `pytest-asyncio` for tests. If `mmh3` is missing, favicon MMH3 matching is skipped and the scan still works.

`vendor/` (third-party reference clones) is **not part of the repository** (it is listed in `.gitignore`) and is not needed to run the scanner. See [Data sources](#1-data-sources-and-provenance).

## Usage

### CLI

Run from the repository root:

```bash
python -m camera_scanner.scanner 192.168.1.64 \
    --timeout 10 --semaphore 50 --concurrency 10 \
    --user admin --password 'secret'
```

Add `--json` for raw JSON output. Illustrative report (values are examples, not a real scan):

```
=== Scan result: 192.168.1.64 ===
  Network      : ok
  Manufacturer : Hikvision
  Model        : DS-2CD2143G0-I
  Firmware     : V5.5.82
  Confidence   : 0.85
  Open ports   : 80, 554, 8000
  Evidence     : http_server:App-webs, model_regex:(DS-2[A-Z0-9]+(?:-[A-Z0-9]+)*)
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

`CameraScanner.scan()` is a staged pipeline. Each stage only fills fields that an earlier stage left empty.

1. **Port check**: 28 candidate TCP ports (web 80-85/88/443/8443/8080/8088/8090, RTSP 554/8554/10554, Hikvision 8000/8001/8081/9000/9010, Dahua 37777/37778/50000, Xiongmai 34567, 5000, legacy 21/22/23), checked concurrently with a 3 s per-port timeout. An open port is not brand evidence. See `common_ports` in `scanner.py`.
2. **HTTP probe**: `Server` header, `WWW-Authenticate`, first 2 KB of HTML, favicon MD5 and MMH3.
3. **RTSP probe**: `OPTIONS` banner.
4. **Data gathering**: SSL certificate issuer/subject (when 443 is open), ISAPI (when HTTP hints Hikvision), ONVIF WS-Discovery (multicast, local segment only).
5. **Fingerprinting**: multi-signal matching against `db/signatures.yaml`. With credentials, Hikvision (ISAPI) can fill model, firmware and serial; Dahua (magicBox CGI) can fill firmware.
6. **URL resolution**: patterns picked by chipset (never set at present), then manufacturer, then `generic`, and verified live (HTTP status, RTSP `DESCRIBE` with Digest/Basic auth).

How confidence is computed, and what it does and does not mean, is documented in [section 4](#4-confidence-and-evidence).

### Network status

Each probe reports whether it reached the device. `network_status` on the result is one of:

| Value | Meaning |
|---|---|
| `ok` | at least one probe got a real answer |
| `partial` | the host answered at the transport level (refused / empty) but nothing useful came back |
| `unreachable` | no probe reached the host |
| `unknown` | status not determined |

The weak Dahua guess from open port 37777/37778 (confidence 0.40) runs only when `network_status` is `ok` or `partial`, and never overrides a stronger signal.

**TCP proxy / VPN detection.** If outbound TCP is intercepted (a VPN or transparent proxy that accepts every connection), a port scan reports every port as open. `scan()` therefore first tries a TCP connect to a random high port on TEST-NET-1 (`192.0.2.1`, never routable); success means interception. In that case `result.tcp_proxied` is set, the evidence list gets `port_scan: unreliable (tcp proxy detected)`, and `open_ports` is kept for information only: no port-derived protocols and no port-37777 Dahua guess. HTTP/RTSP/SSL probes exchange real data and are unaffected. The CLI prints `Network: ok (behind TCP proxy — port data unreliable)` and marks the ports `(proxy-inflated)`. A proxy that only intercepts some destinations or ports is not detected.

---

## 1. Data sources and provenance

The knowledge base lives in `camera_scanner/db/`. It was assembled from several public projects plus entries whose origin was **not recorded**. This section states what the repository evidence supports and what it does not. Nothing here is a claim that a rule was validated against a real device.

### Runtime data vs. reference material

- **Runtime**: only `camera_scanner/` is needed. Rules are plain YAML in `db/`; nothing is read from `vendor/` at scan time.
- **Reference material**: `vendor/` holds local clones of upstream projects used by the maintainers to look up and adapt rules. It is git-ignored, so it is **not shipped in this repository** and is **not a runtime dependency**. Clone the upstream projects yourself if you want to re-run the offline tools.
- **Offline tooling** (not runtime): `camera_scanner/scripts/import_fingerprinthub.py` (reads `vendor/FingerprintHub`, writes review-only candidate files), `camera_scanner/testing/ispyimport.py` (a scraper for iSpyConnect model tables).

### Sources

"Adapts" means individual markers or values were re-expressed as YAML entries. No source file is copied wholesale, except where noted. Upstream URLs and licences below were read from the local clones' `git remote` and `LICENSE` files; the URLs were checked to resolve.

| Source / project | Data or information used | Location in this repository | Attribution / license | Verification status |
|---|---|---|---|---|
| [WhatWeb](https://github.com/urbanadventurer/WhatWeb) | HTML title/body markers adapted from the plugins `sony-network-camera`, `panasonic-network-camera`, `mobotix-network-camera`, `toshiba-network-camera`, `canon-network-camera`, `avtech-video-web-server`, `intellinet-ip-camera`. The `rvi-camera` plugin was consulted and its markers deliberately rejected as non-unique. | `db/signatures.yaml` (`# source: WhatWeb ...` comments) | GPL-2.0 (upstream `LICENSE`) | Plugin files exist in the local clone. Rules are not validated against devices. Licence implications for adapted markers: [manual review](#items-requiring-manual-verification). |
| [Nuclei templates](https://github.com/projectdiscovery/nuclei-templates) | Markers adapted from `http/iot/panasonic-network-management`, `mobotix-guest-camera`, `novus-ip-camera`, `selea-ip-camera` | `db/signatures.yaml` (`# source: Nuclei ...` comments) | MIT, Copyright ProjectDiscovery, Inc. (upstream `LICENSE.md`) | Template files exist in the local clone. Not validated against devices. |
| [Ingram](https://github.com/jorhelp/Ingram) | `Ingram/rules.csv` title/header rules adapted for Xiongmai (NETSurveillance WEB), GeoVision, INSTAR, Netwave, ReeCam, NUUO | `db/signatures.yaml` (`# source: Ingram rules.csv ...` comments) | GPL-3.0 (upstream `LICENSE`) | Each rule line was found in the local `rules.csv`. Not validated against devices. Licence implications: [manual review](#items-requiring-manual-verification). |
| [Ingram-Pro](https://github.com/0x5477/Ingram-Pro) | Cloned into `vendor/`, but **no rule in this repository references it** | none | No `LICENSE` file found in the local clone | Not used. Listed for completeness only. |
| [FingerprintHub](https://github.com/0x727/FingerprintHub) (v4) | AVTECH and NUUO (`nvrsolo`) markers; MMH3 favicon hashes for Hikvision (`999357577`) and Dahua (`2019488876`), per the commit message of `7008ed7`. The importer builds *candidate* files for human review and never edits `signatures.yaml`. | `db/signatures.yaml` (`# src: FingerprintHub v4; id: ...` on three markers); `scripts/import_fingerprinthub.py`; `scripts/imported/_imported_fingerprinthub.yaml` and `scripts/_imported_fingerprinthub.report.yaml` (review-only output) | MIT, Copyright 0x727 (upstream `LICENSE.md`) | Importer output states "NOT verified". The two MMH3 values have no per-line comment; their origin rests on the commit message. |
| [BishopFox/Favicons](https://github.com/BishopFox/Favicons) | 42 MMH3 favicon hashes added from `identified.csv` for 16 brands in commit `69abc10` (camera/NVR web interfaces only; VMS platforms, generic and honeypot hashes were skipped). One hash, `1281253102`, is documented upstream as shared with OEM rebrands. | `favicon_mmh3` lists in `db/signatures.yaml` (`# src: BishopFox/Favicons`); commit `69abc10` | MIT, Copyright 2026 Bishop Fox (upstream `LICENSE`) | Each imported hash was checked to exist in the local `identified.csv`. Upstream labels `2019488876` (already present under Dahua) as an **Intelbras** interface: see [manual review](#items-requiring-manual-verification). |
| [Cameradar](https://github.com/Ullaakut/cameradar) | Candidate RTSP routes from `internal/dict/assets/routes` added as generic stream patterns | `db/_generic.yaml` (comment: "NOT verified against real devices") | MIT per upstream README badge; the `LICENSE` file contains the MIT permission text | Imported as unverified candidates. The `LICENSE` file has no visible copyright line in the local clone; see [manual review](#items-requiring-manual-verification). |
| iSpyConnect camera database (`https://www.ispyconnect.com/camera/<brand>`) | **Suspected** origin of the per-model URL patterns in the brand YAML files (about 7,200 model entries in total). Evidence is circumstantial: the scraper `testing/ispyimport.py` targets this site and builds per-model dictionaries with `snapshot` / `stream` / `ptz` / `other` lists, the same shape as the per-model entries in the brand files (which include `ptz`). The scraper itself emits `{user}:{pass}@{ip}` templates, so it does **not** explain the legacy `[USERNAME]` / `[PASSWORD]` / `[CHANNEL]` placeholders found in the same 20 files; their origin is unknown. | `db/<brand>.yaml` for the 20 brands with per-model entries (see section 2) | Not established. No per-file provenance comments exist. | **Suspected, not verified.** Terms of use and licence of the source have not been checked. [Manual review required](#items-requiring-manual-verification). |
| ONVIF specifications ([onvif.org](https://www.onvif.org/profiles/specifications/), [Core spec PDF](https://www.onvif.org/specs/core/ONVIF-Core-Specification.pdf)) | WS-Discovery probe and `GetDeviceInformation` SOAP messages, implemented independently in `probes/onvif.py` using the ONVIF namespaces | `probes/onvif.py` | ONVIF specification; no code taken from it | Links resolve. Conformance of the implementation to the spec has not been tested against devices. |
| Hikvision ISAPI, Dahua magicBox CGI | Vendor HTTP interfaces (`/ISAPI/System/deviceInfo`, `/cgi-bin/magicBox.cgi?action=getSoftwareVersion`) implemented independently | `probes/isapi.py`, `probes/dahua.py` | Vendor interfaces. No vendor documentation is stored in the repository and no documentation URL was verified. | The Dahua probe docstring refers to a confirmed 3.200.x DVR; no artifact of that observation is stored. Tests mock all I/O. |
| Shodan-style favicon hash convention | The MMH3-over-base64 computation in `fingerprinter.favicon_mmh3_hash` (the same convention used by FingerprintHub and BishopFox data) | `fingerprinter.py`, `tests/test_mmh3.py` | Algorithm convention | A test checks the convention against `mmh3` directly. One Dahua HTML-marker group is commented "supplied Shodan observation"; the observation itself is not stored. |
| Authored for this project | Python logic (`camera_scanner/*.py`) | `camera_scanner/*.py` | Repository owner (no licence file yet) | The `ssl_issuer` / `ssl_subject` markers and list-type AND markers have no recorded origin; see the next row. |
| **Origin not recorded** | Most `http_server`, `www_auth_realm`, `html_markers`, `model_regex`, `mac_oui`, `favicon_md5`, `favicon_paths` entries for Hikvision, Dahua, Axis, Uniview, Reolink and the brands without a `# source:` comment | `db/signatures.yaml` | Unknown | **Unverified.** See [manual review](#items-requiring-manual-verification). |

## 2. Supported brands and device families

### Counting method

- **34** brands are defined under `manufacturers:` in `db/signatures.yaml` (the only section the matcher evaluates).
- **1** additional family, `xiongmai-dvr`, exists only as a URL-pattern file and is never selected by `scan()` (lookup keys come from the manufacturer or chipset name); it can be requested explicitly through `resolve_urls()`.
- That gives **35** distinct brand/family keys.
- `engines:` (nginx, apache, lighttpd, goahead, boa: 5 web servers) and `chipsets:` (xiongmai: 1) in `signatures.yaml` are reference data and are **not** read by the matcher. They are not counted as brands.

### Reading this table

Coverage has four independent layers. A brand can have one and lack the others.

- **Fingerprinting**: can the scanner identify the brand (`Signals`).
- **Metadata**: can it fetch model/firmware/serial (`Metadata probes`).
- **URL resolution**: are there candidate stream/snapshot/OSD URLs (`URL patterns`).
- **Verified behavior**: what the tests establish (`Tests`). **All tests mock network I/O; none validate a real device.** The `Tests` column therefore describes rule logic only.

Signal legend: **N** names (ONVIF name normalisation), **S** HTTP `Server`, **RS** RTSP `Server`, **R** `WWW-Authenticate` realm, **H** HTML markers, **MR** model regex, **M** MAC OUI, **F5** favicon MD5, **FP** favicon-by-path MD5, **FM** favicon MMH3, **SI** / **SS** SSL issuer / subject. Numbers are counts of entries.

`URL patterns` counts per-model keys; "brand-level" means generic snapshot/stream/overlay lists that apply when the model is unknown. A brand with only per-model keys yields **no** candidates when its model could not be resolved (the scanner does not fall back to `generic` once the brand is known).

### Brands with the richest rules

| Brand | Aliases / OEM | Signals | URL patterns | Metadata probes | Tests (mocked) | Provenance and limitations |
|---|---|---|---|---|---|---|
| **hikvision** | `Hikvision`, `HIKVISION`, `Hikvison` | N3 S5 R2 H5 MR4 M6 F5 1 FM9 SI2 SS1 | 1,488 models + brand-level | ISAPI `deviceInfo` (needs credentials): model, firmware, serial | Positive: server, realm, html, favicon MD5, model regex, SSL issuer/subject, MMH3, AND-marker; negative: AND-marker with one part missing | FM from FingerprintHub (1) and BishopFox (8). Other rules: origin not recorded. `www_auth_realm: IP Camera` is generic. |
| **dahua** | `Dahua`, `DAHUA`, `Dahua Technology` | N3 S3 R2 H7 MR4 M4 F5 3 FP1 FM8 SI3 SS2 | 978 models + brand-level | magicBox CGI (needs credentials): **firmware only** | Positive: html markers, favicon MD5/path, SSL, MMH3, firmware CGI (many, mocked); negative: generic web-service title not Dahua | FM: 1 from FingerprintHub, 7 from BishopFox (incl. shared `1281253102`). `2019488876` is labelled Intelbras in BishopFox but corresponds to a Dahua firmware entry (`dh-ipc-hdbw23a0rn-zs_firmware`) in FingerprintHub. `www_auth_realm: Login to` is generic: it also matches Xiongmai-style realms (a test documents this shadowing). |
| **axis** | `Axis`, `AXIS` | N2 S3 R1 H3 MR4 M5 F5 1 FM1 SI1 | 871 models + brand-level | None | No dedicated fingerprint test | `http_server` entries include `Apache` and `lighttpd`, which are not Axis-specific. Origin of most rules not recorded. |
| **uniview** | `Uniview`, `UNIVIEW`, `Uniview Technologies` | N3 S2 R1 H3 MR2 M4 F5 1 FP1 FM1 SI1 SS1 | **Empty file** (brand known, no patterns) | None | Positive: favicon path, SSL subject | `html_markers` include generic `/cgi-bin/login.cgi` and `/view/index.html`. Origin not recorded. |
| **reolink** | `Reolink`, `REOLINK` | N2 S2 R1 H3 MR2 M4 FM4 | 337 models, no brand-level | None | No dedicated test | Rules look templated (see below). FM from BishopFox. |

### Other brands

| Brand | Aliases / OEM | Signals | URL patterns | Metadata probes | Tests (mocked) | Provenance and limitations |
|---|---|---|---|---|---|---|
| amcrest | `Amcrest` | N2 S2 R1 H3 MR1 M3 | Empty file | None | None | Templated rules, origin not recorded |
| ezviz | `Ezviz` | N2 S2 R1 H3 MR1 M4 | 236 models | None | None | Templated rules |
| annke | `Annke` | N2 S2 R1 H3 MR1 M4 | 176 models | None | None | Templated rules |
| lorex | `Lorex` | N2 S2 R1 H3 MR1 M4 | 243 models | None | None | Templated rules |
| swann | `Swann` | N2 S2 R1 H3 MR1 M4 | 178 models | None | None | Templated rules |
| bosch | `Bosch` | N2 S2 R1 H3 MR1 M4 FM1 | **None** (falls to no patterns) | None | None | Templated rules; FM from BishopFox |
| d-link | `D-Link`, `DLink` | N2 R2 H3 FM4 | 885 models, no brand-level | None | Positive: DCS html marker, DCS realm | FM from BishopFox. No `model_regex`, so the model is never extracted from page data for D-Link |
| foscam | `Foscam` | N1 H1 | brand-level only (no models) | None | None | Single html marker `foscam`, origin not recorded |
| hipcam | `Hipcam`, `Hipcam RealServer` | N3 S4 RS3 R2 H2 (`specific_ports: 10554` is declared in the YAML but not evaluated by the matcher) | 13 models + `default` | None | Positive: 5 tests (server, RTSP server) | Only brand with RTSP-server signatures. Origin not recorded |
| imou | `Imou` | N2 H1 | 99 models | None | None | Single html marker, origin not recorded |
| rvi | `RVi`, `RVI` | N2 only | 26 models | None | Negative only: 2 tests that generic text is not matched | **Names only, no fingerprint marker.** Bare marker `rvi` was removed because it matched "service". WhatWeb markers rejected as non-unique |
| samsung | `Samsung`, `Hanwha`, `Wisenet` | N3 H3 FM1 | 369 models, no brand-level | None | None | FM from BishopFox (Hanwha Wisenet NVR page). Samsung/Hanwha merged under one key by the maintainers |
| sony | `Sony` | N1 H2 MR1 | 228 models | None | Positive: model regex `SNC-` | WhatWeb-derived marker |
| tplink | `TP-Link`, `TP-LINK`, `TPLINK`, `Tapo` | N4 H3 FM2 | 315 models | None | None | FM from BishopFox |
| vivotek | `Vivotek`, `VVTK` | N3 H2 FM4 | 473 models | None | None | FM from BishopFox |
| panasonic | `Panasonic`, `Matsushita` | N2 H3 MR1 FM3 | **None** | None | Positive: 2 html tests | WhatWeb + Nuclei markers; FM from BishopFox |
| mobotix | `Mobotix` | N1 H2 FM1 | **None** | None | Positive: 2 html tests | WhatWeb + Nuclei markers; FM from BishopFox |
| toshiba | `Toshiba` | N1 H1 | **None** | None | Positive: 1 html test | WhatWeb-derived |
| canon | `Canon` | N1 H1 MR1 | **None** | None | Positive: model regex `VB-C` | WhatWeb-derived |
| avtech | `AVTech`, `AVTECH` | N2 H4 FP1 FM1 | **None** | None | Positive/negative: AND-marker tests; html title | WhatWeb + FingerprintHub markers; FM from BishopFox; favicon-path MD5 origin not recorded |
| intellinet | `Intellinet` | N1 H1 | **None** | None | Positive: 1 html test | WhatWeb-derived |
| novus | `Novus` | N1 H1 | **None** | None | Positive: 1 html test | Nuclei-derived |
| selea | `Selea` | N1 S2 H1 | **None** | None | Positive: 2 tests (server, html) | Nuclei-derived. ANPR camera |
| xiongmai | `Xiongmai`, `XMEye`, `XM` | N3 H3 MR1 FM1 | `default` only (chipset-style generic list, no per-model) | None | Positive: 2 html tests; negative: generic title not matched; chipset/port-34567 tests | Ingram-derived markers; FM from BishopFox. Port 34567 is deliberately **not** used as evidence. The `chipsets:` copy is reference-only |
| xiongmai-dvr | none | none | 9 models (key `xiongmai-dvr`) | None | None | **Not selected by `scan()`**: no signature key produces this name. It is reachable only by calling `resolve_urls(manufacturer="xiongmai-dvr")` explicitly |
| geovision | `GeoVision` | N1 H1 FM1 | 241 models | None | Positive: 1 html test | Ingram-derived title; FM from BishopFox |
| instar | `INSTAR` | N1 H1 (AND) FM2 | 72 models | None | Positive and negative: AND-marker tests | Ingram-derived; FM from BishopFox |
| netwave | `Netwave` | N1 S1 H1 | 5 models | None | Positive: server | Ingram-derived |
| reecam | `ReeCam` | N1 S1 H1 | Empty file | None | Positive: server | Ingram-derived |
| nuuo | `NUUO`, `Nuuo` | N2 H2 | Empty file | None | Positive: 1 html test | Ingram + FingerprintHub markers |
| `generic` (`_generic.yaml`) | none | none | brand-level snapshot/stream/overlay | None | Loading test (unique, no credential-looking routes) | Used when no manufacturer is identified. Cameradar-derived RTSP routes, unverified |

### Caveats that apply across the table

- **Shared generic HTML markers.** `/cgi-bin/login.cgi` and `/view/index.html` are html markers of **eight** brands (uniview, reolink, amcrest, ezviz, annke, lorex, swann, bosch). A page containing either string is attributed to the first one in file order, **Uniview** (0.75), and the evidence list repeats the marker once per brand.
- **Templated rules.** Seven brands (reolink, amcrest, ezviz, annke, lorex, swann, bosch) share a near-identical shape: `names`, `<brand>` / `<Brand>-Webs` server and realm, markers `/<brand>`, `/cgi-bin/login.cgi`, `/view/index.html`, and 3-4 MAC OUIs. No source is recorded. Treat them as **unverified placeholders**, not as measured fingerprints.
- **Shared MAC OUIs.** `00:16:6E`, `00:1D:4A`, `00:1B:06` and `00:1F:33` appear under 8, 7, 6 and 6 different brands respectively, so they cannot identify one brand. The matcher takes the first brand in file order.
- **MAC OUI data reaches the matcher only in the narrow case described in [section 3](#3-protocol-and-identification-coverage).**
- **Brand-level URL coverage** exists only for hikvision, dahua, axis, foscam, xiongmai (`default`), hipcam (`default`) and `generic`. For other brands, URL candidates are produced only when the model is resolved.
- The 20 brand files with legacy `[USERNAME]` / `[PASSWORD]` / `[CHANNEL]` placeholders are: annke, axis, d-link, dahua, ezviz, geovision, hikvision, hipcam, imou, instar, lorex, netwave, reolink, rvi, samsung, sony, swann, tplink, vivotek, xiongmai-dvr.

## 3. Protocol and identification coverage

| Mechanism | What it can provide | Identifies | Credentials | Limitations / false positives |
|---|---|---|---|---|
| **Port scan** | Open ports among the 28 candidates in `common_ports` (TCP connect only) | A service only. Ports 37777/37778 trigger a weak Dahua guess (0.40) when the device was reached and nothing else matched | No | Ports are shared across vendors; 37777/37778 are Dahua SDK defaults but are not exclusive to Dahua |
| **HTTP / HTTPS** (`probes/http.py`) | `Server` header, `WWW-Authenticate` realm, first 2 KB of HTML, favicon MD5 and MMH3, favicon hashes at signature-listed paths | Brand (and sometimes model via regex) | No | Generic markers and generic servers (`Apache`, `lighttpd`, `IP Camera`) can mismatch. Only 200/401/403 are treated as camera-like |
| **RTSP** (`probes/rtsp.py`) | `OPTIONS` banner (`Server`); `DESCRIBE` with Digest/Basic auth to verify a stream URL | Brand only for `hipcam` (the only brand with RTSP-server signatures); otherwise a service | Only for stream verification | A 200 reply to `DESCRIBE` proves the stream answers, not that the video is decodable |
| **SSL/TLS** (`probes/ssl_cert.py`) | Peer certificate issuer/subject DN (verification is off; modern-then-legacy TLS fallback) | Brand where a DN marker exists (hikvision, dahua, uniview, axis for issuer) | No | Self-signed certificates can carry arbitrary text. Only a few brands have markers |
| **ONVIF** (`probes/onvif.py`) | WS-Discovery over UDP multicast; `GetDeviceInformation` for manufacturer, model, firmware, serial | Brand, model, firmware, serial | No | See implementation gaps below |
| **ISAPI** (`probes/isapi.py`) | `isapi_probe` runs only when the `Server` or `WWW-Authenticate` header literally contains "hikvision" (common Hikvision headers such as `App-webs` do not, so it often does not run; its output is stored but not used by the matcher); authenticated `isapi_device_info` returns model, firmware, serial (and MAC) | Model/firmware/serial for Hikvision | Yes for `deviceInfo` | Hikvision only. Gated on Hikvision having been identified first |
| **Dahua CGI** (`probes/dahua.py`) | `magicBox.cgi?action=getSoftwareVersion` | Firmware only | Yes (Basic then Digest) | Dahua only; does not return model or serial |
| **URL verification** | HTTP status of candidate snapshot/stream/OSD URLs; RTSP `DESCRIBE` verdict | A working URL, not a brand | Used when supplied | 2xx is classed as working, 401/403 as "requires auth" |

### Known implementation gaps (as of this commit)

These were found while auditing the code and are documented here rather than silently assumed to work:

- **ONVIF discovery is multicast and local-segment only.** It cannot reach a remote or Internet-facing target. The scanner now accepts a WS-Discovery reply only if it came from, or advertises, the scanned IP; a neighbour's reply is ignored. (An earlier version merged the first discovered device under keys the matcher did not read, so ONVIF never contributed to a live scan; fixed together with this paragraph.)
- **The ISAPI MAC address is now passed to the matcher**, so MAC OUI matching can fire, but only when the unauthenticated `isapi_probe` returns data, which requires the device to answer `/ISAPI/System/deviceInfo` without credentials and the HTTP headers to contain "hikvision".
- **`chipset` is never set**, so chipset-first URL selection is dormant.

## 4. Confidence and evidence

Confidence is computed in `fingerprinter.fingerprint_camera` and then folded into the result by `scanner.scan`.

**Algorithm (as implemented):**

1. Signals are evaluated in this fixed order: ONVIF, MAC OUI, SSL issuer, SSL subject, HTTP `Server`, RTSP `Server`, WWW-Authenticate realm, favicon MD5, favicon-by-path, favicon MMH3, HTML markers.
2. **The brand comes from the first signal in that order that matches**, not from the highest-confidence signal. Within one signal type, the first brand in `signatures.yaml` file order wins.
3. **Confidence is the maximum** of the constants of all signals that matched (`max()`, no noisy-OR, no summation). A signal that points to a different brand than the one chosen still contributes to the maximum.
4. A model extracted by `model_regex` adds `+0.05` (capped at 1.0).

| Signal | Constant |
|---|---|
| ONVIF device info | 0.99 |
| MAC OUI, SSL issuer | 0.95 |
| WWW-Authenticate realm, favicon MD5 / path / MMH3, SSL subject | 0.90 |
| HTTP / RTSP `Server` | 0.80 |
| HTML marker | 0.75 |
| Port-only Dahua guess (scanner level) | 0.40 |

`scan()` takes `max(existing, fingerprint confidence)` and appends the evidence strings (for example `http_server:App-webs`, `favicon_mmh3:999357577`, `open_port:37777->dahua-guess`).

**Interpretation.** The confidence value is an internal heuristic: a fixed weight per signal type. It is **not a calibrated probability**; no calibration against labelled devices exists in the repository. Two devices with the same score are not equally likely to be identified correctly, and a signal's weight does not reflect how unique its marker is (see the generic markers noted in section 2).

Do not conflate these levels:

| Level | What it means | How it shows up |
|---|---|---|
| Reachable network service | A port is open or a probe got an answer | `open_ports`, `network_status` |
| Weak heuristic | A guess from circumstantial data | e.g. `*-guess` evidence, confidence 0.40 |
| Positive fingerprint match | A manufacturer/model marker matched | `manufacturer`, evidence entries, confidence 0.75-0.99 |
| Verified working stream URL | A candidate URL answered (HTTP 2xx or RTSP `DESCRIBE` OK) | `stream_urls` / `snapshot_urls`; `requires_auth_urls` for 401/403 |

A fingerprint match does not imply that any URL works, and a working URL does not imply the brand is right.

## 5. Licensing, attribution and responsible use

### This repository

No `LICENSE` file exists in this repository at the time of writing, so **no licence is granted or implied** for the code or the YAML data. The maintainers should choose one. See [manual review](#items-requiring-manual-verification).

### Third-party material

Licences below were read from the `LICENSE` files in the local clones. They apply to the upstream projects, not to this repository.

| Upstream | Licence (from upstream file) | Where its material appears here | Obligation to check |
|---|---|---|---|
| WhatWeb | GPL-2.0 | Adapted HTML markers in `signatures.yaml` | Whether short factual markers re-expressed as YAML create a derivative work: not determined |
| Ingram | GPL-3.0 | Adapted title/header rules in `signatures.yaml` | Same question; GPL-3.0 vs. this repository's (unset) licence |
| Nuclei templates | MIT, Copyright 2025 ProjectDiscovery, Inc. | Adapted markers in `signatures.yaml` | Keep the copyright notice when redistributing substantial portions |
| FingerprintHub | MIT, Copyright 2021 0x727 | Markers and two MMH3 values in `signatures.yaml` | As above |
| BishopFox/Favicons | MIT, Copyright 2026 Bishop Fox | 42 MMH3 values in `signatures.yaml` (44 MMH3 values in total, counting the two earlier FingerprintHub-era ones, which also appear in its CSV) | As above |
| Cameradar | MIT per README; `LICENSE` text without a copyright line in the local clone | RTSP routes in `_generic.yaml` | Confirm copyright holder and notice |
| Ingram-Pro | No licence file found | Not used | n/a |
| iSpyConnect | Unknown | Suspected source of per-model URL patterns | Terms of use not checked |

`vendor/` is git-ignored: upstream source is not redistributed through this repository. Attribution for adapted data is carried by the `# source:` / `# src:` comments in `signatures.yaml`; the per-model URL patterns carry none.

### Items requiring manual verification

1. **Choose and add a licence** for this repository.
2. **GPL-2.0 (WhatWeb) and GPL-3.0 (Ingram):** decide whether the adapted markers are derivative works and what that implies for this repository's licence.
3. **iSpyConnect-derived URL patterns:** confirm the actual source of the per-model patterns in the 20 brand files, and check the site's terms of use.
4. **Unrecorded origin** of most `http_server`, `www_auth_realm`, `html_markers`, `model_regex`, `mac_oui`, `favicon_md5` and `favicon_paths` entries (notably Hikvision, Dahua, Axis, Uniview, and the seven templated brands in section 2).
5. **Hash `2019488876`** under Dahua is labelled "Intelbras IP Camera" in BishopFox/Favicons but matches a Dahua firmware entry in FingerprintHub; Intelbras is not a brand in this database. Decide whether it should stay under Dahua.
6. **MAC OUIs** have not been checked against the IEEE registry; four OUIs are each shared by 6-8 brands.
7. **Cameradar `LICENSE`** has no copyright line in the local clone; confirm against the upstream repository.
8. **Limited ONVIF and MAC OUI reach** (section 3): ONVIF works only on the local segment and MAC OUI only when anonymous ISAPI answers. Both were previously not wired into the matcher at all; the wiring is fixed but neither has been validated on a real device.

### Responsible use

This tool sends network probes, attempts HTTP/RTSP authentication when you provide credentials, and tests many candidate URLs. **Scan only devices and networks you own or are explicitly authorized to assess.** Unauthorised scanning or access can be illegal. Credentials you supply are used only for authentication headers and are not logged in URLs. Do not use the tool for mass targeting or to attempt credential guessing against third-party devices.

## 6. Adding or updating a brand

1. **Identify and document the source** of every rule: a public project and file, a vendor document, or a response you captured yourself. If you cannot name it, do not add the rule.
2. **Edit the YAML.**
   - Fingerprints: add or extend the brand under `manufacturers:` in `camera_scanner/db/signatures.yaml`. Only the fields the matcher reads are used: `names`, `http_server`, `rtsp_server`, `www_auth_realm`, `html_markers`, `model_regex`, `mac_oui`, `favicon_md5`, `favicon_paths`, `favicon_mmh3`, `ssl_issuer`, `ssl_subject`.
   - URL patterns: one brand per file, `camera_scanner/db/<brand>.yaml` (a file containing just `<brand>: {}` is valid). Use a `default:` block for brand-wide patterns and prefix keys for many-model brands.
   - Do not invent hashes or OUIs. Leave `favicon_md5` / `mac_oui` empty unless a real value was verified.
3. **Add provenance.** Put a comment above each imported group, for example `# source: <project> <file> (<what matched>)` or `# src: <project>`, with the upstream URL where practical.
4. **Add a positive test** in `camera_scanner/tests/` that feeds a realistic signal to `fingerprint_camera` and asserts the manufacturer and evidence.
5. **Add a negative test** for any short, common or shared marker (for example generic page text or a shared OUI) showing it does not match unrelated devices.
6. **State the validation level** in the PR or commit message: static reference only, mocked/simulated test, or validated against a real device (with firmware and date). Tests in this repository are all mocked; do not describe a rule as device-validated unless it was.
7. **Update the docs.** Add or adjust the brand's row in [section 2](#2-supported-brands-and-device-families) and, for a new upstream source, its row in [section 1](#1-data-sources-and-provenance).

Prefer removing an unsafe marker over keeping a speculative one.

## Tests

```bash
camera_scanner/venv/bin/python -m pytest camera_scanner/tests/ -q
```

Tests mock all network and subprocess I/O and never touch real hosts. They therefore verify rule logic and control flow, not behavior on real cameras.

## Project layout

```
camera_scanner/
  scanner.py        pipeline, URL testing, CLI
  fingerprinter.py  rule-based matcher
  models.py         CameraInfo (Pydantic v2)
  capture.py        ffmpeg / curl command builders
  probes/           http, rtsp, onvif, isapi, dahua, ssl_cert
  db/               signatures and URL patterns (YAML)
  scripts/          offline importers (FingerprintHub candidate generator)
  testing/          ad-hoc import staging (iSpyConnect scraper)
  tests/
vendor/             local upstream clones: reference only, git-ignored, not shipped
```
