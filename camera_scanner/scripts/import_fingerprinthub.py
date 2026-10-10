"""
Extract camera-manufacturer fingerprint *candidates* from FingerprintHub v4 and
emit a review-only candidate YAML plus a provenance report.

This is OFFLINE tooling. It never performs network I/O and it NEVER modifies
`signatures.yaml`, `vendor/`, or runtime code. Its only outputs are:

  * camera_scanner/db/_imported_fingerprinthub.yaml        (candidate signatures)
  * camera_scanner/db/_imported_fingerprinthub.report.yaml (per-entry/per-value provenance)

The candidate YAML uses only the fields the current matcher (`fingerprinter.py`)
evaluates: `html_markers`, `http_server`, `favicon_md5`. It intentionally does
NOT emit regex (the engine does not take regex markers from the DB for these
fields) and does NOT convert favicon hashes between algorithms.

Nothing here is "verified" merely because FingerprintHub contains it: the output
is a candidate set for human review (Phase 3), not an approved merge.
"""

import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

import yaml

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_PKG = os.path.dirname(_HERE)                    # camera_scanner/
_REPO = os.path.dirname(_PKG)                    # GAMA_recognizer/
VENDOR_JSON = os.path.join(_REPO, "vendor", "FingerprintHub", "web_fingerprint_v4.json")
SIGNATURES_YAML = os.path.join(_PKG, "db", "signatures.yaml")
OUT_CANDIDATES = os.path.join(_PKG, "db", "_imported_fingerprinthub.yaml")
# The report lives OUTSIDE db/ on purpose: scanner._load_url_patterns() globs
# every db/*.yaml, so a large provenance file there would be parsed on each
# scanner init. Keeping it in scripts/ avoids any runtime side effect.
OUT_REPORT = os.path.join(_HERE, "_imported_fingerprinthub.report.yaml")

# --------------------------------------------------------------------------
# Discovery / filter constants (from the approved Phase 1 spec)
# --------------------------------------------------------------------------
CAM_KW = [
    "camera", "dvr", "nvr", "ipcam", "webcam", "surveillance",
    "hikvision", "dahua", "axis", "xiongmai", "reolink", "uniview",
    "foscam", "amcrest", "ezviz", "annke", "lorex", "vivotek",
    "mobotix", "geovision", "instar", "avtech", "nuuo", "gv-",
    "ip camera",
]

GENERIC_WORDS = {
    "camera", "web", "login", "admin", "ip", "server", "index",
    "home", "view", "http", "html", "body", "title", "default",
}
BAD_SUBSTR = ["cve", "exploit", "poc", "payload", "inject"]
MIN_WORD_LEN = 6

# Word-matcher `part` values that map to the HTML body (-> html_markers).
BODY_PARTS = {None, "", "body", "all", "response", "<none>"}

_MD5_RE = re.compile(r"^[0-9a-f]{32}$")

# --------------------------------------------------------------------------
# Explicit, auditable routing table for every camera-keyword-matched entry.
#   id -> (classification, gama_key_or_None, human_reason)
# classification in:
#   camera_device     - a real camera/DVR/NVR device
#   platform_software - vendor management/VMS/gateway software (NOT a camera)
#   framework_other   - generic web software that merely matched a keyword
#   nas               - NAS surveillance add-on
#   ambiguous         - unclear; needs a human decision
# Only (camera_device AND gama_key in existing manufacturers) is eligible to be
# written into the candidate YAML. Everything else is recorded in the report,
# never silently dropped. An entry that matches the keyword pass but is absent
# from this table is routed to 'ambiguous'/None ("unclassified") rather than
# guessed at.
# --------------------------------------------------------------------------
ROUTING: Dict[str, Tuple[str, Optional[str], str]] = {
    # --- generic web frameworks that only matched on the word "axis"/"camera"
    "apache-axis": ("framework_other", None, "Apache Axis SOAP framework, not Axis cameras"),
    "apache-axis2": ("framework_other", None, "Apache Axis2 framework"),
    "axis2-web": ("framework_other", None, "Apache Axis2 web console"),
    "cameralife": ("framework_other", None, "Camera Life photo-gallery software"),
    # --- NAS
    "readynas_surveillance": ("nas", None, "Netgear ReadyNAS surveillance add-on"),
    # --- unmapped / software DVRs
    "dvr": ("ambiguous", None, "Argus Surveillance DVR (Windows software); no GAMA brand"),
    "camera_firmware": ("camera_device", None, "ACTi camera firmware; vendor 'acti' has no GAMA key"),
    "tbk-dvr": ("camera_device", None, "TBK-branded DVR; no GAMA key 'tbk'"),
    # --- Dahua software platforms (not cameras)
    "icc": ("platform_software", "dahua", "Dahua ICC command-centre platform"),
    "smart_parking_management": ("platform_software", "dahua", "Dahua parking-management platform"),
    "dahua-wpms": ("platform_software", "dahua", "Dahua WPMS platform"),
    "dahua-zhi-hui-yuan-qu-zong-he-guan-li-ping-tai":
        ("platform_software", "dahua", "Dahua smart-park management platform"),
    # --- Hikvision software platforms / gateways (not cameras)
    "intercom_broadcast_system": ("platform_software", "hikvision", "Hikvision intercom/broadcast system"),
    "hikvision-ip-wang-luo-dui-jiang-guang-bo-xi-tong":
        ("platform_software", "hikvision", "Hikvision IP intercom/broadcast system"),
    "hikvision-isecure-center": ("platform_software", "hikvision", "Hikvision iSecure Center platform"),
    "zong-he-an-fang-guan-li-ping-tai-hikvision-isecure-center":
        ("platform_software", "hikvision", "Hikvision iSecure Center platform (CN title)"),
    "hikvision-ivms": ("platform_software", "hikvision", "Hikvision iVMS platform"),
    "hikvision-ivms-8700": ("platform_software", "hikvision", "Hikvision iVMS-8700 platform"),
    "hikvision-bigdatadiagnosis": ("platform_software", "hikvision", "Hikvision big-data diagnosis tool"),
    "hikvision-cloudvideo": ("platform_software", "hikvision", "Hikvision cloud-video platform"),
    "hikvision-videocload": ("platform_software", "hikvision", "Hikvision video-cloud platform"),
    "hikvision-intelligentsafeguardsystems":
        ("platform_software", "hikvision", "Hikvision intelligent safeguard system"),
    "hikvision-an-quan-wang-guan": ("platform_software", "hikvision", "Hikvision security access gateway"),
    "hikvision-shi-pin-bian-ma-she-bei-jie-ru-wang-guan":
        ("platform_software", "hikvision", "Hikvision video-encoder access gateway"),
    "hikvision-v23-control":
        ("ambiguous", "hikvision", "Hikvision web ActiveX control demo; possibly device web UI"),
    # --- other-vendor platforms without a GAMA key
    "kedacom-dvr-jie-ru-wang-guan": ("platform_software", None, "Kedacom DVR access gateway; no GAMA key"),
    "pcitc-cameras-and-surveillance": ("platform_software", None, "PCITC surveillance platform; no GAMA key"),
    "unimas-cameraaudit": ("platform_software", None, "Unimas camera-audit platform; no GAMA key"),
    "videosurveillancemanagementplatform": ("platform_software", None, "generic VSMP; no GAMA key"),
    # --- Uniview software/clients (not cameras)
    "uniview-ezclould": ("platform_software", "uniview", "Uniview EZCloud platform"),
    "uniview-ezstation": ("platform_software", "uniview", "Uniview EZStation client"),
    "uniview-vm50": ("platform_software", "uniview", "Uniview VM video-management software"),
    # --- real camera / recorder devices (eligible when mapped to a known brand)
    "avtech-video-web-server": ("camera_device", "avtech", "AVTech video web server (device)"),
    "ipm-721s_firmware": ("camera_device", "amcrest", "Amcrest IPM-721S camera firmware"),
    "nvrsolo_firmware": ("camera_device", "nuuo", "NUUO NVRsolo recorder firmware"),
    "nvrmini_firmware": ("camera_device", "nuuo", "NUUO NVRmini recorder firmware"),
    "nvr301-04s2-p4": ("camera_device", "uniview", "Uniview NVR301 recorder"),
    "e1_zoom": ("camera_device", "reolink", "Reolink E1 Zoom camera"),
    "e1_zoom_firmware": ("camera_device", "reolink", "Reolink E1 Zoom firmware"),
    "s14": ("camera_device", "mobotix", "Mobotix S14 camera"),
    "geowebserver": ("camera_device", "geovision", "GeoVision GeoWebServer"),
    "hikvision": ("camera_device", "hikvision", "Hikvision device"),
    "hikvision-ip-camera": ("camera_device", "hikvision", "Hikvision IP camera"),
    "ds-2cd2026g2-iu-sl_firmware": ("camera_device", "hikvision", "Hikvision DS-2CD camera firmware"),
    "dh-ipc-hdbw23a0rn-zs_firmware": ("camera_device", "dahua", "Dahua IPC-HDBW camera firmware"),
}


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def norm(v: Any) -> str:
    """Flatten any JSON value to a defensively-stringified form."""
    if v is None:
        return ""
    if isinstance(v, (list, tuple)):
        return " ".join(norm(x) for x in v)
    return str(v)


def entry_fields(entry: Dict[str, Any]) -> Dict[str, str]:
    info = entry.get("info") or {}
    meta = info.get("metadata") or {}
    return {
        "id": norm(entry.get("id")),
        "name": norm(info.get("name")),
        "product": norm(meta.get("product")),
        "vendor": norm(meta.get("vendor")),
    }


def is_camera_entry(fields: Dict[str, str]) -> bool:
    hay = " ".join([fields["id"], fields["name"], fields["product"], fields["vendor"]]).lower()
    return any(kw in hay for kw in CAM_KW)


def classify(entry_id: str) -> Tuple[str, Optional[str], str]:
    """Route a keyword-matched entry. Unknown ids degrade to 'ambiguous'."""
    if entry_id in ROUTING:
        return ROUTING[entry_id]
    return ("ambiguous", None, "unclassified - not in routing table; needs manual review")


def is_valid_md5(h: Any) -> bool:
    """True only for a 32-char lowercase-hex MD5, matching GAMA's favicon_md5."""
    return isinstance(h, str) and bool(_MD5_RE.match(h.strip().lower()))


def word_filter_reason(word: str) -> Optional[str]:
    """Return a rejection reason, or None if the word passes the first-pass filters."""
    s = word.strip()
    if len(s) < MIN_WORD_LEN:
        return f"too_short(<{MIN_WORD_LEN})"
    if s.lower() in GENERIC_WORDS:
        return "generic_word"
    low = s.lower()
    for bad in BAD_SUBSTR:
        if bad in low:
            return f"bad_substr:{bad}"
    return None


def _marker_dedup_key(value: Any) -> Tuple[str, Any]:
    """Case-insensitive dedup key for an html_markers/http_server value.
    A list value (AND-group) is order-independent."""
    if isinstance(value, (list, tuple)):
        return ("AND", frozenset(str(p).strip().lower() for p in value))
    return ("STR", str(value).strip().lower())


# --------------------------------------------------------------------------
# Matcher extraction
# --------------------------------------------------------------------------
def extract_candidates(entry: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Walk one entry's http[*].matchers and return candidate records. Each record:
      {signal, value, matcher_type, part, condition, source_path, entry_id, status, reason}
    `status` is "extracted" (passed first-pass filters) or "skipped"/"filtered".
    Dedup against existing signatures and against the accumulating YAML happens
    later in build().
    """
    eid = norm(entry.get("id"))
    out: List[Dict[str, Any]] = []

    for req in (entry.get("http") or []):
        if not isinstance(req, dict):
            continue
        src_path = norm(req.get("path"))
        for m in (req.get("matchers") or []):
            if not isinstance(m, dict):
                continue
            mtype = m.get("type")

            if mtype == "regex":
                out.append(dict(signal=None, value=norm(m.get("regex")), matcher_type="regex",
                                part=m.get("part"), condition=m.get("condition"),
                                source_path=src_path, entry_id=eid,
                                status="skipped", reason="regex matcher (policy: skip)"))
                continue

            if mtype == "favicon":
                for h in (m.get("hash") or []):
                    if is_valid_md5(h):
                        out.append(dict(signal="favicon_md5", value=h.strip().lower(),
                                        matcher_type="favicon", part=None, condition=None,
                                        source_path=src_path, entry_id=eid,
                                        status="extracted", reason="valid 32-hex md5"))
                    else:
                        out.append(dict(signal=None, value=norm(h), matcher_type="favicon",
                                        part=None, condition=None, source_path=src_path,
                                        entry_id=eid, status="skipped",
                                        reason="non-md5 favicon hash (mmh3/int) - incompatible"))
                continue

            if mtype == "word":
                part = m.get("part")
                cond = m.get("condition")
                words = [w for w in (m.get("words") or []) if isinstance(w, str)]

                if part == "header":
                    # Constraint 4: a header word is NOT assumed to be a Server
                    # identifier. The observed values include the header name
                    # prefix (e.g. "server: face-webs"), which GAMA's http_server
                    # matcher (matches the header *value*) cannot use. Record for
                    # review rather than emit a wrong http_server candidate.
                    for w in words:
                        out.append(dict(signal=None, value=w, matcher_type="word", part="header",
                                        condition=cond, source_path=src_path, entry_id=eid,
                                        status="skipped",
                                        reason="header word needs manual review (not a clean Server value)"))
                    continue

                if part not in BODY_PARTS:
                    for w in words:
                        out.append(dict(signal=None, value=w, matcher_type="word", part=part,
                                        condition=cond, source_path=src_path, entry_id=eid,
                                        status="skipped", reason=f"unsupported word part: {part!r}"))
                    continue

                # Body words -> html_markers.
                if len(words) > 1 and cond == "and":
                    # AND-group: faithfully representable as a single list-marker
                    # ONLY if every member passes the first-pass filters; dropping
                    # a member would change the matcher's meaning.
                    reasons = [(w, word_filter_reason(w)) for w in words]
                    failed = [(w, r) for w, r in reasons if r]
                    if failed:
                        out.append(dict(signal=None, value=[w for w in words], matcher_type="word",
                                        part="body", condition="and", source_path=src_path, entry_id=eid,
                                        status="filtered",
                                        reason="AND-group dropped (a member failed filters): " +
                                               "; ".join(f"{w!r}:{r}" for w, r in failed)))
                    else:
                        out.append(dict(signal="html_markers", value=[w.strip() for w in words],
                                        matcher_type="word", part="body", condition="and",
                                        source_path=src_path, entry_id=eid, status="extracted",
                                        reason="AND-group of words (all members passed)"))
                else:
                    # single word, or multi with condition OR/unset (Nuclei default
                    # for multiple words is OR) -> each word is an independent marker.
                    cond_label = cond if cond else "or/unset"
                    for w in words:
                        r = word_filter_reason(w)
                        if r:
                            out.append(dict(signal=None, value=w, matcher_type="word", part="body",
                                            condition=cond_label, source_path=src_path, entry_id=eid,
                                            status="filtered", reason=f"word failed filter: {r}"))
                        else:
                            out.append(dict(signal="html_markers", value=w.strip(), matcher_type="word",
                                            part="body", condition=cond_label, source_path=src_path,
                                            entry_id=eid, status="extracted", reason="word passed filters"))
                continue

            # Any other matcher type.
            out.append(dict(signal=None, value=norm(m.get("type")), matcher_type=mtype,
                            part=m.get("part"), condition=m.get("condition"),
                            source_path=src_path, entry_id=eid,
                            status="skipped", reason=f"unsupported matcher type: {mtype!r}"))
    return out


# --------------------------------------------------------------------------
# Build
# --------------------------------------------------------------------------
def _existing_keys(existing: Dict[str, Any], key: str, signal: str) -> set:
    man = (existing.get("manufacturers") or {}).get(key) or {}
    vals = man.get(signal) or []
    keys = set()
    for v in vals:
        if signal == "favicon_md5":
            keys.add(str(v).strip().lower())
        else:
            keys.add(_marker_dedup_key(v))
    return keys


def build(data: List[Dict[str, Any]], existing: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Return (candidate_yaml_dict, report_dict).

    candidate_yaml_dict: {"manufacturers": {key: {signal: [values...]}}} — only
    accepted, de-duplicated candidates from eligible camera-device entries.
    report_dict: full provenance (summary, per-entry routing, per-candidate rows).
    """
    known_brands = set((existing.get("manufacturers") or {}).keys())

    manufacturers: Dict[str, Dict[str, List[Any]]] = {}
    seen: Dict[Tuple[str, str], set] = {}          # (gama_key, signal) -> dedup keys added
    per_entry: List[Dict[str, Any]] = []
    cand_rows: List[Dict[str, Any]] = []
    counts = {
        "entries_examined": len(data),
        "matched_entries": 0,
        "by_classification": {},
        "candidates": {"accepted": {}, "duplicate": {}, "filtered": {}, "skipped": {}},
    }

    def bump(bucket: str, signal: str) -> None:
        d = counts["candidates"][bucket]
        d[signal] = d.get(signal, 0) + 1

    for entry in data:
        fields = entry_fields(entry)
        if not is_camera_entry(fields):
            continue
        counts["matched_entries"] += 1
        eid = fields["id"]
        classification, gama_key, reason = classify(eid)
        counts["by_classification"][classification] = counts["by_classification"].get(classification, 0) + 1
        eligible = (classification == "camera_device" and gama_key is not None and gama_key in known_brands)

        raw = extract_candidates(entry)
        entry_signal_summary = {"extracted": 0, "filtered": 0, "skipped": 0}
        for rec in raw:
            rec = dict(rec)
            rec["fh_vendor"] = fields["vendor"]
            rec["classification"] = classification
            rec["gama_key"] = gama_key
            rec["eligible_for_yaml"] = eligible

            if rec["status"] in ("skipped", "filtered"):
                entry_signal_summary[rec["status"]] += 1
                bump(rec["status"], rec.get("signal") or "none")
                cand_rows.append(rec)
                continue

            # status == extracted
            entry_signal_summary["extracted"] += 1
            signal = rec["signal"]
            if not eligible:
                rec["final_status"] = "review_only"
                rec["final_reason"] = f"not eligible for YAML ({classification}/{gama_key})"
                cand_rows.append(rec)
                continue

            # Dedup against existing signatures + already-added candidates.
            dk = (str(rec["value"]).strip().lower() if signal == "favicon_md5"
                  else _marker_dedup_key(rec["value"]))
            existing_keys = _existing_keys(existing, gama_key, signal)
            added = seen.setdefault((gama_key, signal), set())
            if dk in existing_keys:
                rec["final_status"] = "duplicate"
                rec["final_reason"] = "already present in signatures.yaml"
                bump("duplicate", signal)
                cand_rows.append(rec)
                continue
            if dk in added:
                rec["final_status"] = "duplicate"
                rec["final_reason"] = "duplicate within import"
                bump("duplicate", signal)
                cand_rows.append(rec)
                continue

            added.add(dk)
            manufacturers.setdefault(gama_key, {}).setdefault(signal, []).append(rec["value"])
            rec["final_status"] = "accepted"
            rec["final_reason"] = "accepted into candidate YAML"
            bump("accepted", signal)
            cand_rows.append(rec)

        per_entry.append({
            "id": eid,
            "fh_vendor": fields["vendor"],
            "classification": classification,
            "gama_key": gama_key,
            "eligible_for_yaml": eligible,
            "reason": reason,
            "matcher_summary": entry_signal_summary,
        })

    # Order manufacturers and signals deterministically for a stable file.
    ordered_man: Dict[str, Any] = {}
    for key in sorted(manufacturers):
        ordered_man[key] = {}
        for signal in ("html_markers", "http_server", "favicon_md5"):
            if signal in manufacturers[key]:
                ordered_man[key][signal] = manufacturers[key][signal]

    candidate_yaml = {"manufacturers": ordered_man}

    # Per-manufacturer accepted counts for the summary.
    man_counts = {k: {s: len(v) for s, v in sig.items()} for k, sig in ordered_man.items()}
    counts["candidate_manufacturers"] = man_counts

    report = {
        "source": "FingerprintHub v4 (vendor/FingerprintHub/web_fingerprint_v4.json)",
        "note": "Candidates for manual review only. Presence in FingerprintHub is NOT verification.",
        "summary": counts,
        "entries": sorted(per_entry, key=lambda r: r["id"]),
        "candidates": cand_rows,
    }
    return candidate_yaml, report


# --------------------------------------------------------------------------
# I/O / main
# --------------------------------------------------------------------------
def _load_json(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _load_signatures(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _yaml_header(kind: str) -> str:
    return (
        f"# {kind}\n"
        "# GENERATED by scripts/import_fingerprinthub.py from FingerprintHub v4.\n"
        "# Review-only candidates; NOT merged into signatures.yaml and NOT verified.\n"
        "# Do not edit by hand; regenerate instead.\n"
    )


def main() -> int:
    for out in (OUT_CANDIDATES, OUT_REPORT):
        if os.path.exists(out):
            print(f"REFUSING TO OVERWRITE existing output: {out}", file=sys.stderr)
            print("Delete it first if you intend to regenerate.", file=sys.stderr)
            return 2

    data = _load_json(VENDOR_JSON)
    existing = _load_signatures(SIGNATURES_YAML)
    candidate_yaml, report = build(data, existing)

    with open(OUT_CANDIDATES, "w", encoding="utf-8") as f:
        f.write(_yaml_header("Candidate signatures (review only)"))
        yaml.safe_dump(candidate_yaml, f, sort_keys=False, allow_unicode=True,
                       default_flow_style=False, width=4096)
    with open(OUT_REPORT, "w", encoding="utf-8") as f:
        f.write(_yaml_header("Provenance / review report"))
        yaml.safe_dump(report, f, sort_keys=False, allow_unicode=True,
                       default_flow_style=False, width=4096)

    s = report["summary"]
    print(f"examined={s['entries_examined']} matched={s['matched_entries']}")
    print(f"by_classification={s['by_classification']}")
    print(f"candidate counts={s['candidates']}")
    print(f"candidate manufacturers={s['candidate_manufacturers']}")
    print(f"wrote {OUT_CANDIDATES}")
    print(f"wrote {OUT_REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
