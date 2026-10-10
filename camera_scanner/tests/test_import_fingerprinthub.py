"""
Focused tests for the offline FingerprintHub v4 extraction tool.

All inputs are synthetic in-memory fixtures; no vendor dataset, no file I/O, no
network. Covers: keyword filtering, word first-pass filters, dedup (vs existing
signatures and within the import), MMH3/integer favicon rejection, valid MD5
handling, ambiguous/platform routing, and matcher AND/OR semantics.
"""

import pytest

from camera_scanner.scripts import import_fingerprinthub as imp


# --- small unit helpers -----------------------------------------------------

def test_is_valid_md5_accepts_32hex():
    assert imp.is_valid_md5("ed8cf53ef6836184587ee3a987be074a")
    assert imp.is_valid_md5("ED8CF53EF6836184587EE3A987BE074A")  # case-normalised


@pytest.mark.parametrize("bad", [
    "2019488876",      # mmh3 positive int
    "-808437027",      # mmh3 negative int
    "89b932fcc47cf4ca3faadb0cfdef89c",   # 31 chars
    "89b932fcc47cf4ca3faadb0cfdef89cfa", # 33 chars
    "zzz932fcc47cf4ca3faadb0cfdef89cf",  # non-hex
    "", None, 12345,
])
def test_is_valid_md5_rejects_non_md5(bad):
    assert not imp.is_valid_md5(bad)


def test_word_filter_reasons():
    assert imp.word_filter_reason("vm5.0") == "too_short(<6)"        # 5 chars
    assert imp.word_filter_reason("server") == "generic_word"
    assert imp.word_filter_reason("SERVER") == "generic_word"        # case-insensitive
    assert imp.word_filter_reason("cve-2021-1234 marker") == "bad_substr:cve"
    assert imp.word_filter_reason("some_sqlinject_here") == "bad_substr:inject"
    assert imp.word_filter_reason("nvrsolo") is None                 # passes


def test_is_camera_entry_keyword_pass():
    assert imp.is_camera_entry({"id": "x", "name": "", "product": "", "vendor": "hikvision"})
    assert imp.is_camera_entry({"id": "tbk-dvr", "name": "", "product": "", "vendor": "00_unknown"})
    assert not imp.is_camera_entry({"id": "wordpress", "name": "WP", "product": "wp", "vendor": "wp"})


# --- matcher extraction / semantics ----------------------------------------

def _entry(eid, matchers, path="/"):
    return {"id": eid, "info": {"metadata": {}}, "http": [{"path": [path], "matchers": matchers}]}


def test_regex_matcher_is_skipped():
    recs = imp.extract_candidates(_entry("x", [{"type": "regex", "regex": ["(?mi)<title>x</title>"]}]))
    assert len(recs) == 1
    assert recs[0]["status"] == "skipped"
    assert recs[0]["matcher_type"] == "regex"


def test_favicon_mmh3_rejected_md5_extracted():
    recs = imp.extract_candidates(_entry("x", [
        {"type": "favicon", "hash": ["2019488876"]},
        {"type": "favicon", "hash": ["ed8cf53ef6836184587ee3a987be074a"]},
    ]))
    by_status = {(r["matcher_type"], r["status"]): r for r in recs}
    mmh3 = [r for r in recs if r["value"] == "2019488876"][0]
    md5 = [r for r in recs if r["signal"] == "favicon_md5"][0]
    assert mmh3["status"] == "skipped" and "mmh3" in mmh3["reason"]
    assert md5["status"] == "extracted" and md5["value"] == "ed8cf53ef6836184587ee3a987be074a"


def test_header_word_is_review_not_http_server():
    recs = imp.extract_candidates(_entry("x", [
        {"type": "word", "part": "header", "words": ["server: face-webs"]},
    ]))
    assert len(recs) == 1
    assert recs[0]["status"] == "skipped"
    assert recs[0]["signal"] is None
    assert "header word" in recs[0]["reason"]


def test_and_condition_makes_single_list_marker():
    recs = imp.extract_candidates(_entry("x", [
        {"type": "word", "condition": "and", "words": ["<li id=\"dss-help\">", "dss-assistant-token"]},
    ]))
    ex = [r for r in recs if r["status"] == "extracted"]
    assert len(ex) == 1
    assert ex[0]["signal"] == "html_markers"
    assert isinstance(ex[0]["value"], list) and len(ex[0]["value"]) == 2


def test_and_group_dropped_if_member_fails_filter():
    # "ip" is a generic stopword -> the whole AND group is dropped (not partially kept).
    recs = imp.extract_candidates(_entry("x", [
        {"type": "word", "condition": "and", "words": ["a-very-specific-marker", "ip"]},
    ]))
    assert all(r["status"] != "extracted" for r in recs)
    assert any(r["status"] == "filtered" and "AND-group dropped" in r["reason"] for r in recs)


def test_or_unset_multi_words_become_separate_markers():
    recs = imp.extract_candidates(_entry("x", [
        {"type": "word", "words": ["marker-one-long", "marker-two-long"]},  # no condition -> OR
    ]))
    ex = [r for r in recs if r["status"] == "extracted"]
    assert len(ex) == 2
    assert all(isinstance(r["value"], str) for r in ex)


# --- build(): routing, eligibility, dedup ----------------------------------

def _existing():
    return {"manufacturers": {
        "avtech": {"html_markers": ["--- video web server ---"], "favicon_md5": []},
        "amcrest": {"html_markers": ["/amcrest"], "favicon_md5": []},
        "hikvision": {"html_markers": ["hikvision"], "favicon_md5": ["89b932fcc47cf4ca3faadb0cfdef89cf"]},
        "nuuo": {"html_markers": ["network video recorder login"]},
    }}


def test_build_accepts_eligible_device_candidate():
    data = [_entry("avtech-video-web-server", [
        {"type": "word", "words": ["/av732e/setup.exe"]},
        {"type": "favicon", "hash": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]},
    ])]
    # give the entry camera metadata so is_camera_entry() matches
    data[0]["info"]["metadata"] = {"vendor": "00_unknown", "product": "avtech-video-web-server"}
    cand, report = imp.build(data, _existing())
    av = cand["manufacturers"]["avtech"]
    assert "/av732e/setup.exe" in av["html_markers"]
    assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in av["favicon_md5"]


def test_build_dedup_against_existing_signatures():
    # Hikvision favicon already present -> must be reported duplicate, not added.
    data = [_entry("hikvision-ip-camera", [
        {"type": "favicon", "hash": ["89b932fcc47cf4ca3faadb0cfdef89cf"]},
    ])]
    data[0]["info"]["metadata"] = {"vendor": "00_unknown", "product": "hikvision-ip-camera"}
    cand, report = imp.build(data, _existing())
    assert "hikvision" not in cand["manufacturers"]  # nothing new added
    dups = [r for r in report["candidates"] if r.get("final_status") == "duplicate"]
    assert any("signatures.yaml" in r["final_reason"] for r in dups)


def test_build_dedup_within_import():
    data = [
        _entry("nvrsolo_firmware", [{"type": "word", "words": ["nvrsolo"]}]),
        _entry("nvr301-04s2-p4", [{"type": "word", "words": ["nvrsolo"]}]),  # same token, same brand? no
    ]
    data[0]["info"]["metadata"] = {"vendor": "nuuo", "product": "nvrsolo_firmware"}
    data[1]["info"]["metadata"] = {"vendor": "uniview", "product": "nvr301-04s2-p4"}
    # Route both to the SAME brand to force an in-import duplicate.
    data[1]["id"] = "nvrsolo_firmware"
    cand, report = imp.build(data, _existing())
    assert cand["manufacturers"]["nuuo"]["html_markers"].count("nvrsolo") == 1
    assert any(r.get("final_reason") == "duplicate within import" for r in report["candidates"])


def test_build_platform_and_framework_not_written_to_yaml():
    data = [
        _entry("hikvision-ivms", [{"type": "word", "words": ["<h1 class=\"logo\">mgmt-platform</h1>"]}]),
        _entry("apache-axis2", [{"type": "word", "condition": "and", "words": ["axis2-admin", "axis2-web"]}]),
    ]
    data[0]["info"]["metadata"] = {"vendor": "00_unknown", "product": "hikvision-ivms"}
    data[1]["info"]["metadata"] = {"vendor": "apache", "product": "axis2"}
    cand, report = imp.build(data, _existing())
    # Neither platform nor framework contributes to the candidate YAML.
    assert cand["manufacturers"] == {} or all(
        k not in cand["manufacturers"] for k in ("hikvision", "apache", "axis2"))
    # But they ARE recorded in the report (not silently discarded).
    ids = {e["id"] for e in report["entries"]}
    assert {"hikvision-ivms", "apache-axis2"} <= ids
    cls = {e["id"]: e["classification"] for e in report["entries"]}
    assert cls["hikvision-ivms"] == "platform_software"
    assert cls["apache-axis2"] == "framework_other"


def test_build_ambiguous_unmapped_recorded_not_yaml():
    data = [_entry("tbk-dvr", [{"type": "word", "words": ["<div class='log-dvr-logo'>"]}])]
    data[0]["info"]["metadata"] = {"vendor": "00_unknown", "product": "tbk-dvr"}
    cand, report = imp.build(data, _existing())
    assert cand["manufacturers"] == {}
    e = [x for x in report["entries"] if x["id"] == "tbk-dvr"][0]
    assert e["gama_key"] is None
    assert e["classification"] == "camera_device"  # it IS a device, just unmapped brand


def test_unclassified_entry_degrades_to_ambiguous():
    assert imp.classify("totally-new-camera-id-not-in-table")[0] == "ambiguous"
    assert imp.classify("totally-new-camera-id-not-in-table")[1] is None
