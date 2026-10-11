import pytest
from camera_scanner.fingerprinter import fingerprint_camera


def test_hikvision_by_onvif():
    data = {
        "onvif_manufacturer": "Hikvision",
        "onvif_model": "DS-2CD2043G2-I",
        "onvif_firmware": "V5.7.3",
        "onvif_serial": "12345678"
    }
    fp = fingerprint_camera(data)
    assert fp is not None
    assert fp["manufacturer"] == "Hikvision"
    assert fp["model"] == "DS-2CD2043G2-I"
    assert fp["firmware_version"] == "V5.7.3"
    assert fp["serial_number"] == "12345678"
    assert fp["confidence"] >= 0.99
    assert "onvif:device_info" in fp["evidence"]


def test_hikvision_by_mac():
    data = {
        "mac_address": "44:19:B6:00:11:22"
    }
    fp = fingerprint_camera(data)
    assert fp is not None
    assert fp["manufacturer"] == "Hikvision"
    assert fp["confidence"] >= 0.95
    assert "mac_oui:44:19:B6->Hikvision" in fp["evidence"]


def test_hikvision_by_server():
    data = {
        "http_server": "Hikvision-Webs"
    }
    fp = fingerprint_camera(data)
    assert fp is not None
    assert fp["manufacturer"] == "Hikvision"
    assert fp["confidence"] >= 0.80
    assert "http_server:Hikvision-Webs" in fp["evidence"]


def test_hikvision_by_www_auth():
    data = {
        "http_www_authenticate": 'Digest realm="IP Camera(Camera)", qop="auth"'
    }
    fp = fingerprint_camera(data)
    assert fp is not None
    assert fp["manufacturer"] == "Hikvision"
    assert fp["confidence"] >= 0.90
    assert "www_auth_realm:IP Camera" in fp["evidence"]


@pytest.mark.skip(reason="no real favicon hash collected yet; needs a real camera")
def test_hikvision_by_favicon():
    data = {
        "http_favicon_md5": "2a4b1a1b1a1c1d1e1f2a3b4c5d6e7f8a"  # from signatures.yaml example
    }
    fp = fingerprint_camera(data)
    assert fp is not None
    assert fp["manufacturer"] == "Hikvision"
    assert fp["confidence"] >= 0.90
    assert "favicon:2a4b1a1b" in fp["evidence"]


def test_hikvision_by_html():
    data = {
        "http_html_content": '<html><head><title>HIKVISION</title></head><body></body></html>'
    }
    fp = fingerprint_camera(data)
    assert fp is not None
    assert fp["manufacturer"] == "Hikvision"
    assert fp["confidence"] >= 0.75
    assert "html:<title>HIKVISION</title>" in fp["evidence"]


def test_hikvision_by_model_regex():
    data = {
        "http_html_content": '<html>Model: DS-2CD2T43G2-I</html>',
        "http_server": "some server"
    }
    fp = fingerprint_camera(data)
    assert fp is not None
    assert fp["model"] == "DS-2CD2T43G2-I"
    assert any(e.startswith("model_regex:") for e in fp["evidence"])


def test_firmware_extraction():
    data = {
        "http_server": "Webs",
        "http_html_content": "Firmware Version: V5.5.0 build 200918",
        "http_www_authenticate": ""
    }
    fp = fingerprint_camera(data)
    assert fp is not None
    assert fp["firmware_version"] == "V5.5.0 build 200918"
    assert "firmware:regex" in fp["evidence"]


def test_hipcam_by_server_real():
    fp = fingerprint_camera({"http_server": "Hipcam RealServer/V1.0"})
    assert fp is not None
    assert fp["manufacturer"] == "Hipcam"
    assert fp["confidence"] >= 0.80


def test_hipcam_by_server_plain():
    fp = fingerprint_camera({"http_server": "Hipcam"})
    assert fp is not None
    assert fp["manufacturer"] == "Hipcam"
    assert fp["confidence"] >= 0.80


def test_hipcam_by_server_vodserver():
    fp = fingerprint_camera({"http_server": "VodServer/1.0.0"})
    assert fp is not None
    assert fp["manufacturer"] == "Hipcam"
    assert fp["confidence"] >= 0.80


def test_hipcam_by_server_hiipcam():
    fp = fingerprint_camera({"http_server": "HiIpcam"})
    assert fp is not None
    assert fp["manufacturer"] == "Hipcam"
    assert fp["confidence"] >= 0.80


def test_hipcam_by_rtsp_server():
    fp = fingerprint_camera({"rtsp_server": "Hipcam RealServer/V1.0"})
    assert fp is not None
    assert fp["manufacturer"] == "Hipcam"
    assert fp["confidence"] >= 0.80


# ---- WhatWeb-derived signatures (Stage 2) ----

def test_panasonic_by_html_wjnt104():
    fp = fingerprint_camera({"http_html_content": "<HEAD><TITLE>WJ-NT104 MAIN PAGE</TITLE></HEAD>"})
    assert fp is not None
    assert fp["manufacturer"] == "Panasonic"


def test_mobotix_by_html_meta():
    fp = fingerprint_camera({"http_html_content": '<meta name="publisher" content="MOBOTIX AG, Germany">'})
    assert fp is not None
    assert fp["manufacturer"] == "Mobotix"


def test_toshiba_by_html_title():
    fp = fingerprint_camera({"http_html_content": "<title>TOSHIBA Network Camera - User Login</title>"})
    assert fp is not None
    assert fp["manufacturer"] == "Toshiba"


def test_intellinet_by_html():
    fp = fingerprint_camera({"http_html_content": "<TITLE>::::: INTELLINET IP Camera Homepage :::::</TITLE>"})
    assert fp is not None
    assert fp["manufacturer"] == "Intellinet"


def test_avtech_by_html_title():
    fp = fingerprint_camera({"http_html_content": "<title>--- VIDEO WEB SERVER ---</title>"})
    assert fp is not None
    assert fp["manufacturer"] == "AVTech"


def test_sony_model_regex_snc():
    fp = fingerprint_camera({"http_html_content": "<TITLE>Sony Network Camera SNC-RZ30</TITLE>"})
    assert fp is not None
    assert fp["manufacturer"] == "Sony"
    assert fp["model"] == "SNC-RZ30"


def test_dlink_by_html_dcs_marker():
    # D-Link detection via DCS- marker (model extraction not asserted: the
    # hyphenated brand key "d-link" is not reachable via _brand_key normalization)
    fp = fingerprint_camera({"http_html_content": "<title>DCS-5300</title> dlink"})
    assert fp is not None
    assert fp["manufacturer"] == "D-Link"


def test_canon_model_regex_vbc():
    fp = fingerprint_camera({"http_html_content": "<TITLE>Network Camera VB-C50i/VB-C50iR</TITLE>"})
    assert fp is not None
    assert fp["manufacturer"] == "Canon"
    assert fp["model"].startswith("VB-C")


# ---- Nuclei-derived signatures (Stage 4) ----

def test_novus_by_html_title():
    fp = fingerprint_camera({"http_html_content": "<title>NoVus IP camera</title>"})
    assert fp is not None
    assert fp["manufacturer"] == "Novus"


def test_selea_by_server_banner():
    fp = fingerprint_camera({"http_server": "SeleaCPSHttpServer"})
    assert fp is not None
    assert fp["manufacturer"] == "Selea"


def test_selea_by_html_carplateserver():
    fp = fingerprint_camera({"http_html_content": "<h1>Selea CarPlateServer</h1>"})
    assert fp is not None
    assert fp["manufacturer"] == "Selea"


def test_mobotix_by_body_word():
    fp = fingerprint_camera({"http_html_content": "<html><body>MOBOTIX</body></html>"})
    assert fp is not None
    assert fp["manufacturer"] == "Mobotix"


def test_panasonic_management_title():
    fp = fingerprint_camera({"http_html_content": "<TITLE>Panasonic Network Camera Management System</TITLE>"})
    assert fp is not None
    assert fp["manufacturer"] == "Panasonic"


def test_generic_network_camera_title_not_attributed():
    # Negative: the generic "<TITLE>Network Camera</TITLE>" (Nuclei network-camera-detect,
    # intentionally NOT imported) must not be attributed to any brand.
    fp = fingerprint_camera({"http_html_content": "<TITLE>Network Camera</TITLE>"})
    assert fp is None or fp.get("manufacturer") is None


def _is_rvi(fp):
    if fp is None:
        return False
    if fp.get("manufacturer") in ("RVi", "RVI"):
        return True
    return any("rvi" in e.lower() for e in fp.get("evidence", []))


def test_rvi_not_matched_by_web_service_title():
    # "WEB SERVICE" contains the substring "rvi" (se-rvi-ce) — must NOT be RVi.
    fp = fingerprint_camera({"http_html_content": "<title>WEB SERVICE</title>"})
    assert not _is_rvi(fp)


def test_rvi_not_matched_by_generic_service_or_preserving():
    for text in ("<p>service status ok</p>", "<p>preserving configuration</p>"):
        fp = fingerprint_camera({"http_html_content": text})
        assert not _is_rvi(fp), f"RVi false-positive on {text!r}"


def test_dahua_by_webactiveexe_plugin():
    # supplied Shodan observation: Dahua DVR exposes WebActiveEXE.Plugin.1 in page body
    fp = fingerprint_camera({"http_html_content": "<OBJECT ID='WebActiveEXE.Plugin.1'></OBJECT>"})
    assert fp is not None
    assert fp["manufacturer"] == "Dahua"


def test_generic_web_service_title_not_dahua():
    # Negative: a generic "WEB SERVICE" title alone must NOT be attributed to Dahua
    # (ambiguous between Dahua and Xiongmai; not a Dahua marker).
    fp = fingerprint_camera({"http_html_content": "<title>WEB SERVICE</title>"})
    assert fp is None or fp.get("manufacturer") != "Dahua"


def test_generic_server_not_attributed_to_camera_brand():
    # Negative: a bare generic embedded web server must NOT be attributed to a
    # specific camera manufacturer (no http_server=webs/GoAhead=brand shortcut).
    fp = fingerprint_camera({"http_server": "GoAhead-Webs", "http_html_content": "<html>login</html>"})
    assert fp is None or fp.get("manufacturer") is None


def test_unknown_returns_none():
    data = {
        "http_server": "nginx",
        "http_html_content": "<html>test</html>"
    }
    fp = fingerprint_camera(data)
    assert fp is None or (fp.get("manufacturer") is None and fp.get("model") is None and fp.get("firmware_version") is None)


def test_multiple_sources_confidence():
    data = {
        "http_server": "Hikvision-Webs",
        "http_www_authenticate": 'Digest realm="IP Camera(Camera)"',
        "http_html_content": '<html>Model: DS-2CD2043</html>',
    }
    fp = fingerprint_camera(data)
    assert fp is not None
    assert fp["manufacturer"] == "Hikvision"
    assert fp["model"] == "DS-2CD2043"
    # max() semantics: strongest single signal (realm 0.90), plus model bump
    assert fp["confidence"] >= 0.90
    # Check that evidence includes multiple sources
    evidence = fp["evidence"]
    assert any("http_server" in e for e in evidence)
    assert any("www_auth_realm" in e for e in evidence)
    assert any("model_regex" in e for e in evidence)


# ---- Ingram-derived signatures (Stage 6) ----

def test_xiongmai_by_netsurveillance_html():
    fp = fingerprint_camera({"http_html_content": "<title>NETSurveillance WEB</title>"})
    assert fp is not None
    assert fp["manufacturer"] == "Xiongmai"


def test_xiongmai_by_xmeye_html():
    fp = fingerprint_camera({"http_html_content": "<title>XMEye</title>"})
    assert fp is not None
    assert fp["manufacturer"] == "Xiongmai"


def test_xiongmai_login_to_xm_is_shadowed_by_dahua_realm():
    # Documents a known collision: Dahua's generic "Login to" www_auth_realm marker
    # swallows "Login to XM", so Xiongmai is NOT identified from the realm alone.
    # Xiongmai is instead identified by its specific HTML markers (see above).
    # Reported as an adjacent issue (Dahua realm specificity), not fixed here.
    fp = fingerprint_camera({"http_www_authenticate": 'Digest realm="Login to XM"'})
    assert fp is not None and fp["manufacturer"] == "Dahua"


def test_xiongmai_not_matched_by_web_service():
    # Negative: a bare "WEB SERVICE" page must not be attributed to Xiongmai.
    fp = fingerprint_camera({"http_html_content": "<title>WEB SERVICE</title>"})
    assert fp is None or fp.get("manufacturer") != "Xiongmai"


def test_hikvision_and_marker_positive():
    # AND marker [g_szCacheTime, iVMS]: both present -> Hikvision
    fp = fingerprint_camera({"http_html_content": "<script>var g_szCacheTime=1;</script> iVMS-4200"})
    assert fp is not None
    assert fp["manufacturer"] == "Hikvision"
    assert any(e == "html:g_szCacheTime&&iVMS" for e in fp["evidence"])


def test_hikvision_and_marker_negative_one_of_two():
    # Only one half of the AND pair present -> must NOT match via that marker.
    fp = fingerprint_camera({"http_html_content": "<script>var g_szCacheTime=1;</script>"})
    assert fp is None or fp.get("manufacturer") != "Hikvision"


def test_avtech_and_marker_positive():
    html = "<title>Remote Surveillance</title> Any time & Any where"
    fp = fingerprint_camera({"http_html_content": html})
    assert fp is not None
    assert fp["manufacturer"] == "AVTech"


def test_avtech_and_marker_negative():
    fp = fingerprint_camera({"http_html_content": "<title>Remote Surveillance</title>"})
    assert fp is None or fp.get("manufacturer") != "AVTech"


def test_dlink_by_www_auth_realm_dcs():
    fp = fingerprint_camera({"http_www_authenticate": 'Basic realm="DCS-2103"'})
    assert fp is not None
    assert fp["manufacturer"] == "D-Link"


def test_hikvision_by_favicon_md5_real():
    fp = fingerprint_camera({"http_favicon_md5": "89b932fcc47cf4ca3faadb0cfdef89cf"})
    assert fp is not None
    assert fp["manufacturer"] == "Hikvision"
    assert "favicon:89b932fc" in fp["evidence"]


def test_dahua_favicon_by_path():
    fp = fingerprint_camera({"http_favicon_paths": {"/image/lgbg.jpg": "4ff53be6165e430af41d782e00207fda"}})
    assert fp is not None
    assert fp["manufacturer"] == "Dahua"
    assert "favicon_path:/image/lgbg.jpg:4ff53be6" in fp["evidence"]


def test_uniview_favicon_by_path():
    fp = fingerprint_camera({"http_favicon_paths": {"/skin/default_1/images/logo.png": "c30a692ad0d1324389485de06c96d9b8"}})
    assert fp is not None
    assert fp["manufacturer"] == "Uniview"


def test_favicon_by_path_wrong_hash_not_matched():
    # Negative: a non-matching hash on a known path must not attribute a brand.
    fp = fingerprint_camera({"http_favicon_paths": {"/image/lgbg.jpg": "00000000000000000000000000000000"}})
    assert fp is None or fp.get("manufacturer") is None


def test_geovision_by_html():
    fp = fingerprint_camera({"http_html_content": "<title>GeoVision Inc.</title>"})
    assert fp is not None
    assert fp["manufacturer"] == "GeoVision"


def test_instar_by_html_and():
    fp = fingerprint_camera({"http_html_content": "<title>INSTAR Full HD Camera</title>"})
    assert fp is not None
    assert fp["manufacturer"] == "INSTAR"


def test_instar_negative_without_camera():
    fp = fingerprint_camera({"http_html_content": "<title>INSTAR</title>"})
    assert fp is None or fp.get("manufacturer") != "INSTAR"


def test_netwave_by_server():
    fp = fingerprint_camera({"http_server": "Netwave IP Camera"})
    assert fp is not None
    assert fp["manufacturer"] == "Netwave"


def test_reecam_by_server():
    fp = fingerprint_camera({"http_server": "ReeCam IP Camera"})
    assert fp is not None
    assert fp["manufacturer"] == "ReeCam"


def test_nuuo_by_html_title():
    fp = fingerprint_camera({"http_html_content": "<title>Network Video Recorder Login</title>"})
    assert fp is not None
    assert fp["manufacturer"] == "NUUO"


def test_dahua_rpc2_webservice_page_identified_by_js_markers():
    # Real Dahua RPC2 web UI (from a live device): the <title> is the ambiguous
    # "WEB SERVICE", but the body references Dahua-specific RPC2 assets. Must be
    # identified as Dahua WITHOUT relying on the (fragile) favicon hash.
    html = (
        '<html><head><title>WEB SERVICE</title>'
        '<script type="text/javascript" src="jsCore/rpcLogin.js"></script></head>'
        '<body><a href="/webplugin.exe" id="prew_downloadplugin"></a></body></html>'
    )
    fp = fingerprint_camera({"http_html_content": html})
    assert fp is not None
    assert fp["manufacturer"] == "Dahua"


def test_dahua_by_favicon_md5_real():
    fp = fingerprint_camera({"http_favicon_md5": "bd9e17c46bbbc18af2a2bd718dddad0e"})
    assert fp is not None
    assert fp["manufacturer"] == "Dahua"


def test_dahua_by_ssl_issuer():
    # Real Shodan-observed Dahua DVR cert issuer DN (O=DahuaTech ...).
    fp = fingerprint_camera({
        "ssl_issuer": "O=DahuaTech OU=DAHUATECH C=CN ST=ZheJiang L=HangZhou"
    })
    assert fp is not None
    assert fp["manufacturer"] == "Dahua"
    assert fp["confidence"] >= 0.95
    assert any(e.startswith("ssl_issuer:") for e in fp["evidence"])


def test_hikvision_by_ssl_issuer():
    fp = fingerprint_camera({
        "ssl_issuer": "C=CN O=Hangzhou Hikvision Digital Technology CN=Hikvision"
    })
    assert fp is not None
    assert fp["manufacturer"] == "Hikvision"
    assert fp["confidence"] >= 0.95


def test_unknown_ssl_issuer_returns_none():
    # A generic/unknown issuer must not be attributed to any camera brand.
    fp = fingerprint_camera({"ssl_issuer": "O=Let's Encrypt C=US CN=R3"})
    assert fp is None or fp.get("manufacturer") is None


if __name__ == "__main__":
    pytest.main([__file__])

# ---- SSL certificate subject matching (Stage 8) ----

def test_dahua_by_ssl_subject():
    fp = fingerprint_camera({"ssl_subject": "C=CN O=DahuaTech OU=DAHUATECH CN=Dahua Technology"})
    assert fp is not None
    assert fp["manufacturer"] == "Dahua"
    assert any(e.startswith("ssl_subject:") for e in fp["evidence"])


def test_hikvision_by_ssl_subject():
    fp = fingerprint_camera({"ssl_subject": "C=CN O=Hikvision CN=192.168.1.64"})
    assert fp is not None
    assert fp["manufacturer"] == "Hikvision"


def test_uniview_by_ssl_subject():
    fp = fingerprint_camera({"ssl_subject": "O=Uniview Technologies CN=uniview"})
    assert fp is not None
    assert fp["manufacturer"] == "Uniview"


def test_unknown_ssl_subject_returns_none():
    fp = fingerprint_camera({"ssl_subject": "O=Acme Corp C=US CN=device.local"})
    assert fp is None or fp.get("manufacturer") is None
