from camera_scanner.capture import (
    ffmpeg_snapshot, ffmpeg_record, curl_snapshot, capture_command,
    _inject_rtsp_credentials,
)


def test_ffmpeg_snapshot_rtsp_injects_creds_and_single_frame():
    args = ffmpeg_snapshot("rtsp://host:554/cam/realmonitor?channel=1&subtype=0",
                           "snap.jpg", "admin", "secret")
    s = " ".join(args)
    assert "-rtsp_transport tcp" in s
    assert "-frames:v 1" in s
    assert "rtsp://admin:secret@host:554/" in s
    assert args[-1] == "snap.jpg"


def test_ffmpeg_snapshot_does_not_double_inject_creds():
    args = ffmpeg_snapshot("rtsp://u:p@host/cam", user="x", password="y")
    s = " ".join(args)
    assert "rtsp://u:p@host/cam" in s
    assert "x:y@" not in s


def test_curl_snapshot_uses_digest_auth():
    args = curl_snapshot("http://host/cgi-bin/snapshot.cgi?channel=1",
                         "snap.jpg", "admin", "secret")
    s = " ".join(args)
    assert "--digest" in s
    assert "-u admin:secret" in s
    assert args[-1] == "snap.jpg"


def test_curl_snapshot_no_creds_no_auth_flags():
    args = curl_snapshot("http://host/img.jpg")
    assert "--digest" not in args and "-u" not in args


def test_capture_command_auto_rtsp_is_ffmpeg():
    cmd = capture_command("rtsp://host/cam", user="a", password="b")
    assert cmd.startswith("ffmpeg ")


def test_capture_command_auto_http_is_curl():
    cmd = capture_command("http://host/cgi-bin/snapshot.cgi", user="a", password="b")
    assert cmd.startswith("curl ")


def test_capture_command_shell_quotes_ampersand():
    cmd = capture_command("rtsp://host/cam?channel=1&subtype=0")
    assert "'rtsp://host/cam?channel=1&subtype=0'" in cmd


def test_rtsp_credentials_are_url_encoded():
    url = _inject_rtsp_credentials("rtsp://host/cam", "user@x", "p/w")
    assert "user%40x:p%2Fw@host" in url


def test_ffmpeg_record_copies_stream():
    args = ffmpeg_record("rtsp://host/cam", "clip.mp4", seconds=5)
    s = " ".join(args)
    assert "-t 5" in s and "-c copy" in s and args[-1] == "clip.mp4"
