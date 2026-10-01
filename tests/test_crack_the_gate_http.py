# -*- coding: utf-8 -*-
"""
اختبار شامل: حلّ Crack the Gate عبر مسار HTTP الفعلي للمحرك (POST /web/session-audit)
مع تعيين المضيف crack.cylabacademy.net إلى الخادم الوهمي المحلي — للتأكد أن النتيجة
تُعرض عبر المسار الحقيقي دون أن يستبدلها محلل آخر (Old Sessions مثلًا).
"""
import sys
import json
import threading
import importlib.util
import http.client
import urllib.request
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "local-engine"), str(ROOT / "tests")]

import web_session_audit as w          # noqa: E402
import mock_crack_the_gate as mock      # noqa: E402

spec = importlib.util.spec_from_file_location("falcon", str(ROOT / "local-engine/falcon_local.py"))
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)

server, base = mock.start_server(mode="ok")
target_port = int(base.rstrip("/").rsplit(":", 1)[1])
_real = http.client.HTTPConnection
MAPPED = "crack.cylabacademy.net"


class LocalConnection(_real):
    def __init__(self, host, port=None, **kw):
        super().__init__("127.0.0.1" if host == MAPPED else host,
                         target_port if host == MAPPED else port, **kw)


engine_server = engine.ThreadingHTTPServer(("127.0.0.1", 0), engine.H)
threading.Thread(target=engine_server.serve_forever, daemon=True).start()
url = "http://127.0.0.1:" + str(engine_server.server_port)

try:
    health = json.load(urllib.request.urlopen(url + "/health"))
    assert health["version"] == "2.30.0", health

    req = urllib.request.Request(
        url + "/web/session-audit",
        data=json.dumps({"url": f"http://{MAPPED}:{target_port}/", "challenge_text": "Use player@example.org"}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with patch.object(w.http.client, "HTTPConnection", LocalConnection):
        with urllib.request.urlopen(req) as r:
            data = json.load(r)
            assert r.headers["Access-Control-Allow-Origin"] == "https://sc1561.github.io"

    assert data["ok"] is True, data
    assert data["challenge"] == "Crack the Gate", data["challenge"]
    assert data["analyzer"] == "crack-the-gate", data["analyzer"]
    assert data["success"] is True, data
    assert data["flag"] == mock.FLAG, data["flag"]
    assert data["discovered"]["email_used"] == "player@example.org"
    assert data["discovered"]["dev_header"]["name"] == "X-Dev-Access"
    # لم يستبدلها محلل آخر ولم تُطلب مسارات Old Sessions
    from urllib.parse import urlsplit
    paths = [urlsplit(s["url"]).path for s in data["steps"]]
    assert "/register" not in paths and "/sessions" not in paths, paths
    assert data["target"].endswith(f":{target_port}/"), data["target"]

    print("PASS: Crack the Gate solved via engine HTTP path, CORS present, "
          "correct analyzer, real flag, no /register or /sessions, target scoped")
finally:
    engine_server.shutdown()
    server.shutdown()
