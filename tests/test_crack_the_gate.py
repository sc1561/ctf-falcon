# -*- coding: utf-8 -*-
"""
اختبارات محلل Crack the Gate عبر مسار run_audit المباشر (بلا محرك HTTP).
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "local-engine"))
sys.path.insert(0, HERE)

import web_session_audit as w          # noqa: E402
import mock_crack_the_gate as mock      # noqa: E402

PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}")


def paths(res):
    from urllib.parse import urlsplit
    return [urlsplit(s["url"]).path for s in res["steps"]]


def test_happy_path():
    print("\n[1] المسار الناجح (ok)")
    srv, base = mock.start_server(mode="ok")
    try:
        res = w.run_audit(base)
    finally:
        srv.shutdown()

    check("نوع التحدي = Crack the Gate", res["challenge"] == "Crack the Gate")
    check("المحلل = crack-the-gate", res["analyzer"] == "crack-the-gate")
    check("recognized = True", res["recognized"] is True)
    check("success = True", res["success"] is True)
    check("العلم مطابق للمحاكاة", res["flag"] == mock.FLAG)
    d = res["discovered"]
    check("ترويسة المطوّر: X-Dev-Access", d.get("dev_header", {}).get("name") == "X-Dev-Access")
    check("قيمة الترويسة: yes", d.get("dev_header", {}).get("value") == "yes")
    check("التعليق المفكوك يذكر الترويسة", "X-Dev-Access" in (d.get("comment_decoded") or ""))
    check("مسار الدخول = /login", d.get("login_path") == "/login")
    check("البريد المستخدم من الأكاديمية", "cylabacademy" in (d.get("email_used") or ""))

    p = paths(res)
    check("لا طلب إلى /register في هذا التحدي", "/register" not in p)
    check("لا طلب إلى /sessions في هذا التحدي", "/sessions" not in p)
    check("يوجد طلب POST إلى /login", any(s["method"] == "POST" and s["url"].endswith("/login") for s in res["steps"]))
    check("عدد الخطوات = 2 (فحص + دخول)", len(res["steps"]) == 2)
    # لا تُعرض كلمة المرور في أي مقتطف
    joined = " ".join(s.get("body_snippet", "") for s in res["steps"]) + " ".join(res["explanation_ar"])
    check("كلمة المرور التجريبية لا تظهر في السجل", w.TEST_PASSWORD not in joined)


def test_reject_401():
    print("\n[2] رفض الخادم (401) — لا علم مزيّف")
    srv, base = mock.start_server(mode="reject")
    try:
        res = w.run_audit(base)
    finally:
        srv.shutdown()
    check("recognized = True (تعرّف على النمط)", res["recognized"] is True)
    check("success = False", res["success"] is False)
    check("لا علم", res["flag"] is None)
    check("تحذير يذكر الرفض/401", any("401" in x or "رفض" in x for x in res["warnings"]))
    p = paths(res)
    check("لا /register ولا /sessions", "/register" not in p and "/sessions" not in p)


def test_no_flag():
    print("\n[3] دخول ناجح بلا علم")
    srv, base = mock.start_server(mode="no_flag")
    try:
        res = w.run_audit(base)
    finally:
        srv.shutdown()
    check("success = False (لا علم رغم النجاح)", res["success"] is False)
    check("لا علم", res["flag"] is None)
    check("تحذير مناسب", len(res["warnings"]) >= 1)


def test_text_flag():
    print("\n[4] علم كنص عادي (التقاط بالنمط لا JSON)")
    srv, base = mock.start_server(mode="text_flag")
    try:
        res = w.run_audit(base)
    finally:
        srv.shutdown()
    check("success = True", res["success"] is True)
    check("العلم مُلتقط من النص", res["flag"] == mock.FLAG)


def test_plain_not_recognized():
    print("\n[5] صفحة عادية — لا يُختار أي محلل، ولا تُطلب مسارات Old Sessions")
    srv, base = mock.start_plain()
    try:
        res = w.run_audit(base)
    finally:
        srv.shutdown()
    check("recognized = False", res["recognized"] is False)
    check("نوع التحدي = غير معروف", res["challenge"] == "غير معروف")
    check("رسالة عدم التعرّف", any("لم يتعرف" in x for x in res["explanation_ar"]))
    p = paths(res)
    check("خطوة واحدة فقط (فحص أولي)", len(res["steps"]) == 1)
    check("لا /register ولا /sessions إطلاقًا", "/register" not in p and "/sessions" not in p)


def test_connection_error():
    print("\n[6] هدف غير متاح — معالجة سلسة بلا انهيار")
    # منفذ مغلق على الأرجح
    res = w.run_audit("http://127.0.0.1:9/")
    check("recognized = False", res["recognized"] is False)
    check("success = False", res["success"] is False)
    check("تحذير بتعذّر الوصول", any("تعذّر" in x for x in res["warnings"]))


def test_detection_isolation():
    print("\n[7] عزل الكشف: recon لصفحة عادية لا يُصنَّف Crack the Gate")
    srv, base = mock.start_plain()
    try:
        client = w.HttpClient()
        steps, bodies = [], []
        rec = w._make_recorder(client, steps, bodies)
        recon = w.do_recon(client, base, rec)
        check("detect_crack_the_gate = None", w.detect_crack_the_gate(recon) is None)
        check("detect_old_sessions = False", w.detect_old_sessions(recon) is False)
    finally:
        srv.shutdown()


if __name__ == "__main__":
    print("=" * 68)
    print("اختبارات Crack the Gate")
    print("=" * 68)
    check("JSON shorthand fields", w.extract_login_fetch("fetch('/login', {method:'POST',body:JSON.stringify({email,password})})")["fields"] == ["email", "password"])
    srv, base = mock.start_server(mode="error_flag")
    try:
        result = w.run_audit(base)
        check("401 flag is not success", not result["success"] and result["flag"] is None)
    finally:
        srv.shutdown()
    test_happy_path()
    test_reject_401()
    test_no_flag()
    test_text_flag()
    test_plain_not_recognized()
    test_connection_error()
    test_detection_isolation()
    print("\n" + "=" * 68)
    print(f"النتيجة: {PASS} ناجح / {FAIL} فاشل")
    print("=" * 68)
    sys.exit(1 if FAIL else 0)
