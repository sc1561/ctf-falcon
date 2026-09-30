# -*- coding: utf-8 -*-
"""
اختبارات المدقّق: تشغيل المسار كاملًا ضد الخادم الوهمي + وحدات تحليل الكوكيز.
Run:  python tests/test_web_session_audit.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "local-engine"))
sys.path.insert(0, HERE)

import web_session_audit as wsa
import mock_old_sessions as mock

PASS, FAIL = 0, 0


def check(name, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}  {extra}")


def test_cookie_analysis():
    print("\n== تحليل الكوكيز (Max-Age / Expires) ==")

    a = wsa.analyze_set_cookie("session=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/")
    check("Max-Age=0 => deletion", a["intent"] == "deletion", a["intent"])

    b = wsa.analyze_set_cookie("session=abc; Expires=Tue, 19 Jan 2058 03:14:07 GMT; HttpOnly; Path=/")
    check("Expires 2058 => set", b["intent"] == "set", b["intent"])
    check("far-future warns about server session",
          any("لا يثبت أن جلسة المصادقة" in n for n in b["notes_ar"]))

    c = wsa.analyze_set_cookie("session=abc; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/")
    check("past Expires (no Max-Age) => deletion", c["intent"] == "deletion", c["intent"])

    d = wsa.analyze_set_cookie("session=abc; Path=/")
    check("no Max-Age/Expires => set (session cookie)", d["intent"] == "set", d["intent"])
    check("session cookie note present",
          any("تُحذف بإغلاق المتصفح" in n for n in d["notes_ar"]))

    e = wsa.analyze_set_cookie("session=abc; Max-Age=3600; Path=/")
    check("Max-Age=3600 => set with lifetime", e["intent"] == "set" and e["lifetime_seconds"] == 3600)

    f = wsa.analyze_set_cookie("session=abc; Max-Age=-1; Path=/")
    check("Max-Age=-1 => deletion", f["intent"] == "deletion", f["intent"])

    g = wsa.analyze_set_cookie("session=abc")
    check("missing HttpOnly noted separately",
          any("HttpOnly غائبة" in n for n in g["hardening_ar"]))


def test_full_path():
    print("\n== المسار الكامل ضد الخادم الوهمي ==")
    srv, base = mock.start_server()
    try:
        res = wsa.run_audit(base, demonstrate_register_requirement=True)
    finally:
        srv.shutdown()

    check("success == True", res["success"] is True)
    check("flag matches mock", res["flag"] == mock.FLAG, f"got={res['flag']}")
    check("admin token discovered",
          res["discovered"]["admin_session_token"] == mock.ADMIN_TOKEN,
          res["discovered"]["admin_session_token"])
    check("sessions hint found", res["discovered"]["sessions_hint"] == "/sessions")

    # الخطوة 1: / بلا جلسة => 302 وكوكي جديدة
    s1 = res["steps"][0]
    check("step1 is 302 to /login", s1["status"] == 302 and s1["location"] == "/login")
    check("step1 sets a persistent cookie",
          any(c["intent"] == "set" for c in s1["set_cookies"]))

    # خطوة /login تحذف الكوكي (الدليل الذي يخفيه اتباع التحويل)
    login_step = next(s for s in res["steps"] if s["url"].endswith("/login") and s["method"] == "GET")
    check("login GET deletes cookie",
          any(c["intent"] == "deletion" for c in login_step["set_cookies"]))

    # إثبات متطلب conf_password => 400
    reg_probe = [s for s in res["steps"] if s["method"] == "POST" and s["url"].endswith("/register")]
    check("register without conf_password => 400 recorded",
          any(s["status"] == 400 for s in reg_probe))

    # لا قيم مثبّتة: تشغيل ثانٍ على منفذ مختلف يجب أن ينجح أيضًا
    srv2, base2 = mock.start_server()
    try:
        res2 = wsa.run_audit(base2)
    finally:
        srv2.shutdown()
    check("second instance (different port) also solved", res2["success"] is True)

    return res


def main():
    print("=" * 68)
    print("CTF Falcon — Web Session Audit :: اختبارات")
    print("=" * 68)
    test_cookie_analysis()
    res = test_full_path()

    print("\n" + "=" * 68)
    print(f"النتيجة: {PASS} ناجح / {FAIL} فاشل")
    print("=" * 68)

    if FAIL == 0:
        print("\n--- دليل: ملخص المسار الناجح ---")
        for line in res["explanation_ar"]:
            print("  " + line)
        print(f"\n  ✅ العلم المستخرج: {res['flag']}  (المصدر: {res['flag_source']})")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
