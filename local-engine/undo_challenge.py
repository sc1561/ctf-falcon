"""Educational, non-executing helper for the picoCTF Undo transformation challenge."""
from __future__ import annotations

import base64
import binascii
import re
import socket
import time


_RULES = (
    ("rev", re.compile(r"\brev(?:erse|ersal|ersing)?\b|reverse\s+(?:the\s+)?(?:string|text)", re.I),
     "`rev` يقلب ترتيب المحارف؛ عكسه `rev` مرة أخرى." , "rev"),
    ("rot13", re.compile(r"\brot\s*[- ]?13\b|rotate.{0,20}13|13\s+positions?", re.I),
     "ROT13 يعكس نفسه؛ طبّق ROT13 مرة أخرى باستخدام `tr 'A-Za-z' 'N-ZA-Mn-za-m'`.",
     "tr 'A-Za-z' 'N-ZA-Mn-za-m'"),
    ("case-swap", re.compile(r"swap\s*case|case\s+conversion|upper\s*(?:to|↔|and)\s*lower|lower\s*(?:to|↔|and)\s*upper", re.I),
     "تبديل حالة الأحرف يعكس نفسه؛ استخدم `tr 'A-Za-z' 'a-zA-Z'`.", "tr 'A-Za-z' 'a-zA-Z'"),
    ("base64", re.compile(r"base\s*64|base64", re.I),
     "إذا كان التحويل ترميز Base64، فكّه بـ `base64 -d`.", "base64 -d"),
    ("hex", re.compile(r"\bhex(?:adecimal)?\b|xxd\s+-p", re.I),
     "إذا كان النص Hex، حوّله إلى بايتات بـ `xxd -r -p`.", "xxd -r -p"),
    ("tr-map", re.compile(r"\btr\b|translate|substitut|replace|replac(?:e|ed|ing)", re.I),
     "تحويل `tr` يُعكس بتبديل مجموعتي المحارف فقط إذا كان الربط واحدًا لواحد ولم تُحذف أو تُدمج محارف. افحص الأمر والمجموعتين أولًا.",
     "tr 'مجموعة_الناتج' 'مجموعة_الأصل'"),
)

_NC_TARGET = re.compile(r"(?i)\bnc\s+([a-z0-9.-]+)\s+(\d{1,5})\b")
_ALLOWED_SUFFIXES = (".cylabacademy.net", ".cylabacademy.org")


def parse_target(challenge_text: str) -> tuple[str, int] | None:
    """Extract only explicitly posted CyLab Academy challenge targets."""
    match = _NC_TARGET.search(challenge_text or "")
    if not match:
        return None
    host = match.group(1).lower().rstrip(".")
    try:
        port = int(match.group(2))
    except ValueError:
        return None
    if (not any(host.endswith(suffix) and host[:-len(suffix)] for suffix in _ALLOWED_SUFFIXES)
            or ".." in host or not 1 <= port <= 65535):
        return None
    return host, port


def connect_transcript(challenge_text: str, *, connector=socket.create_connection,
                       max_bytes: int = 12288, read_window: float = 1.2) -> dict:
    """Read the initial CTF service banner only; never send data to the service."""
    target = parse_target(challenge_text)
    if not target:
        return {"ok": False, "error": "لم يُعثر على هدف nc صالح ضمن نطاق CyLab Academy في وصف Undo."}
    host, port = target
    data = bytearray()
    try:
        with connector(target, timeout=4.0) as sock:
            sock.settimeout(0.4)
            deadline = time.monotonic() + read_window
            while len(data) < max_bytes and time.monotonic() < deadline:
                try:
                    chunk = sock.recv(min(2048, max_bytes - len(data)))
                except socket.timeout:
                    if data:
                        break
                    continue
                if not chunk:
                    break
                data.extend(chunk)
    except (OSError, TimeoutError) as exc:
        return {"ok": False, "target": f"{host}:{port}", "error": f"تعذر الاتصال بخدمة التحدي: {str(exc)[:180]}"}
    transcript = data.decode("utf-8", "replace").strip()
    if not transcript:
        return {"ok": False, "target": f"{host}:{port}",
                "error": "اتصل صقر بالخدمة، لكنها لم ترسل نصًا تلقائيًا. قد تنتظر إدخالًا أوليًا؛ استخدم Ncat والصق ما يظهر."}
    return {"ok": True, "target": f"{host}:{port}", "transcript": transcript,
            "bytes_read": len(data), "sent_bytes": 0}


def analyze(challenge_text: str, transcript: str) -> dict:
    """Explain and reverse supported text operations in a pasted CTF transcript."""
    text = (transcript or "").strip()
    if not text:
        return {"ok": False, "error": "الصق نص التحدي أو رسائل المراحل التي ظهرت بعد الاتصال."}
    found: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    # Process lines in displayed order so the inverse recipe can be reversed safely.
    for line in text.splitlines():
        hits = []
        for name, pattern, explanation, command in _RULES:
            match = pattern.search(line)
            if match and name not in seen:
                hits.append((match.start(), name, explanation, command))
        for _position, name, explanation, command in sorted(hits):
            if name not in seen:
                found.append((name, explanation, command))
                seen.add(name)
    # Explicit command-shaped tr mappings carry more useful evidence than a generic hint.
    tr_cmd = re.search(r"(?i)\btr\s+(['\"])(.*?)\1\s+(['\"])(.*?)\3", text)
    if tr_cmd:
        src, dst = _expand_tr_set(tr_cmd.group(2)), _expand_tr_set(tr_cmd.group(4))
        tr_item = next((i for i, item in enumerate(found) if item[0] == "tr-map"), None)
        src_len, dst_len = len(src or ""), len(dst or "")
        explanation = (f"ظهر أمر `tr` بمجموعتي المصدر والوجهة بطولَي {src_len} و{dst_len}. "
                       "يمكن عكسه بتبديل المجموعتين إذا لم تتكرر محارف المصدر ولم توجد خيارات حذف/ضغط.")
        invertible = (src is not None and dst is not None and src_len == dst_len and
                      len(set(src)) == src_len and len(set(dst)) == dst_len)
        inverse = f"tr '{tr_cmd.group(4)}' '{tr_cmd.group(2)}'" if invertible else None
        entry = ("tr-map", explanation, inverse or "غير قابل للعكس آليًا: افحص التكرار وخيارات tr")
        if tr_item is None:
            found.append(entry)
        else:
            found[tr_item] = entry

    reverse_steps = [
        {"stage": index + 1, "operation": name, "explanation_ar": explanation,
         "inverse_command": command}
        for index, (name, explanation, command) in enumerate(reversed(found))
    ]
    caution = []
    if not found:
        caution.append("لم أتعرف على تحويل محدد. أرسل نص المراحل كاملًا، مع ترتيبها وأي أوامر أو تلميحات يعرضها الخادم.")
    if any(x[0] == "tr-map" for x in found):
        caution.append("لا يمكن عكس كل تحويلات tr: الحذف، ضغط التكرار، أو استبدال عدة محارف بمحرف واحد قد يفقد معلومات.")
    recovery = _recover(text, found)
    if recovery.get("flag"):
        caution.append("استخرج صقر العلم محليًا؛ راجعه ثم انسخه إلى منصة التحدي بنفسك.")
    elif not recovery.get("candidates"):
        caution.append("لم يعثر صقر على نص الحمولة في الخرج. راجع خرج الخدمة المعروض أدناه والصق السلسلة المشوّهة كاملة إن كانت منفصلة.")
    result = {
        "ok": True, "challenge": "Undo", "analyzer": "undo", "recognized": True,
        "operations_seen": [x[0] for x in found], "inverse_steps": reverse_steps,
        "explanation_ar": [
            "هذا تحدٍ لعكس تحويلات نصية؛ نقرأ التلميحات الفعلية في خرج الخدمة ولا نخمن التحويل من شكل العلم وحده.",
            "نعكس ترتيب العمليات: آخر تحويل طُبّق هو أول تحويل نفكّه.",
            "صقر يشرح الأوامر ولا ينفذ أوامر Linux على جهازك.",
        ],
        "warnings": caution, "transcript_preview": text[:12000],
    }
    result.update(recovery)
    return result


def _recover(transcript: str, found: list[tuple[str, str, str]]) -> dict:
    """Try candidate strings through known inverses only; return a flag only on exact pattern."""
    operations = [item[0] for item in reversed(found)]
    tr_cmd = re.search(r"(?i)\btr\s+(['\"])(.*?)\1\s+(['\"])(.*?)\3", transcript)
    tr_inverse = None
    if tr_cmd:
        src, dst = _expand_tr_set(tr_cmd.group(2)), _expand_tr_set(tr_cmd.group(4))
        if (src is not None and dst is not None and len(src) == len(dst) and
                len(set(src)) == len(src) and len(set(dst)) == len(dst)):
            tr_inverse = str.maketrans(dict(zip(dst, src)))

    candidates = _candidate_strings(transcript)
    trials = []
    for candidate, priority in candidates:
        value = candidate
        trace = []
        valid = True
        for op in operations:
            try:
                value = _inverse(value, op, tr_inverse)
                trace.append({"operation": op, "value": value[:2000]})
            except (ValueError, UnicodeError, binascii.Error):
                valid = False
                break
        if valid and value:
            flag_match = re.search(r"(?:picoCTF|academy)\{[^{}\r\n]{2,200}\}", value)
            score = priority + (10000 if flag_match else 0) + _readability(value)
            trials.append((score, value, trace, flag_match.group(0) if flag_match else None))
    if not trials:
        return {"candidates": len(candidates), "recovery_steps": [], "recovered_text": None, "flag": None}
    trials.sort(key=lambda row: row[0], reverse=True)
    _score, value, trace, flag = trials[0]
    return {"candidates": len(candidates), "recovery_steps": trace,
            "recovered_text": value[:4000], "flag": flag}


def _candidate_strings(text: str) -> list[tuple[str, int]]:
    ansi = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    values: dict[str, int] = {}
    label = re.compile(r"(?i)(?:output|result|ciphertext|encrypted|encoded|transformed(?:\s+flag)?|flag)\s*[:=\-]>?\s*(\S+)")
    for line in ansi.splitlines():
        line = line.strip().strip("`\"'")
        if not line:
            continue
        match = label.search(line)
        if match:
            token = match.group(1).strip("`\"'.,;: ")
            if len(token) >= 4:
                values[token] = max(values.get(token, 0), 150)
        if "{" in line or "}" in line:
            token = line.split(":", 1)[-1].strip().strip("`\"'")
            if 4 <= len(token) <= 2000:
                values[token] = max(values.get(token, 0), 250)
        for token in re.findall(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{8,}={0,2}(?![A-Za-z0-9+/=])", line):
            values[token] = max(values.get(token, 0), 50)
        for token in re.findall(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){4,}(?![0-9A-Fa-f])", line):
            values[token] = max(values.get(token, 0), 50)
    flag = re.search(r"(?:picoCTF|academy)\{[^{}\r\n]{2,200}\}", ansi)
    if flag:
        values[flag.group(0)] = max(values.get(flag.group(0), 0), 1000)
    return list(values.items())[:100]


def _inverse(value: str, operation: str, tr_inverse) -> str:
    if operation == "rev":
        return value[::-1]
    if operation == "rot13":
        lower = "abcdefghijklmnopqrstuvwxyz"
        upper = lower.upper()
        table = str.maketrans(lower + upper, lower[13:] + lower[:13] + upper[13:] + upper[:13])
        return value.translate(table)
    if operation == "case-swap":
        return value.swapcase()
    if operation == "tr-map":
        if tr_inverse is None:
            raise ValueError("non-invertible tr mapping")
        return value.translate(tr_inverse)
    if operation == "base64":
        compact = re.sub(r"\s+", "", value)
        compact += "=" * ((-len(compact)) % 4)
        decoded = base64.b64decode(compact, validate=True)
        return decoded.decode("utf-8", "strict")
    if operation == "hex":
        compact = re.sub(r"\s+|0x", "", value, flags=re.I)
        if len(compact) % 2:
            raise ValueError("odd-length hex")
        return bytes.fromhex(compact).decode("utf-8", "strict")
    raise ValueError("unknown transformation")


def _readability(value: str) -> int:
    if not value:
        return -100
    printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in value) / len(value)
    return int(printable * 100)


def _expand_tr_set(value: str) -> str | None:
    """Expand basic ascending ASCII ranges (for example A-Za-z) in a tr set."""
    out: list[str] = []
    i = 0
    while i < len(value):
        if i + 2 < len(value) and value[i + 1] == "-":
            start, end = ord(value[i]), ord(value[i + 2])
            if start > end:
                return None
            out.extend(chr(code) for code in range(start, end + 1))
            i += 3
        else:
            out.append(value[i])
            i += 1
    return "".join(out)
