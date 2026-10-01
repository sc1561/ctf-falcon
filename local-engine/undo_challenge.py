"""Educational, non-executing helper for the picoCTF Undo transformation challenge."""
from __future__ import annotations

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
    """Explain explicit transformations in a pasted challenge transcript; never executes commands."""
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
    return {
        "ok": True, "challenge": "Undo", "analyzer": "undo", "recognized": True,
        "operations_seen": [x[0] for x in found], "inverse_steps": reverse_steps,
        "explanation_ar": [
            "هذا تحدٍ لعكس تحويلات نصية؛ نقرأ التلميحات الفعلية في خرج الخدمة ولا نخمن التحويل من شكل العلم وحده.",
            "نعكس ترتيب العمليات: آخر تحويل طُبّق هو أول تحويل نفكّه.",
            "صقر يشرح الأوامر ولا ينفذ أوامر Linux على جهازك.",
        ],
        "warnings": caution,
    }


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
