"""Educational, non-executing helper for the picoCTF Undo transformation challenge."""
from __future__ import annotations

import re


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
        src, dst = tr_cmd.group(2), tr_cmd.group(4)
        tr_item = next((i for i, item in enumerate(found) if item[0] == "tr-map"), None)
        explanation = (f"ظهر أمر `tr` بمجموعتي المصدر والوجهة بطولَي {len(src)} و{len(dst)}. "
                       "يمكن عكسه بتبديل المجموعتين إذا لم تتكرر محارف المصدر ولم توجد خيارات حذف/ضغط.")
        inverse = f"tr '{dst}' '{src}'" if len(src) == len(dst) and len(set(src)) == len(src) else None
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
