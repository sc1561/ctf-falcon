"""Arabic clue guided steganography and document triage.

Reads supplied CTF files only. It does not run scripts from an archive, access
the network, or try password dictionaries. Steghide is invoked only with the
empty passphrase when the Arabic clue explicitly says no key is needed.
"""
from __future__ import annotations

import base64
import io
import itertools
import re
import subprocess
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

FLAG_RE = re.compile(rb"(?i)(?:flag|picoctf|academy|ctf|moe)\{[^{}\r\n]{2,180}\}")
INVIS = "\u200b\u200c\u200d\u2060\u202c\ufeff"
COMMON_WORDS = {
    "a", "about", "at", "beautiful", "book", "books", "brown", "bicycle",
    "child", "dropped", "fox", "love", "mailman", "on", "over", "past",
    "person", "quick", "read", "rode", "snow", "sunny", "the",
    "their", "to", "toy", "was", "day", "dog", "barked", "jumps",
}


def recognizes_arabic_stego(text: str) -> bool:
    t = (text or "").lower()
    has_ar = any("\u0600" <= c <= "\u06ff" for c in t)
    clue = re.search(r"(?:صورة|ألوان|الوان|الصورة|مخفي|مخبأ|غير مرئي|لا ترى العين|بين السطور|المسافات|مسافات|فراغات|حروف|مفتاح|طبقات|ظل|ظلال|تفاصيل|ملف|رسالة مدفونة)", t)
    english_clue = re.search(
        r"(?:hidden\s+message|words?\s+(?:seem|look)\s+familiar|"
        r"something\s+strange.{0,80}(?:written|way)|"
        r"letters?\s+that\s+whisper|don't\s+look\s+for\s+the\s+words|"
        r"invisible\s+(?:spaces?|characters?|whitespace)|"
        r"message\s+(?:is\s+)?(?:hidden|hides)\s+(?:between|in)|"
        r"between.{0,100}(?:visible\s+)?(?:lines|sentences).{0,100}(?:hidden|hides|message)|"
        r"don't\s+trust\s+(?:the\s+)?appearances)",
        t,
    )
    return bool((has_ar and clue) or english_clue)


def _flag_strings(data: bytes) -> list[str]:
    found = []
    for m in FLAG_RE.finditer(data):
        s = m.group().decode("utf-8", "replace")
        if s not in found:
            found.append(s)
    return found


def _jpeg_segments(data: bytes):
    """Yield JPEG comment and APP payloads, plus any bytes after EOI."""
    if not data.startswith(b"\xff\xd8"):
        return [], b""
    fields = []
    i = 2
    while i + 4 <= len(data):
        if data[i] != 0xFF:
            i += 1
            continue
        while i < len(data) and data[i] == 0xFF:
            i += 1
        if i >= len(data):
            break
        marker = data[i]
        i += 1
        if marker == 0xD9:
            return fields, data[i:]
        if marker == 0xDA:
            end = data.rfind(b"\xff\xd9")
            return fields, data[end + 2:] if end >= 0 else b""
        if marker in (0x01, *range(0xD0, 0xD8)):
            continue
        if i + 2 > len(data):
            break
        n = int.from_bytes(data[i:i + 2], "big")
        if n < 2 or i + n > len(data):
            break
        payload = data[i + 2:i + n]
        if marker == 0xFE:
            fields.append(("JPEG COM comment", payload))
        elif 0xE0 <= marker <= 0xEF:
            fields.append((f"JPEG APP{marker - 0xE0} metadata", payload))
        i += n
    return fields, b""


def _png_text(data: bytes) -> list[tuple[str, bytes]]:
    out = []
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return out
    i = 8
    while i + 12 <= len(data):
        n = int.from_bytes(data[i:i + 4], "big")
        if n > 32 * 1024 * 1024 or i + 12 + n > len(data):
            break
        kind = data[i + 4:i + 8]
        chunk = data[i + 8:i + 8 + n]
        if kind == b"tEXt":
            out.append(("PNG tEXt", chunk.replace(b"\x00", b" ")))
        elif kind == b"zTXt" and b"\x00" in chunk:
            key, rest = chunk.split(b"\x00", 1)
            if len(rest) > 1 and rest[0] == 0:
                try:
                    import zlib
                    out.append(("PNG zTXt " + key.decode("latin-1"), zlib.decompress(rest[1:])[:2_000_000]))
                except Exception:
                    pass
        elif kind == b"iTXt" and b"\x00" in chunk:
            out.append(("PNG iTXt", chunk.replace(b"\x00", b" ")))
        i += n + 12
        if kind == b"IEND":
            break
    return out


def _unicode_text(data: bytes):
    for enc in ("utf-8-sig", "utf-16", "utf-16-le", "utf-16-be"):
        try:
            text = data.decode(enc)
        except UnicodeError:
            continue
        if any(c in INVIS for c in text):
            return text
        if sum(c.isprintable() or c in "\r\n\t" for c in text) / max(1, len(text)) > .75:
            return text
    return None


def _hidden_unicode_candidates(text: str):
    seq = "".join(c for c in text if c in INVIS)
    result = []
    if len(seq) < 8:
        return seq, result
    # Common zero-width binary pair encodings. Try every pair/order and byte
    # alignment, but report only exact flag-shaped decodes.
    chars = list(dict.fromkeys(seq))
    for a, b in itertools.permutations(chars, 2):
        for va, vb in (("0", "1"), ("1", "0")):
            bits = "".join(va if c == a else vb for c in seq if c in (a, b))
            for reverse in (False, True):
                stream = bits[::-1] if reverse else bits
                for offset in range(8):
                    part = stream[offset:]
                    raw = bytes(int(part[i:i + 8], 2) for i in range(0, len(part) - 7, 8))
                    for candidate in (raw, raw[::-1]):
                        for flag in _flag_strings(candidate):
                            if flag not in result:
                                result.append(flag)
    # Four-symbol/two-bit encoding, again preserving no guessed plaintext.
    if len(chars) == 4:
        for order in itertools.permutations(chars):
            digit = {c: str(i) for i, c in enumerate(order)}
            bits = "".join(format(int(digit[c]), "02b") for c in seq)
            for offset in range(8):
                part = bits[offset:]
                raw = bytes(int(part[i:i + 8], 2) for i in range(0, len(part) - 7, 8))
                for candidate in (raw, raw[::-1]):
                    for flag in _flag_strings(candidate):
                        if flag not in result:
                            result.append(flag)
            # Some zero-width schemes store each plaintext character as a
            # 16-bit code unit, with each invisible glyph carrying two bits.
            # Decode this separately from byte streams (e.g. 8 symbols/char).
            for reverse in (False, True):
                stream = bits[::-1] if reverse else bits
                for offset in range(16):
                    part = stream[offset:]
                    for swap_bytes in (False, True):
                        chars_out = []
                        for i in range(0, len(part) - 15, 16):
                            word = part[i:i + 16]
                            if swap_bytes:
                                word = word[8:] + word[:8]
                            codepoint = int(word, 2)
                            if 0xD800 <= codepoint <= 0xDFFF:
                                chars_out = []
                                break
                            chars_out.append(chr(codepoint))
                        if chars_out:
                            candidate = "".join(chars_out).encode("utf-8", "ignore")
                            for flag in _flag_strings(candidate):
                                if flag not in result:
                                    result.append(flag)
    return seq, result


def _typo_candidates(text: str):
    """Extract likely altered letters using a small common-word reference set."""
    words = re.findall(r"[A-Za-z@$#0-9]+", text)
    altered = []
    for token in words:
        low = token.lower()
        if low in COMMON_WORDS or len(low) < 3:
            continue
        best = []
        for expected in COMMON_WORDS:
            if abs(len(expected) - len(low)) > 1:
                continue
            # Same-length single substitution: the written character is the
            # signal. Avoid treating arbitrary words as evidence unless a
            # plausible common-word correction exists.
            diffs = [i for i, (x, y) in enumerate(zip(low, expected)) if x != y]
            if len(low) == len(expected) and len(diffs) == 1:
                best.append((expected, low[diffs[0]]))
            elif len(low) == len(expected) + 1:
                for i in range(len(low)):
                    if low[:i] + low[i + 1:] == expected:
                        best.append((expected, low[i]))
            elif len(expected) == len(low) + 1:
                for i in range(len(expected)):
                    if expected[:i] + expected[i + 1:] == low:
                        best.append((expected, ""))
        # Repeated identical letters can create the same deletion candidate
        # at multiple positions (e.g. wass -> was by removing either s).
        unique = list(dict.fromkeys(best))
        if len(unique) == 1:
            altered.append((token, unique[0][0], unique[0][1]))
    return altered


def _pdf_text(data: bytes):
    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(data), strict=False)
        chunks = []
        meta = reader.metadata
        if meta:
            chunks.extend(str(v) for v in meta.values() if v)
        for page in reader.pages[:100]:
            chunks.append(page.extract_text() or "")
        return "\n".join(chunks), None
    except ImportError:
        return "", "تثبيت pypdf مطلوب لفحص نص وبيانات PDF محليًا."
    except Exception as exc:
        return "", "تعذر استخراج نص PDF: " + str(exc)[:160]


def _file_findings(data: bytes, name: str, clue: str, steghide: str | None):
    findings = []
    flags = []
    suffix = PurePosixPath(name).suffix.lower()
    candidates = [("محتوى الملف", data)]
    if suffix in (".jpg", ".jpeg") or data.startswith(b"\xff\xd8\xff"):
        fields, trailing = _jpeg_segments(data)
        for label, payload in fields:
            candidates.append((label, payload))
            findings.append(f"{label}: {len(payload)} بايت")
        if trailing:
            candidates.append(("بيانات بعد علامة JPEG EOI", trailing))
            findings.append(f"بيانات ملحقة بعد نهاية JPEG: {len(trailing)} بايت")
        try:
            from PIL import Image
            im = Image.open(io.BytesIO(data))
            comment = im.info.get("comment")
            if comment:
                candidates.append(("JPEG comment", comment if isinstance(comment, bytes) else str(comment).encode()))
                findings.append("عُثر على تعليق JPEG")
            exif = im.getexif()
            if exif:
                findings.append(f"حقول EXIF: {len(exif)}")
        except Exception as exc:
            findings.append("تعذر قراءة خصائص JPEG عبر Pillow: " + str(exc)[:120])
        empty_passphrase_hint = re.search(r"(?:لست\s*بحاجة|لا\s*تحتاج|دون|بدون|لا\s*حاجة).{0,25}(?:مفتاح|كلمة\s*مرور|password|key)", clue, re.I | re.S)
        if empty_passphrase_hint and not steghide:
            findings.append("التلميح يطلب تجربة Steghide بكلمة مرور فارغة، لكن steghide غير مثبت أو لم يُكتشف في المحرك المحلي.")
        if steghide and empty_passphrase_hint:
            try:
                with tempfile.TemporaryDirectory(prefix="falcon_stego_") as td:
                    src = Path(td) / Path(name).name
                    out = Path(td) / "payload.bin"
                    src.write_bytes(data)
                    run = subprocess.run([steghide, "extract", "-sf", str(src), "-p", "", "-xf", str(out)], capture_output=True, timeout=20)
                    if run.returncode == 0 and out.is_file() and out.stat().st_size <= 8 * 1024 * 1024:
                        payload = out.read_bytes()
                        candidates.append(("Steghide (empty passphrase)", payload))
                        findings.append("استخرج صقر محتوى Steghide بكلمة مرور فارغة استنادًا إلى التلميح العربي.")
                    else:
                        findings.append("لم ينجح فحص Steghide بكلمة مرور فارغة؛ لم تُجرّب كلمات مرور تخمينية.")
            except Exception as exc:
                findings.append("تعذر تشغيل Steghide: " + str(exc)[:140])
        elif not empty_passphrase_hint:
            findings.append("لم تُظهر الصورة وحدها سببًا لتجربة Steghide بكلمة مرور فارغة.")
    elif suffix == ".png" or data.startswith(b"\x89PNG\r\n\x1a\n"):
        candidates.extend(_png_text(data))
        findings.append("فُحصت حقول PNG النصية ومؤشر نهاية الصورة.")
        end = data.rfind(b"IEND")
        if end >= 0 and end + 8 < len(data):
            candidates.append(("بيانات بعد PNG IEND", data[end + 8:]))
            findings.append(f"بيانات بعد IEND: {len(data) - end - 8} بايت")
        try:
            from PIL import Image
            im = Image.open(io.BytesIO(data))
            findings.append(f"الصورة {im.width}×{im.height}، القنوات: {im.mode}؛ مسارات التلميح: القنوات، مستويات البت، تحسين التباين.")
        except Exception:
            pass
    elif suffix == ".pdf" or data.startswith(b"%PDF-"):
        extracted, warning = _pdf_text(data)
        if extracted:
            candidates.append(("نص وبيانات PDF المستخرجة", extracted.encode("utf-8", "replace")))
            findings.append("استُخرج نص الصفحات وحقول المستند محليًا، بما فيها النص غير الظاهر بصريًا إذا كان ضمن طبقة النص.")
        if warning:
            findings.append(warning)
    else:
        text = _unicode_text(data)
        if text is not None:
            candidates.append(("نص Unicode", text.encode("utf-8")))
            hidden, hidden_flags = _hidden_unicode_candidates(text)
            if hidden:
                findings.append(f"عُثر على {len(hidden)} محرفًا غير مرئي/تنسيقي. فُحصت ترميزات البتات الثنائية والرباعية ومحارف 16-bit؛ لم تُقبل إلا النتائج المطابقة لصيغة العلم.")
                flags.extend((f, "محارف Unicode غير مرئية") for f in hidden_flags)
            typo = _typo_candidates(text)
            if typo:
                findings.append("حروف شاذة محتملة بعد مقارنة كلمات قريبة: " + ", ".join(f"{a}→{b} ({c or 'حرف محذوف'})" for a, b, c in typo[:30]))
                signal = "".join(c for _, _, c in typo)
                if len(signal) >= 4:
                    flags.append((f"Flag{{{signal}}}", "حروف الكلمات التي خالفت الهجاء المرجعي المحلي"))
            for line in text.splitlines():
                leading = len(line) - len(line.lstrip(" \t"))
                trailing = len(line) - len(line.rstrip(" \t"))
                if leading or trailing:
                    findings.append(f"مسافات بادئة/نهائية موجودة في النص؛ قد تحمل ترميزًا بالمسافات.")
                    break
    for method, content in candidates:
        for flag in _flag_strings(content):
            pair = (flag, method)
            if pair not in flags:
                flags.append(pair)
    return findings, flags


def analyze_arabic_challenge(data: bytes, filename: str, challenge_text: str = "", steghide_path: str | None = None):
    """Analyze one file or ZIP supplied alongside Arabic forensic clues."""
    if not isinstance(data, (bytes, bytearray)) or not data:
        raise ValueError("الملف فارغ أو غير صالح.")
    if len(data) > 64 * 1024 * 1024:
        raise ValueError("حجم الملف أكبر من 64 ميغابايت.")
    clue = str(challenge_text or "")[:24000]
    if not recognizes_arabic_stego(clue):
        return {"ok": True, "recognized": False, "success": False, "flags": [], "findings": [], "warnings": ["لم يتعرف صقر على تلميح عربي خاص بتحليل الصور/الإخفاء."]}
    files = []
    if bytes(data).startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                total = 0
                for item in zf.infolist()[:100]:
                    if item.is_dir() or item.file_size > 24 * 1024 * 1024:
                        continue
                    total += item.file_size
                    if total > 64 * 1024 * 1024:
                        break
                    safe = str(PurePosixPath(item.filename))
                    if safe.startswith("../") or safe.startswith("/"):
                        continue
                    files.append((safe, zf.read(item)))
        except (zipfile.BadZipFile, OSError) as exc:
            return {"ok": True, "recognized": True, "success": False, "flags": [], "findings": [], "warnings": ["تعذر قراءة ZIP: " + str(exc)[:120]]}
    else:
        files = [(Path(filename or "upload.bin").name, bytes(data))]
    all_findings, all_flags, missing = [], [], []
    for name, blob in files:
        findings, flags = _file_findings(blob, name, clue, steghide_path)
        all_findings.extend({"file": name, "text": line} for line in findings)
        for flag, method in flags:
            row = {"flag": flag, "file": name, "method": method}
            previous = next((x for x in all_flags if x["flag"] == flag and x["file"] == name), None)
            if previous is None:
                all_flags.append(row)
            elif previous["method"] == "محتوى الملف" and method != "محتوى الملف":
                previous["method"] = method
    if not files:
        missing.append("لم يحتو الأرشيف على ملفات قابلة للفحص.")
    return {"ok": True, "recognized": True, "challenge": "تحليل أدلة عربية: Steganography / Forensics",
            "success": bool(all_flags), "files_scanned": len(files), "flags": all_flags,
            "findings": all_findings, "warnings": missing,
            "explanation_ar": ["فهم صقر التلميحات العربية ووجّه كل ملف حسب نوعه: JPEG metadata/Steghide، PNG، نصوص Unicode/الأخطاء الإملائية، وPDF.",
                               "لم يشغّل صقر أي سكربت من الأرشيف، ولم يستخدم تخمين كلمات مرور."]}
