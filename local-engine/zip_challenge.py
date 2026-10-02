"""Inspect encrypted CTF ZIPs and derive bounded password candidates from evidence."""
from __future__ import annotations

import io
import gzip
import re
import unicodedata
import zipfile
from pathlib import Path, PurePosixPath

MAX_CANDIDATES = 100_000
MAX_PASSWORD_LENGTH = 128
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_AUTO_CANDIDATES = 100_000
MAX_EVIDENCE_CANDIDATES = 5_000
MAX_WORDLIST_CANDIDATES = 100_000
WORDLIST_NAMES = ("rockyou.txt", "rockyou.txt.gz")
_TOKEN = re.compile(r"[\w][\w.@!-]{1,39}", re.UNICODE)
_GENERIC = {"flag", "secret", "password", "passwd", "archive", "encrypted", "readme",
            "file", "data", "txt", "zip", "pdf", "png", "jpg", "jpeg", "doc", "docx"}


def _has_aes_extra(extra: bytes) -> bool:
    pos = 0
    while pos + 4 <= len(extra):
        kind = int.from_bytes(extra[pos:pos + 2], "little")
        size = int.from_bytes(extra[pos + 2:pos + 4], "little")
        pos += 4
        if pos + size > len(extra):
            break
        if kind == 0x9901:
            return True
        pos += size
    return False


def inspect_zip(data: bytes, filename: str = "challenge.zip") -> dict:
    """Return reliable archive metadata without extracting or guessing passwords."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            files = [entry for entry in archive.infolist() if not entry.is_dir()]
            encrypted = [entry for entry in files if entry.flag_bits & 1]
            if not encrypted:
                return {"is_zip": True, "encrypted": False, "filename": filename,
                        "file_count": len(files), "algorithm": None}
            aes = any(_has_aes_extra(entry.extra) for entry in encrypted)
            return {
                "is_zip": True,
                "encrypted": True,
                "filename": filename,
                "file_count": len(files),
                "encrypted_file_count": len(encrypted),
                "files": [PurePosixPath(entry.filename.replace("\\", "/")).name[:180]
                          for entry in files[:50]],
                "algorithm": "WinZip AES" if aes else "ZipCrypto",
                "compression_methods": sorted({entry.compress_type for entry in files}),
                "encrypted_archives": [{
                    "path": filename,
                    "algorithm": "WinZip AES" if aes else "ZipCrypto",
                    "encrypted_file_count": len(encrypted),
                    "file_count": len(files),
                    "files": [PurePosixPath(entry.filename.replace("\\", "/")).name[:180]
                              for entry in files[:50]],
                }],
            }
    except (OSError, zipfile.BadZipFile, ValueError):
        return {"is_zip": False, "encrypted": False, "filename": filename}


def recover_zip(data: bytes, candidates: list[str], filename: str = "challenge.zip") -> dict:
    """Try only caller-supplied password candidates; never brute-force or persist files."""
    info = inspect_zip(data, filename)
    if not info.get("is_zip"):
        return {"ok": False, "error": "الملف ليس أرشيف ZIP صالحًا."}
    if not info.get("encrypted"):
        return {"ok": False, "error": "الأرشيف غير مشفّر؛ استخدم فحص الملفات العادي."}
    if info.get("algorithm") == "WinZip AES":
        try:
            import pyzipper  # optional AES-capable reader
        except ImportError:
            return {"ok": True, "success": False, "encrypted": True, "algorithm": "WinZip AES",
                    "error": "رُصد تشفير WinZip AES. فكّه يحتاج قارئ AES مثل pyzipper؛ لم تُجرّب كلمات المرور."}
        return _recover_with_pyzipper(data, candidates, filename, info, pyzipper)

    normalized = []
    seen = set()
    for item in candidates:
        password = str(item).rstrip("\r\n")
        if not password or len(password) > MAX_PASSWORD_LENGTH or password in seen:
            continue
        seen.add(password)
        normalized.append(password)
        if len(normalized) >= MAX_CANDIDATES:
            break
    if not normalized:
        return {"ok": False, "encrypted": True, "algorithm": "ZipCrypto",
                "error": "أدخل قائمة كلمات مرور مرشحة (كلمة واحدة في كل سطر).",
                "attempts": 0}

    encrypted_entries = []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = [e for e in archive.infolist() if not e.is_dir()]
        encrypted_entries = [e for e in entries if e.flag_bits & 1]
        for password in normalized:
            password_bytes = password.encode("utf-8")
            try:
                extracted = []
                total = 0
                for entry in entries:
                    pwd = password_bytes if entry.flag_bits & 1 else None
                    with archive.open(entry, "r", pwd=pwd) as stream:
                        member = stream.read(MAX_MEMBER_BYTES + 1)
                    if len(member) > MAX_MEMBER_BYTES:
                        raise ValueError("member_too_large")
                    total += len(member)
                    if total > MAX_TOTAL_BYTES:
                        raise ValueError("archive_too_large")
                    extracted.append((entry.filename, member))
                return {"ok": True, "success": True, "encrypted": True,
                        "algorithm": "ZipCrypto", "password": password,
                        "attempts": normalized.index(password) + 1,
                        "candidate_count": len(normalized), "members": extracted,
                        "filename": filename}
            except (RuntimeError, zipfile.BadZipFile, OSError, ValueError, EOFError):
                continue
    return {"ok": True, "success": False, "encrypted": True,
            "algorithm": "ZipCrypto", "attempts": len(normalized),
            "candidate_count": len(normalized),
            "error": "لم تطابق أي كلمة مرور من القائمة الأرشيف. أضف كلمات مرشحة مستندة إلى وصف التحدي أو ملف الكلمات المرفق."}


def locate_rockyou(analysis_root: Path | None = None, falcon_home: Path | None = None) -> Path | None:
    """Find a user-provided RockYou list in standard local training locations."""
    analysis_root = Path(analysis_root) if analysis_root is not None else Path(r"C:\Falcon\analysis")
    falcon_home = Path(falcon_home) if falcon_home is not None else Path(r"C:\Falcon")
    roots = (
        analysis_root, analysis_root / "wordlists", falcon_home,
        falcon_home / "wordlists", Path(__file__).resolve().parent / "wordlists",
        Path.home() / "wordlists", Path("/usr/share/wordlists"),
        Path("/usr/share/seclists/Passwords/Common-Credentials"),
    )
    for root in roots:
        for name in WORDLIST_NAMES:
            candidate = root / name
            if candidate.is_file():
                return candidate
    return None


def _clue_candidates(challenge_text: str) -> tuple[list[str], list[str], bool]:
    """Translate a few explicit CTF clue patterns into ranked password guesses."""
    text = unicodedata.normalize("NFKC", challenge_text or "").lower()
    values: list[str] = []
    reasons: list[str] = []
    wordlist_hint = bool(re.search(r"rock\s*you|rockyou|قائمة.{0,50}(?:متسرّب|متسرب|مسرب|شهيرة)|(?:كلمات|كلمة مرور).{0,60}(?:متسرّب|متسرب|مسرب)", text))

    morning = any(term in text for term in ("كل صباح", "كل صباحًا", "يطل كل صباح", "الصباح", "morning", "sunrise", "dawn"))
    warmth = any(term in text for term in ("الدفء", "دفء", "الحرارة", "الشمس", "يبعث الدفء", "warmth", "warm", "heat", "sun"))
    if morning and warmth:
        values.extend(("sunshine", "sunrise", "sunlight", "sun", "sunny", "morning", "sunbeam", "warmth", "heat"))
        reasons.append("قرينة الصباح والدفء تشير إلى sunshine")
    elif any(term in text for term in ("الشمس", "sunshine", "sunlight", "sunbeam")):
        values.extend(("sunshine", "sunlight", "sunbeam", "sun", "sunny"))
        reasons.append("قرينة الشمس تشير إلى كلمات مرتبطة بها")

    # Include a short, bounded set of literal words from the supplied challenge
    # text after semantic guesses, while filtering narrative boilerplate.
    stop = _GENERIC | {"the", "and", "for", "with", "from", "this", "that", "can", "you",
                       "your", "into", "about", "challenge", "passwords", "password", "zipcrypto",
                       "المهمة", "التحدي", "كلمة", "كلمات", "مرور", "قائمة", "تلميح", "التلميح",
                       "شيء", "الذي", "التي", "على", "من", "في", "إلى", "هذا", "هذه", "ذلك",
                       "لكن", "ليس", "بل", "قبل", "كل", "صباح", "الدفء", "يطل", "يبعث"}
    literal = []
    for token in _TOKEN.findall(text):
        token = token.strip("._-!@ ")
        if len(token) >= 4 and token not in stop and not token.isdecimal() and token not in literal:
            literal.append(token)
        if len(literal) >= 120:
            break
    values.extend(literal)
    return list(dict.fromkeys(values)), reasons, wordlist_hint


def derive_candidates(data: bytes, filename: str = "challenge.zip", challenge_text: str = "",
                      analysis_root: Path | None = None, falcon_home: Path | None = None,
                      include_wordlist: bool = True) -> tuple[list[str], list[str]]:
    """Build candidates from challenge hints, archive evidence, then local RockYou."""
    evidence: list[tuple[str, str]] = [("اسم الأرشيف", filename)]
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if archive.comment:
                evidence.append(("تعليق الأرشيف", _decode_text(archive.comment)))
            for entry in archive.infolist()[:MAX_CANDIDATES]:
                evidence.append(("اسم ملف داخل الأرشيف", entry.filename))
                year, month, day, hour, minute, second = entry.date_time
                date_candidates = (
                    f"{year:04d}{month:02d}{day:02d}", f"{day:02d}{month:02d}{year:04d}",
                    f"{year:04d}-{month:02d}-{day:02d}", f"{day:02d}-{month:02d}-{year:04d}",
                    f"{month:02d}{day:02d}{year:04d}", f"{year:04d}{month:02d}{day:02d}{hour:02d}{minute:02d}",
                    f"{hour:02d}{minute:02d}{second:02d}", f"{year:04d}",
                )
                evidence.append(("تاريخ ووقت ZIP", " ".join(date_candidates)))
                if entry.comment:
                    evidence.append(("تعليق ملف", _decode_text(entry.comment)))
                if not entry.is_dir() and not (entry.flag_bits & 1) and entry.file_size <= 256_000:
                    try:
                        with archive.open(entry) as stream:
                            content = stream.read(256_001)
                        if len(content) <= 256_000:
                            evidence.append(("محتوى غير مشفّر داخل الأرشيف", _decode_text(content)))
                    except (OSError, RuntimeError, zipfile.BadZipFile):
                        continue
    except (OSError, zipfile.BadZipFile, ValueError):
        return [], []

    candidates: list[str] = []
    seen: set[str] = set()
    used_sources: list[str] = []

    def add(value: str) -> None:
        value = unicodedata.normalize("NFKC", value).strip().strip("._-!@ ")
        if not value or len(value) > MAX_PASSWORD_LENGTH or len(value) < 3 or value in seen:
            return
        seen.add(value)
        candidates.append(value)

    clue_values, clue_reasons, wordlist_hint = _clue_candidates(challenge_text)
    for value in clue_values:
        add(value)
    if challenge_text.strip():
        used_sources.append("وصف التحدي وتلميحاته")

    rot13 = str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm")
    for source, text in evidence:
        if not text:
            continue
        if source not in used_sources:
            used_sources.append(source)
        normalized = unicodedata.normalize("NFKC", text)
        tokens = _TOKEN.findall(normalized)
        meaningful: list[str] = []
        for token in tokens:
            stem = token.rsplit(".", 1)[0] if "." in token else token
            if source == "اسم ملف داخل الأرشيف":
                # File names themselves are useful candidates even when generic
                # (for example, challenges sometimes use "flag" as the password).
                add(stem)
            if stem.lower() in _GENERIC or len(stem) < 3:
                continue
            meaningful.append(stem)
            add(stem)
            add(stem.lower())
            add(stem.upper())
            add(stem[::-1])
            if stem.isascii() and stem.isalpha():
                add(stem.translate(rot13))

        # Try adjacent clue terms and numeric suffixes before punctuation variants.
        for left, right in zip(meaningful, meaningful[1:]):
            if len(left) <= 20 and len(right) <= 20:
                for separator in ("", "_", "-", "!"):
                    add(left + separator + right)
        numbers = list(dict.fromkeys(re.findall(r"\d{1,4}", normalized)))[:20]
        for word in meaningful[:80]:
            if len(word) <= 24:
                for number in numbers:
                    add(word + number)
                    add(word.lower() + number)
        if len(candidates) >= MAX_EVIDENCE_CANDIDATES:
            break
    wordlist = locate_rockyou(analysis_root, falcon_home) if include_wordlist else None
    if wordlist and len(candidates) < MAX_AUTO_CANDIDATES:
        try:
            opener = gzip.open if wordlist.suffix.lower() == ".gz" else open
            with opener(wordlist, "rt", encoding="utf-8", errors="ignore") as stream:
                for index, line in enumerate(stream):
                    if index >= MAX_WORDLIST_CANDIDATES or len(candidates) >= MAX_AUTO_CANDIDATES:
                        break
                    add(line.rstrip("\r\n"))
            used_sources.append("قائمة RockYou المحلية" + (" (قرينة قائمة كلمات مسرّبة)" if wordlist_hint else ""))
        except (OSError, EOFError, gzip.BadGzipFile):
            used_sources.append("تعذر قراءة قائمة RockYou المحلية")
    return candidates[:MAX_AUTO_CANDIDATES], list(dict.fromkeys(used_sources))


def recover_zip_auto(data: bytes, filename: str = "challenge.zip", challenge_text: str = "",
                     analysis_root: Path | None = None, falcon_home: Path | None = None) -> dict:
    """Try semantic/archive clues first; read RockYou only if those candidates fail."""
    clue_values, clue_reasons, wordlist_hint = _clue_candidates(challenge_text)
    wordlist = locate_rockyou(analysis_root, falcon_home)
    info = inspect_zip(data, filename)
    if not info.get("is_zip"):
        return {"ok": False, "success": False, "error": "الملف ليس أرشيف ZIP صالحًا."}
    if not info.get("encrypted"):
        return {"ok": False, "success": False, "encrypted": False,
                "error": "الأرشيف غير مشفّر؛ استخدم فحص الملفات العادي."}

    primary, primary_sources = derive_candidates(data, filename, challenge_text,
        analysis_root, falcon_home, include_wordlist=False)
    primary_result = recover_zip(data, primary, filename) if primary else {
        "ok": True, "success": False, "attempts": 0, "candidate_count": 0,
        "algorithm": info.get("algorithm"), "encrypted": True}
    sources = list(primary_sources)
    result = primary_result
    wordlist_tried = 0

    # Keep RockYou as a true fallback: don't read or test the large list when a
    # semantic or archive clue already unlocked the file.
    if not primary_result.get("success") and wordlist:
        all_candidates, all_sources = derive_candidates(data, filename, challenge_text,
            analysis_root, falcon_home, include_wordlist=True)
        dictionary_candidates = all_candidates[len(primary):]
        sources = all_sources
        if dictionary_candidates:
            dictionary_result = recover_zip(data, dictionary_candidates, filename)
            wordlist_tried = dictionary_result.get("attempts", 0)
            sources = [item for item in sources if not item.startswith("قائمة RockYou المحلية")]
            if wordlist_tried:
                sources.append("قائمة RockYou المحلية: جُرّب %s كلمة" % wordlist_tried)
            dictionary_result["attempts"] = primary_result.get("attempts", 0) + wordlist_tried
            dictionary_result["candidate_count"] = dictionary_result["attempts"]
            result = dictionary_result

    if not primary and not wordlist:
        return {"ok": True, "success": False, "encrypted": info.get("encrypted", False),
                "algorithm": info.get("algorithm"), "attempts": 0, "candidate_count": 0,
                "evidence_sources": sources, "clue_matches": clue_reasons,
                "wordlist_available": bool(wordlist),
                "error": "لم يجد صقر مرشحات كافية. ألصق وصف التحدي وتلميحاته، أو ضع rockyou.txt في C:\\Falcon\\analysis."}

    result["evidence_sources"] = sources
    result["candidate_count"] = result.get("attempts", 0)
    result["clue_matches"] = clue_reasons
    result["wordlist_available"] = bool(wordlist)
    result["wordlist_candidates"] = wordlist_tried
    result["wordlist_hint"] = wordlist_hint
    result["explanation_ar"] = clue_reasons
    if not result.get("success"):
        result["error"] = ("فحص صقر وصف التحدي وأدلة الأرشيف" + (" وقائمة RockYou المحلية" if wordlist else "") +
                           " ولم يجد كلمة المرور. " + ("ضع rockyou.txt في C:\\Falcon\\analysis ثم أعد المحاولة. " if wordlist_hint and not wordlist else "") +
                           "كلمة المرور لا تُحفظ عادةً داخل ZIP المشفّر.")
    return result


def _decode_text(data: bytes | str) -> str:
    if isinstance(data, str):
        return data
    for encoding in ("utf-8-sig", "utf-16", "cp1252", "latin-1"):
        try:
            text = data.decode(encoding)
            if text and sum(ch.isprintable() or ch.isspace() for ch in text) / len(text) > 0.8:
                return text
        except (UnicodeError, ZeroDivisionError):
            continue
    return ""


def _recover_with_pyzipper(data, candidates, filename, info, pyzipper):
    normalized = []
    seen = set()
    for item in candidates:
        password = str(item).rstrip("\r\n")
        if password and len(password) <= MAX_PASSWORD_LENGTH and password not in seen:
            normalized.append(password)
            seen.add(password)
        if len(normalized) >= MAX_CANDIDATES:
            break
    for index, password in enumerate(normalized, 1):
        try:
            with pyzipper.AESZipFile(io.BytesIO(data)) as archive:
                archive.setpassword(password.encode("utf-8"))
                members = []
                total = 0
                for entry in archive.infolist():
                    if entry.is_dir():
                        continue
                    with archive.open(entry) as stream:
                        content = stream.read(MAX_MEMBER_BYTES + 1)
                    total += len(content)
                    if len(content) > MAX_MEMBER_BYTES or total > MAX_TOTAL_BYTES:
                        raise ValueError("archive_too_large")
                    members.append((entry.filename, content))
                return {"ok": True, "success": True, "encrypted": True,
                        "algorithm": "WinZip AES", "password": password,
                        "attempts": index, "candidate_count": len(normalized),
                        "members": members, "filename": filename}
        except Exception:
            continue
    return {"ok": True, "success": False, "encrypted": True,
            "algorithm": "WinZip AES", "attempts": len(normalized),
            "candidate_count": len(normalized),
            "error": "لم تطابق أي كلمة مرور من القائمة المقدمة."}
