"""Inspect encrypted CTF ZIPs and derive bounded password candidates from evidence."""
from __future__ import annotations

import io
import re
import unicodedata
import zipfile
from pathlib import PurePosixPath

MAX_CANDIDATES = 20_000
MAX_PASSWORD_LENGTH = 128
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_AUTO_CANDIDATES = 10_000
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


def derive_candidates(data: bytes, filename: str = "challenge.zip") -> tuple[list[str], list[str]]:
    """Build a ranked candidate set only from clues physically inside this ZIP.

    Evidence sources are the archive/member names, ZIP comments, and readable
    contents of unencrypted members. A correctly encrypted archive does not
    normally contain its own password, so this is a bounded heuristic search.
    """
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
        if len(candidates) >= MAX_AUTO_CANDIDATES:
            break
    return candidates[:MAX_AUTO_CANDIDATES], list(dict.fromkeys(used_sources))


def recover_zip_auto(data: bytes, filename: str = "challenge.zip") -> dict:
    """Try password candidates automatically derived from evidence in the ZIP."""
    candidates, sources = derive_candidates(data, filename)
    if not candidates:
        info = inspect_zip(data, filename)
        return {"ok": True, "success": False, "encrypted": info.get("encrypted", False),
                "algorithm": info.get("algorithm"), "attempts": 0, "candidate_count": 0,
                "evidence_sources": sources,
                "error": "لم يجد صقر نصًا أو تلميحًا قابلًا للاستخدام داخل الأرشيف. كلمة المرور لا تُحفظ عادةً داخل ZIP المشفّر؛ يمكن إضافة تلميح التحدي أو استخدام المسار اليدوي."}
    result = recover_zip(data, candidates, filename)
    result["evidence_sources"] = sources
    result["candidate_count"] = len(candidates)
    if not result.get("success"):
        result["error"] = ("فحص صقر أسماء الملفات والتعليقات والمحتوى غير المشفّر داخل الأرشيف، ولم يجد كلمة المرور. "
                           "قد لا تكفي الأدلة الموجودة في الملف وحده؛ كلمة المرور ليست محفوظة عادةً داخل ZIP المشفّر.")
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
