"""Inspect and perform bounded, wordlist-only recovery for encrypted CTF ZIPs."""
from __future__ import annotations

import io
import zipfile
from pathlib import PurePosixPath

MAX_CANDIDATES = 20_000
MAX_PASSWORD_LENGTH = 128
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024


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
