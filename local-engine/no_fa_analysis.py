"""Read-only analysis helpers for the picoCTF No FA challenge artifacts."""
from __future__ import annotations

import base64
import hashlib
import json
import re
import sqlite3
import zlib
from pathlib import Path

MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_DATABASE_BYTES = 64 * 1024 * 1024
MAX_WORDLIST_BYTES = 256 * 1024 * 1024
BUILTIN_CANDIDATES = (
    "apple@123", "password", "Password123", "admin", "123456", "qwerty",
    "letmein", "welcome", "iloveyou", "P@ssw0rd", "changeme",
)
WORDLIST_NAMES = ("rockyou.txt", "passwords.txt", "wordlist.txt", "common-passwords.txt")


def _read_candidate_words(folder: Path):
    for candidate in BUILTIN_CANDIDATES:
        yield candidate, "built-in"
    for name in WORDLIST_NAMES:
        path = folder / name
        try:
            if not path.is_file() or path.stat().st_size > MAX_WORDLIST_BYTES:
                continue
            with path.open("r", encoding="utf-8", errors="ignore") as stream:
                for line in stream:
                    word = line.rstrip("\r\n")
                    if word:
                        yield word, name
        except OSError:
            continue


def analyze_artifacts(folder: str | Path) -> dict:
    """Inspect only app.py and users.db under the configured analysis folder."""
    root = Path(folder).resolve()
    source_path, database_path = root / "app.py", root / "users.db"
    result = {
        "ok": True,
        "folder": str(root),
        "files": {
            "app.py": {"exists": source_path.is_file(), "bytes": source_path.stat().st_size if source_path.is_file() else 0},
            "users.db": {"exists": database_path.is_file(), "bytes": database_path.stat().st_size if database_path.is_file() else 0},
        },
        "account_count": 0,
        "admin": {"exists": False, "two_fa": None, "password_candidate": None},
        "source_findings": [],
        "wordlist_used": [],
        "next_steps": [],
    }

    source = ""
    if source_path.is_file() and source_path.stat().st_size <= MAX_SOURCE_BYTES:
        try:
            source = source_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
    if re.search(r"hashlib\.sha256\s*\(", source):
        result["source_findings"].append("passwords_sha256_unsalted")
    if re.search(r"session\s*\[\s*['\"]otp_secret['\"]\s*\]\s*=", source):
        result["source_findings"].append("otp_stored_in_flask_session")
    if re.search(r"random\.randint\s*\(\s*1000\s*,\s*9999\s*\)", source):
        result["source_findings"].append("four_digit_otp")
    if re.search(r"time\.time\(\)\s*-\s*timestamp\s*\)\s*<\s*120", source):
        result["source_findings"].append("otp_valid_for_120_seconds")

    if database_path.is_file() and database_path.stat().st_size <= MAX_DATABASE_BYTES:
        try:
            uri = database_path.as_uri() + "?mode=ro"
            with sqlite3.connect(uri, uri=True, timeout=2) as connection:
                connection.execute("PRAGMA query_only=ON")
                table = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='users'"
                ).fetchone()
                if table:
                    rows = connection.execute(
                        "SELECT username, password, two_fa FROM users"
                    ).fetchall()
                    result["account_count"] = len(rows)
                    admin_hash = next((str(h) for u, h, _ in rows if u == "admin"), None)
                    admin_two_fa = next((bool(two_fa) for u, _, two_fa in rows if u == "admin"), None)
                    result["admin"].update({"exists": admin_hash is not None, "two_fa": admin_two_fa})
                    if admin_hash and re.fullmatch(r"[0-9a-fA-F]{64}", admin_hash):
                        for candidate, source_name in _read_candidate_words(root):
                            if hashlib.sha256(candidate.encode("utf-8")).hexdigest().lower() == admin_hash.lower():
                                result["admin"]["password_candidate"] = candidate
                                if source_name != "built-in":
                                    result["wordlist_used"].append(source_name)
                                break
        except (OSError, sqlite3.Error, UnicodeError) as exc:
            result["database_error"] = str(exc)[:240]

    if result["files"]["app.py"]["exists"] and result["files"]["users.db"]["exists"]:
        result["next_steps"] = [
            "log_in_as_admin_with_recovered_password",
            "read_otp_secret_from_the_flask_session_cookie",
            "submit_otp_within_120_seconds",
        ]
    else:
        result["next_steps"] = ["save_app.py_and_users.db_in_analysis_folder"]
    return result


def decode_flask_session(cookie: str) -> dict:
    """Decode Flask's client-side session payload; this does not verify its signature."""
    raw = str(cookie or "").strip()
    if raw.lower().startswith("session="):
        raw = raw.split("=", 1)[1].strip()
    first = raw.split(".", 2)[0]
    compressed = first == ""
    payload = raw.split(".", 2)[1] if compressed else first
    if not payload or len(payload) > 32768:
        raise ValueError("Invalid Flask session cookie")
    payload += "=" * ((4 - len(payload) % 4) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload.encode("ascii"))
        if compressed:
            decoded = zlib.decompress(decoded)
        data = json.loads(decoded.decode("utf-8"))
    except Exception as exc:
        raise ValueError("Could not decode the Flask session payload") from exc
    if not isinstance(data, dict):
        raise ValueError("Flask session payload is not an object")
    return {
        "ok": True,
        "signature_verified": False,
        "username": data.get("username"),
        "logged": data.get("logged"),
        "otp_secret": data.get("otp_secret"),
        "otp_timestamp": data.get("otp_timestamp"),
    }
