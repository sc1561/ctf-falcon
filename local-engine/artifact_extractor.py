"""Bounded, read-only recursive CTF artifact scanner for the localhost engine."""
from __future__ import annotations

import base64
import bz2
import hashlib
import io
import lzma
import re
import tarfile
import urllib.parse
import zipfile
import zlib
from collections import deque
from pathlib import PurePosixPath

MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_CHILD_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 96 * 1024 * 1024
MAX_NODES = 220
MAX_DEPTH = 6
MAX_ARCHIVE_ENTRIES = 250
MAX_DECODES_PER_NODE = 32
DOWNLOAD_LIMIT = 1024 * 1024

FLAG_RE = re.compile(r"(?i)(?:[A-Za-z][A-Za-z0-9_.:-]{1,30})\{[^{}\r\n]{2,200}\}")
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/_-])")
HEX_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}[\s:]*){12,}(?![0-9A-Fa-f])")
PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")


def _safe_name(value: str) -> str:
    value = str(value or "upload.bin").replace("\\", "/")
    parts = [p for p in PurePosixPath(value).parts if p not in ("/", "", ".", "..")]
    return "/".join(parts)[-240:] or "upload.bin"


def _kind(data: bytes, name: str) -> str:
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
        return "ZIP"
    if data.startswith(b"\x1f\x8b"):
        return "GZIP"
    if data.startswith(b"BZh"):
        return "BZIP2"
    if data.startswith(b"\xfd7zXZ\x00"):
        return "XZ"
    if len(data) > 2 and data[0] == 0x78 and ((data[0] << 8) | data[1]) % 31 == 0:
        return "ZLIB"
    if data.startswith(b"%PDF-"):
        return "PDF"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG"
    if data.startswith(b"\xff\xd8\xff"):
        return "JPEG"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "GIF"
    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7Z"
    if data.startswith(b"Rar!\x1a\x07"):
        return "RAR"
    if len(data) >= 4 and data[:4] == b"\x7fELF":
        return "ELF"
    suffix = PurePosixPath(name).suffix.lower()
    return {".tar": "TAR", ".tgz": "GZIP", ".gz": "GZIP", ".bz2": "BZIP2", ".xz": "XZ"}.get(suffix, "FILE")


def _bounded_read(stream, limit: int) -> bytes:
    return stream.read(limit + 1)


def _decompress(data: bytes, kind: str, limit: int) -> bytes | None:
    try:
        if kind == "GZIP":
            obj = zlib.decompressobj(16 + zlib.MAX_WBITS)
            out = obj.decompress(data, limit + 1)
        elif kind == "ZLIB":
            obj = zlib.decompressobj()
            out = obj.decompress(data, limit + 1)
        elif kind == "BZIP2":
            obj = bz2.BZ2Decompressor()
            out = obj.decompress(data, max_length=limit + 1)
        elif kind == "XZ":
            obj = lzma.LZMADecompressor()
            out = obj.decompress(data, max_length=limit + 1)
        else:
            return None
        return out if out and len(out) <= limit else None
    except (OSError, EOFError, ValueError, zlib.error, lzma.LZMAError):
        return None


def _text_views(data: bytes) -> list[str]:
    views: list[str] = []
    for encoding in ("utf-8-sig", "utf-16", "utf-16-le", "utf-16-be"):
        try:
            text = data.decode(encoding)
        except (UnicodeError, LookupError):
            continue
        clean = sum(ch.isprintable() or ch in "\r\n\t" for ch in text) / max(1, len(text))
        if clean >= 0.72 and text.strip() and text not in views:
            views.append(text)
    strings = "\n".join(x.decode("ascii", "ignore") for x in PRINTABLE_RE.findall(data))
    if strings and strings not in views:
        views.append(strings)
    return views[:3]


def _is_tar(data: bytes) -> bool:
    if len(data) < 512:
        return False
    try:
        return tarfile.is_tarfile(io.BytesIO(data))
    except (OSError, tarfile.TarError):
        return False


def _decode_text(text: str) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []

    def add(label: str, value: bytes):
        if value and len(value) <= MAX_CHILD_BYTES and all(existing[1] != value for existing in out):
            out.append((label, value))

    for match in list(BASE64_RE.finditer(text))[:MAX_DECODES_PER_NODE]:
        token = match.group(0)
        if len(token) % 4 == 1:
            continue
        token += "=" * ((4 - len(token) % 4) % 4)
        try:
            add("Base64", base64.urlsafe_b64decode(token.encode("ascii")))
        except (ValueError, base64.binascii.Error):
            pass
    for match in list(HEX_RE.finditer(text))[:MAX_DECODES_PER_NODE]:
        token = re.sub(r"[\s:]", "", match.group(0))
        if len(token) >= 24 and len(token) % 2 == 0:
            try:
                add("Hex", bytes.fromhex(token))
            except ValueError:
                pass
    stripped = text.strip()
    if 32 <= len(stripped) <= MAX_CHILD_BYTES * 8 and re.fullmatch(r"[01\s]+", stripped):
        bits = re.sub(r"\s", "", stripped)
        if len(bits) % 8 == 0:
            try:
                add("Binary", bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8)))
            except ValueError:
                pass
    url_text = urllib.parse.unquote(text)
    if url_text != text:
        add("URL Decode", url_text.encode("utf-8", "replace"))
    if "\\x" in text or "\\u" in text:
        try:
            unescaped = bytes(text, "utf-8").decode("unicode_escape")
            if unescaped != text:
                add("Escape Decode", unescaped.encode("utf-8", "replace"))
        except (UnicodeError, ValueError):
            pass
    # Try ROT13 only when it produces a flag-shaped value or recognizable CTF clue.
    if not FLAG_RE.search(text) and re.search(r"[A-Za-z]{5,}", text):
        import codecs
        rotated = codecs.decode(text, "rot_13")
        if FLAG_RE.search(rotated) or re.search(r"(?i)\b(flag|secret|password|picoctf)\b", rotated):
            add("ROT13", rotated.encode("utf-8", "replace"))
    return out


def analyze_artifact(data: bytes, filename: str = "upload.bin") -> dict:
    """Inspect an uploaded artifact recursively without writing files to disk."""
    if not isinstance(data, (bytes, bytearray)) or not data:
        raise ValueError("الملف فارغ أو غير صالح.")
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError("حجم الملف أكبر من الحد المسموح (64 ميغابايت).")

    root_name = _safe_name(filename)
    queue = deque([(root_name, bytes(data), 0, "الملف المرفوع")])
    seen: set[str] = set()
    flags: dict[str, dict] = {}
    artifacts: list[dict] = []
    findings: list[str] = []
    total_bytes = len(data)
    scanned = 0
    truncated = False

    def enqueue(parent: str, label: str, child: bytes, depth: int):
        nonlocal total_bytes, truncated
        if not child or len(child) > MAX_CHILD_BYTES:
            truncated = truncated or bool(child)
            return
        digest = hashlib.sha256(child).hexdigest()
        if digest in seen:
            return
        if depth > MAX_DEPTH or len(queue) + scanned >= MAX_NODES or total_bytes + len(child) > MAX_TOTAL_BYTES:
            truncated = True
            return
        child_name = _safe_name(label)
        path = parent + " → " + child_name
        item = {"path": path, "name": child_name, "kind": _kind(child, child_name),
                "size": len(child), "sha256": digest}
        if len(artifacts) < 80 and len(child) <= DOWNLOAD_LIMIT and len(artifacts) < 8:
            item["download_b64"] = base64.b64encode(child).decode("ascii")
        artifacts.append(item)
        total_bytes += len(child)
        queue.append((path, child, depth, label))

    while queue and scanned < MAX_NODES:
        path, blob, depth, origin = queue.popleft()
        digest = hashlib.sha256(blob).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        scanned += 1
        kind = _kind(blob, path)

        views = _text_views(blob)
        for text in views:
            for match in FLAG_RE.finditer(text):
                flags.setdefault(match.group(0), {"flag": match.group(0), "path": path, "offset": match.start()})
            if depth < MAX_DEPTH:
                for decoder, decoded in _decode_text(text):
                    decoded_kind = _kind(decoded, path)
                    if decoded_kind != "FILE" or decoded.startswith((b"PK", b"\x1f\x8b", b"%PDF", b"\x89PNG", b"\xff\xd8")) or _text_views(decoded):
                        enqueue(path, "decoded." + decoder.lower().replace(" ", "_") + ".bin", decoded, depth + 1)

        if depth >= MAX_DEPTH:
            truncated = True
            continue

        if kind == "ZIP":
            try:
                with zipfile.ZipFile(io.BytesIO(blob)) as archive:
                    for index, info in enumerate(archive.infolist()):
                        if index >= MAX_ARCHIVE_ENTRIES:
                            truncated = True
                            break
                        if info.is_dir():
                            continue
                        if info.file_size > MAX_CHILD_BYTES:
                            truncated = True
                            continue
                        try:
                            with archive.open(info) as member:
                                child = _bounded_read(member, MAX_CHILD_BYTES)
                            if len(child) <= MAX_CHILD_BYTES:
                                enqueue(path, info.filename, child, depth + 1)
                            else:
                                truncated = True
                        except (OSError, RuntimeError, zipfile.BadZipFile):
                            findings.append("تعذر قراءة عنصر ZIP: " + _safe_name(info.filename))
            except (OSError, zipfile.BadZipFile, ValueError):
                findings.append("توقيع ZIP موجود لكن الأرشيف غير مكتمل أو تالف: " + path)
        elif kind == "TAR" or path.lower().endswith((".tar", ".tar.gz", ".tgz")) or _is_tar(blob):
            try:
                with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as archive:
                    for index, info in enumerate(archive):
                        if index >= MAX_ARCHIVE_ENTRIES:
                            truncated = True
                            break
                        if not info.isfile() or info.size > MAX_CHILD_BYTES:
                            if info.size > MAX_CHILD_BYTES:
                                truncated = True
                            continue
                        member = archive.extractfile(info)
                        if member:
                            with member:
                                child = _bounded_read(member, MAX_CHILD_BYTES)
                            if len(child) <= MAX_CHILD_BYTES:
                                enqueue(path, info.name, child, depth + 1)
                            else:
                                truncated = True
            except (OSError, tarfile.TarError, EOFError):
                findings.append("تعذر قراءة أرشيف TAR: " + path)
        elif kind in {"GZIP", "BZIP2", "XZ", "ZLIB"}:
            child = _decompress(blob, kind, MAX_CHILD_BYTES)
            if child:
                derived = re.sub(r"\.(gz|bz2|xz|zlib)$", "", path.split(" → ")[-1], flags=re.I) or "decompressed.bin"
                enqueue(path, derived, child, depth + 1)
            else:
                findings.append("لم يُفك الضغط بسبب تلف البيانات أو تجاوز حد فك الضغط: " + path)

        # Recover common file signatures embedded after headers or inside polyglots.
        signatures = ((b"PK\x03\x04", "embedded.zip"), (b"%PDF-", "embedded.pdf"),
                      (b"\x89PNG\r\n\x1a\n", "embedded.png"), (b"\xff\xd8\xff", "embedded.jpg"),
                      (b"\x1f\x8b", "embedded.gz"))
        for signature, label in signatures:
            offset = blob.find(signature, 1)
            if offset >= 0:
                enqueue(path, label + "@" + str(offset), blob[offset:], depth + 1)

    if queue:
        truncated = True
    artifact_view = [{k: v for k, v in item.items() if k != "download_b64"} for item in artifacts]
    return {
        "ok": True,
        "filename": root_name,
        "input_bytes": len(data),
        "scanned_nodes": scanned,
        "extracted_count": len(artifacts),
        "expanded_bytes": total_bytes,
        "truncated": truncated,
        "flags": list(flags.values()),
        "artifacts": artifacts,
        "findings": list(dict.fromkeys(findings))[:80],
        "summary": "تم فحص الملف ومحتوياته المتداخلة محليًا." if not truncated else "اكتمل الفحص ضمن حدود الحجم والعمق؛ قد تكون بعض العناصر الكبيرة أو العميقة غير مفحوصة.",
    }
