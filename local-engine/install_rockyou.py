"""Download RockYou once into the local Falcon analysis directory."""
from __future__ import annotations

import os
import sys
import urllib.request
from pathlib import Path

URL = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
MAX_BYTES = 180 * 1024 * 1024


def install(destination: Path | None = None) -> Path:
    root = Path(destination) if destination else Path(r"C:\Falcon\analysis")
    root.mkdir(parents=True, exist_ok=True)
    target = root / "rockyou.txt"
    partial = root / "rockyou.txt.download"
    request = urllib.request.Request(URL, headers={"User-Agent": "Falcon-CTF-Local-Engine/2.54"})
    total = 0
    try:
        with urllib.request.urlopen(request, timeout=40) as response, partial.open("wb") as output:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_BYTES:
                    raise ValueError("حجم التنزيل تجاوز الحد 180 ميغابايت.")
                output.write(chunk)
        if total < 10 * 1024 * 1024:
            raise ValueError("الملف المستلم أصغر من المتوقع؛ أُلغي التثبيت.")
        with partial.open("rb") as source:
            sample = source.read(4096)
        if b"<html" in sample.lower() or b"<!doctype" in sample.lower():
            raise ValueError("المصدر أعاد صفحة HTML بدل قائمة كلمات.")
        os.replace(partial, target)
        return target
    except Exception:
        try:
            partial.unlink(missing_ok=True)
        except OSError:
            pass
        raise


if __name__ == "__main__":
    try:
        result = install(Path(sys.argv[1]) if len(sys.argv) > 1 else None)
        print("تم تثبيت RockYou في:", result)
        print("سيستخدمها صقر تلقائيًا في البحث المحلي عن كلمات مرور ZIP.")
    except Exception as error:
        print("تعذر تثبيت RockYou:", error, file=sys.stderr)
        raise SystemExit(1)
