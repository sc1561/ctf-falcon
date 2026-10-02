"""Small dependency-free PCAP/PCAPNG DNS triage for local CTF evidence."""
from __future__ import annotations

import collections
import csv
import decimal
import re
import shutil
import socket
import struct
import subprocess
import tempfile
from pathlib import Path


def is_capture(data: bytes, filename: str = "") -> bool:
    return data.startswith(b"\x0a\x0d\x0d\x0a") or data[:4] in {
        b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
    } or str(filename).lower().endswith((".pcap", ".pcapng", ".cap"))


def _options(data: bytes, offset: int, endian: str) -> dict[int, list[bytes]]:
    result: dict[int, list[bytes]] = collections.defaultdict(list)
    while offset + 4 <= len(data):
        code, size = struct.unpack_from(endian + "HH", data, offset)
        offset += 4
        if code == 0:
            break
        result[code].append(data[offset:offset + size])
        offset += (size + 3) & ~3
    return result


def _blocks(data: bytes):
    offset, endian, interfaces = 0, "<", []
    frames = []
    while offset + 12 <= len(data):
        raw_type = struct.unpack_from("<I", data, offset)[0]
        if raw_type == 0x0A0D0D0A:
            if offset + 12 > len(data):
                break
            bom = data[offset + 8:offset + 12]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise ValueError("ترويسة PCAPNG غير صالحة.")
            block_len = struct.unpack_from(endian + "I", data, offset + 4)[0]
            if block_len < 28 or offset + block_len > len(data):
                raise ValueError("كتلة Section Header غير مكتملة.")
            interfaces = []
            offset += block_len
            continue

        block_type, block_len = struct.unpack_from(endian + "II", data, offset)
        if block_len < 12 or offset + block_len > len(data):
            raise ValueError("كتلة PCAPNG غير مكتملة.")
        block = data[offset:offset + block_len]
        if block_type == 1:  # Interface Description Block
            linktype = struct.unpack_from(endian + "H", block, 8)[0]
            opts = _options(block, 16, endian)
            resolution = 1_000_000.0
            if opts.get(9):
                value = opts[9][0][0]
                resolution = (2 ** (value & 0x7f)) if value & 0x80 else (10 ** value)
            tsoffset = 0
            if opts.get(14) and len(opts[14][0]) == 8:
                tsoffset = struct.unpack(endian + "q", opts[14][0])[0]
            interfaces.append((linktype, resolution, tsoffset))
        elif block_type == 6 and len(block) >= 32:  # Enhanced Packet Block
            iface, high, low, caplen, _origlen = struct.unpack_from(endian + "IIIII", block, 8)
            if iface < len(interfaces) and 28 + caplen <= len(block) - 4:
                linktype, resolution, tsoffset = interfaces[iface]
                # Store nanoseconds as an integer so a 1e9 timestamp
                # resolution does not lose precision through large floats.
                ticks = (high << 32) | low
                resolution_int = int(resolution)
                if resolution_int > 0 and 1_000_000_000 % resolution_int == 0:
                    timestamp = ticks * (1_000_000_000 // resolution_int)
                else:
                    timestamp = round(ticks * 1_000_000_000 / resolution)
                timestamp += tsoffset * 1_000_000_000
                frames.append((timestamp, linktype, block[28:28 + caplen]))
        elif block_type == 3 and interfaces and len(block) >= 16:  # Simple Packet Block
            origlen = struct.unpack_from(endian + "I", block, 8)[0]
            linktype = interfaces[0][0]
            frames.append((None, linktype, block[12:min(12 + origlen, len(block) - 4)]))
        offset += block_len
    return frames


def _classic_frames(data: bytes):
    magic = data[:4]
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    if len(data) < 24:
        raise ValueError("ترويسة PCAP غير مكتملة.")
    _major, _minor, _zone, _sigfigs, _snaplen, linktype = struct.unpack_from(endian + "HHiiii", data, 4)
    offset, frames = 24, []
    while offset + 16 <= len(data):
        sec, frac, caplen, _origlen = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if caplen > len(data) - offset:
            break
        timestamp = sec * 1_000_000_000 + (frac if nano else frac * 1_000)
        frames.append((timestamp, linktype, data[offset:offset + caplen]))
        offset += caplen
    return frames


def _dns_name(payload: bytes, offset: int):
    labels, cursor, resume, seen = [], offset, None, set()
    while cursor < len(payload):
        if cursor in seen:
            break
        seen.add(cursor)
        size = payload[cursor]
        if size == 0:
            cursor += 1
            break
        if size & 0xC0 == 0xC0:
            if cursor + 1 >= len(payload):
                break
            pointer = ((size & 0x3f) << 8) | payload[cursor + 1]
            if resume is None:
                resume = cursor + 2
            cursor = pointer
            continue
        if size & 0xC0 or cursor + 1 + size > len(payload):
            break
        cursor += 1
        labels.append(payload[cursor:cursor + size].decode("ascii", "replace"))
        cursor += size
    return ".".join(labels), (resume if resume is not None else cursor)


def _dns_payload(frame: bytes, linktype: int):
    offset = 0
    if linktype == 1:  # Ethernet
        if len(frame) < 14:
            return None
        ethertype, offset = struct.unpack_from("!H", frame, 12)[0], 14
        while ethertype in (0x8100, 0x88a8, 0x9100):
            if offset + 4 > len(frame):
                return None
            ethertype, offset = struct.unpack_from("!H", frame, offset + 2)[0], offset + 4
        if ethertype == 0x0800:
            if offset + 20 > len(frame):
                return None
            ihl = (frame[offset] & 0x0f) * 4
            if frame[offset] >> 4 != 4 or offset + ihl > len(frame):
                return None
            proto = frame[offset + 9]
            src = socket.inet_ntop(socket.AF_INET, frame[offset + 12:offset + 16])
            dst = socket.inet_ntop(socket.AF_INET, frame[offset + 16:offset + 20])
            offset += ihl
        elif ethertype == 0x86dd:
            if offset + 40 > len(frame) or frame[offset] >> 4 != 6:
                return None
            proto = frame[offset + 6]
            src = socket.inet_ntop(socket.AF_INET6, frame[offset + 8:offset + 24])
            dst = socket.inet_ntop(socket.AF_INET6, frame[offset + 24:offset + 40])
            offset += 40
        else:
            return None
    elif linktype == 101:  # Raw IP
        if not frame:
            return None
        version = frame[0] >> 4
        if version == 4:
            offset = (frame[0] & 15) * 4
            proto = frame[9]
            src, dst = socket.inet_ntop(socket.AF_INET, frame[12:16]), socket.inet_ntop(socket.AF_INET, frame[16:20])
        elif version == 6:
            offset, proto = 40, frame[6]
            src, dst = socket.inet_ntop(socket.AF_INET6, frame[8:24]), socket.inet_ntop(socket.AF_INET6, frame[24:40])
        else:
            return None
    else:
        return None

    if proto == 17:
        if offset + 8 > len(frame):
            return None
        sport, dport, length = struct.unpack_from("!HHH", frame, offset)
        payload = frame[offset + 8:offset + max(8, length)]
        transport = "UDP"
    elif proto == 6:
        if offset + 20 > len(frame):
            return None
        sport, dport = struct.unpack_from("!HH", frame, offset)
        tcp_header_len = (frame[offset + 12] >> 4) * 4
        payload = frame[offset + tcp_header_len:]
        if len(payload) >= 2:
            msg_len = int.from_bytes(payload[:2], "big")
            payload = payload[2:2 + msg_len]
        transport = "TCP"
    else:
        return None
    if 53 not in (sport, dport) or len(payload) < 12:
        return None
    ident, flags, qdcount, ancount, _nscount, _arcount = struct.unpack_from("!HHHHHH", payload)
    name, qtype, qclass = "", None, None
    if qdcount:
        name, pos = _dns_name(payload, 12)
        if pos + 4 <= len(payload):
            qtype, qclass = struct.unpack_from("!HH", payload, pos)
    return {"id": ident, "qr": (flags >> 15) & 1, "rcode": flags & 0x0f,
            "name": name, "qtype": qtype, "qclass": qclass, "answers": ancount,
            "src": src, "dst": dst, "sport": sport, "dport": dport,
            "transport": transport}


_QTYPE = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
          16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}
_RCODE = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
          4: "NOTIMP", 5: "REFUSED"}


def analyze_pcap(data: bytes, filename: str = "capture.pcap"):
    if len(data) > 64 * 1024 * 1024:
        raise ValueError("حجم ملف الالتقاط يتجاوز 64 ميغابايت.")
    frames = _blocks(data) if data.startswith(b"\x0a\x0d\x0d\x0a") else _classic_frames(data)
    messages = []
    for timestamp, linktype, frame in frames:
        try:
            msg = _dns_payload(frame, linktype)
        except (ValueError, OSError, struct.error):
            msg = None
        if msg is not None:
            msg["timestamp"] = timestamp
            messages.append(msg)

    queries = [m for m in messages if not m["qr"] and m["name"]]
    responses = [m for m in messages if m["qr"]]
    counts = collections.Counter(q["name"].lower() for q in queries)
    suspicious_domain = counts.most_common(1)[0][0] if counts else None
    relevant = [q for q in queries if q["name"].lower() == suspicious_domain] if suspicious_domain else []
    pending: dict[tuple, list[float | None]] = collections.defaultdict(list)
    for q in relevant:
        key = (q["id"], q["src"], q["dst"], q["sport"], q["dport"], q["name"].lower())
        pending[key].append(q["timestamp"])
    matched = []
    for r in responses:
        key = (r["id"], r["dst"], r["src"], r["dport"], r["sport"], r["name"].lower())
        if pending.get(key):
            qtime = pending[key].pop(0)
            if qtime is not None and r["timestamp"] is not None and r["timestamp"] >= qtime:
                matched.append((r["timestamp"] - qtime, r))
    type_counts = collections.Counter(q["qtype"] for q in relevant if q["qtype"] is not None)
    source_ports = collections.Counter(q["sport"] for q in relevant)
    destination_ports = collections.Counter(q["dport"] for q in relevant)
    response_codes = collections.Counter(r["rcode"] for _, r in matched)
    transports = collections.Counter(q["transport"] for q in relevant)
    average_time = (sum(delta for delta, _ in matched) / len(matched) / 1_000_000_000) if matched else None

    response_code = response_codes.most_common(1)[0][0] if response_codes else None
    # Keep protocol truth separate from the short category requested by student worksheets.
    response_status = ("Success" if response_code == 0 else
                       "Refused" if response_code == 5 else
                       "Failure" if response_code is not None else None)
    answers = [
        {"item": "اسم النطاق", "value": suspicious_domain, "field": "dns.qry.name"},
        {"item": "نوع استعلام DNS", "value": _QTYPE.get(type_counts.most_common(1)[0][0], str(type_counts.most_common(1)[0][0])) if type_counts else None, "field": "dns.qry.type"},
        {"item": "الإجابة المختصرة للمرحلة", "value": response_status, "response_code": response_code, "response_code_name": _RCODE.get(response_code) if response_code is not None else None, "field": "DNS outcome derived from dns.flags.rcode"},
        {"item": "رمز استجابة DNS الفعلي", "value": _RCODE.get(response_code, str(response_code)) if response_code is not None else None, "response_code": response_code, "field": "dns.flags.rcode"},
        {"item": "بروتوكول النقل", "value": transports.most_common(1)[0][0] if transports else None, "field": "udp / tcp"},
        {"item": "منفذ الوجهة على خادم DNS", "value": destination_ports.most_common(1)[0][0] if destination_ports else None, "field": "udp.dstport"},
        {"item": "منفذ المصدر على جهاز العميل", "value": source_ports.most_common(1)[0][0] if source_ports else None, "field": "udp.srcport"},
        {"item": "زمن الاستجابة (صيغة الإدخال: 6 منازل)", "value": round(average_time, 6) if average_time is not None else None, "exact_value": round(average_time, 9) if average_time is not None else None, "field": "dns.time"},
    ]
    findings = [f"{a['item']}: {a['value'] if a['value'] is not None else 'لم يُستخرج'}" for a in answers]
    warnings = []
    if not queries:
        warnings.append("لم يُعثر على استعلام DNS قياسي داخل الالتقاط.")
    if queries and not matched:
        warnings.append("عُثر على استعلامات DNS، لكن لم تُطابق استجابة مرتبطة بها لحساب زمن الاستجابة.")
    result = {"ok": True, "recognized": True, "success": bool(queries), "challenge": "تحليل DNS من PCAP",
            "analyzer": "pcap-dns", "filename": filename, "packet_count": len(frames),
            "dns_message_count": len(messages), "dns_query_count": len(queries),
            "dns_response_count": len(responses), "suspicious_domain": suspicious_domain,
            "answers": answers, "findings": findings, "warnings": warnings,
            "explanation_ar": ["فك صقر حزم Ethernet/IP/UDP أو TCP محليًا واستخرج حقول DNS مباشرة من الالتقاط.",
                               "حُسب زمن الاستجابة من الطوابع الزمنية في ملف PCAPNG؛ ولم يُرسل أي اتصال شبكي."]}
    tshark_path = find_tshark()
    if tshark_path:
        try:
            result["wireshark_analysis"] = analyze_with_tshark(data, filename, tshark_path)
            result["findings"].append("تحقق مستقل عبر TShark/Wireshark: اكتمل تحليل الإطارات والبروتوكولات محليًا.")
        except Exception as exc:
            result["wireshark_analysis"] = {"available": True, "used": False,
                "path": tshark_path, "warning": str(exc)[:400]}
            result["warnings"].append("تعذر تشغيل TShark على هذا الملف؛ عُرض تحليل Falcon المدمج. " + str(exc)[:250])
    else:
        result["wireshark_analysis"] = {"available": False, "used": False,
            "install_hint": "ثبّت Wireshark مع TShark؛ راجع WIRESHARK_WINDOWS_ar.md."}
    return result


_TSHARK_FIELDS = (
    "frame.number", "frame.time_epoch", "frame.protocols",
    "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
    "udp.srcport", "udp.dstport", "tcp.srcport", "tcp.dstport", "tcp.stream",
    "dns.id", "dns.flags.response", "dns.flags.rcode", "dns.qry.name",
    "dns.qry.type", "dns.count.answers", "http.host", "http.request.method",
    "http.request.uri", "tls.handshake.extensions_server_name",
)


def find_tshark():
    """Locate the Wireshark command-line dissector without searching arbitrary folders."""
    candidates = [shutil.which("tshark"), shutil.which("tshark.exe"),
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        str(Path(__file__).resolve().parent / "tools" / "wireshark" / "tshark.exe")]
    return next((str(Path(p)) for p in candidates if p and Path(p).is_file()), None)


def find_wireshark_gui():
    candidates = [shutil.which("wireshark"), shutil.which("wireshark.exe"),
        r"C:\Program Files\Wireshark\Wireshark.exe",
        r"C:\Program Files (x86)\Wireshark\Wireshark.exe"]
    return next((str(Path(p)) for p in candidates if p and Path(p).is_file()), None)


def tshark_version(path=None):
    exe = path or find_tshark()
    if not exe:
        return None
    try:
        proc = subprocess.run([exe, "--version"], capture_output=True, text=True,
                              timeout=8, check=False)
        first = (proc.stdout or proc.stderr).splitlines()
        return first[0][:160] if first else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def _field_int(value):
    if not value:
        return None
    match = re.search(r"(?<!\d)(\d+)", value)
    return int(match.group(1)) if match else None


def _field_ns(value):
    if not value:
        return None
    try:
        return int(decimal.Decimal(value) * decimal.Decimal(1_000_000_000))
    except decimal.InvalidOperation:
        return None


def analyze_with_tshark(data: bytes, filename: str, executable: str):
    """Use TShark only to dissect a saved capture; never starts live capture."""
    suffix = Path(filename).suffix.lower()
    if suffix not in (".pcap", ".pcapng", ".cap"):
        suffix = ".pcapng" if data.startswith(b"\x0a\x0d\x0d\x0a") else ".pcap"
    with tempfile.TemporaryDirectory(prefix="falcon_tshark_") as folder:
        capture = Path(folder) / ("capture" + suffix)
        capture.write_bytes(data)
        command = [executable, "-r", str(capture), "-T", "fields",
                   "-E", "header=y", "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=f"]
        for field in _TSHARK_FIELDS:
            command.extend(("-e", field))
        proc = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=75, check=False)
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or "TShark returned a nonzero status")[-700:])
        rows = list(csv.DictReader(proc.stdout.splitlines(), delimiter="\t"))
        protocols = collections.Counter()
        dns = []
        http_hosts, tls_names, tcp_streams = set(), set(), set()
        for row in rows:
            proto_path = row.get("frame.protocols", "")
            for proto in proto_path.split(":"):
                if proto:
                    protocols[proto] += 1
            for field, output in (("http.host", http_hosts),
                                  ("tls.handshake.extensions_server_name", tls_names),
                                  ("tcp.stream", tcp_streams)):
                value = row.get(field, "").strip()
                if value:
                    output.add(value.rstrip("."))
            if row.get("dns.id", "").strip():
                src = row.get("ip.src", "").strip() or row.get("ipv6.src", "").strip()
                dst = row.get("ip.dst", "").strip() or row.get("ipv6.dst", "").strip()
                sport = row.get("udp.srcport", "").strip() or row.get("tcp.srcport", "").strip()
                dport = row.get("udp.dstport", "").strip() or row.get("tcp.dstport", "").strip()
                dns.append({
                    "frame": _field_int(row.get("frame.number", "")),
                    "time_ns": _field_ns(row.get("frame.time_epoch", "")),
                    "protocols": proto_path,
                    "src": src, "dst": dst, "sport": _field_int(sport), "dport": _field_int(dport),
                    "stream": _field_int(row.get("tcp.stream", "")),
                    "id": _field_int(row.get("dns.id", "")),
                    "response": _field_int(row.get("dns.flags.response", "")) == 1,
                    "rcode": _field_int(row.get("dns.flags.rcode", "")),
                    "name": row.get("dns.qry.name", "").strip().rstrip("."),
                    "qtype": row.get("dns.qry.type", "").strip(),
                    "answers": _field_int(row.get("dns.count.answers", "")),
                })
        queries = [m for m in dns if not m["response"] and m["name"]]
        responses = [m for m in dns if m["response"]]
        pending = collections.defaultdict(list)
        for q in queries:
            key = (q["id"], q["src"], q["dst"], q["sport"], q["dport"], q["name"].lower())
            pending[key].append(q)
        pairs = []
        for r in responses:
            key = (r["id"], r["dst"], r["src"], r["dport"], r["sport"], r["name"].lower())
            if pending[key]:
                q = pending[key].pop(0)
                qtime = q["time_ns"]
                if qtime is not None and r["time_ns"] is not None and r["time_ns"] >= qtime:
                    pairs.append({"query_frame": q["frame"], "response_frame": r["frame"],
                                  "delta_ns": r["time_ns"] - qtime, "rcode": r["rcode"],
                                  "name": r["name"] or key[-1]})
        latency = (sum(p["delta_ns"] for p in pairs) / len(pairs) / 1_000_000_000) if pairs else None
        v = tshark_version(executable)
        return {"available": True, "used": True, "engine": "TShark (Wireshark CLI)",
                "version": v, "path": executable, "frame_count": len(rows),
                "dns_message_count": len(dns), "dns_query_count": len(queries),
                "dns_response_count": len(responses), "matched_dns_pairs": pairs,
                "average_dns_response_seconds": round(latency, 9) if latency is not None else None,
                "protocol_counts": dict(protocols.most_common(30)),
                "http_hosts": sorted(http_hosts)[:100], "tls_server_names": sorted(tls_names)[:100],
                "tcp_streams": sorted(tcp_streams)[:100],
                "evidence_fields": list(_TSHARK_FIELDS),
                "scope": "قراءة ملف الالتقاط المحفوظ فقط؛ لا يوجد التقاط حي أو اتصال شبكي."}
