import struct
import sys
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "local-engine"))
import pcap_analyzer


def _block(kind, body):
    size = 12 + len(body)
    return struct.pack("<II", kind, size) + body + struct.pack("<I", size)


def _dns_frame(is_response, timestamp_ns):
    name = b"\x0fsuspicious-test\x03xyz\x00"
    ident = 0x1234
    flags = 0x8183 if is_response else 0x0100
    dns = struct.pack("!HHHHHH", ident, flags, 1, 0, 0, 0) + name + struct.pack("!HH", 1, 1)
    src_port, dst_port = (53, 41000) if is_response else (41000, 53)
    udp = struct.pack("!HHHH", src_port, dst_port, 8 + len(dns), 0) + dns
    src = b"\xc0\xa8\xb2\x02" if is_response else b"\xc0\xa8\xb2\x81"
    dst = b"\xc0\xa8\xb2\x81" if is_response else b"\xc0\xa8\xb2\x02"
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, src, dst)
    ethernet = b"\x00" * 12 + b"\x08\x00"
    return ethernet + ip + udp


def _pcapng():
    shb = _block(0x0A0D0D0A, b"\x4d\x3c\x2b\x1a" + struct.pack("<HHq", 1, 0, -1))
    options = struct.pack("<HHB3xHH", 9, 1, 9, 0, 0)
    idb = _block(1, struct.pack("<HHI", 1, 0, 65535) + options)
    packets = []
    for response, timestamp_ns in ((False, 1_000_000_000), (True, 1_195_287_137)):
        frame = _dns_frame(response, timestamp_ns)
        hi, lo = divmod(timestamp_ns, 1 << 32)
        body = struct.pack("<IIIII", 0, hi, lo, len(frame), len(frame)) + frame
        body += b"\x00" * ((-len(frame)) & 3)
        packets.append(_block(6, body))
    return shb + idb + b"".join(packets)


class PcapAnalyzerTests(unittest.TestCase):
    def test_recognizes_pcapng(self):
        self.assertTrue(pcap_analyzer.is_capture(_pcapng(), "trace.pcapng"))

    def test_extracts_dns_fields_and_exact_latency(self):
        result = pcap_analyzer.analyze_pcap(_pcapng(), "trace.pcapng")
        self.assertEqual(result["suspicious_domain"], "suspicious-test.xyz")
        by_item = {row["item"]: row for row in result["answers"]}
        self.assertEqual(by_item["اسم النطاق"]["value"], "suspicious-test.xyz")
        self.assertEqual(by_item["نوع استعلام DNS"]["value"], "A")
        self.assertEqual(by_item["الإجابة المختصرة للمرحلة"]["value"], "Failure")
        self.assertEqual(by_item["رمز استجابة DNS الفعلي"]["value"], "NXDOMAIN")
        self.assertEqual(by_item["بروتوكول النقل"]["value"], "UDP")
        self.assertEqual(by_item["منفذ الوجهة على خادم DNS"]["value"], 53)
        self.assertEqual(by_item["منفذ المصدر على جهاز العميل"]["value"], 41000)
        self.assertEqual(by_item["زمن الاستجابة (صيغة الإدخال: 6 منازل)"]["value"], 0.195287)
        self.assertEqual(by_item["زمن الاستجابة (صيغة الإدخال: 6 منازل)"]["exact_value"], 0.195287137)
        self.assertEqual(result["packet_count"], 2)

    def test_tshark_crosscheck_reads_saved_capture_and_matches_dns(self):
        headers = list(pcap_analyzer._TSHARK_FIELDS)
        def row(**values):
            return "\t".join(values.get(name, "") for name in headers)
        output = "\t".join(headers) + "\n"
        output += row(**{"frame.number":"1", "frame.time_epoch":"100.000000000",
            "frame.protocols":"eth:ethertype:ip:udp:dns", "ip.src":"192.168.1.10",
            "ip.dst":"192.168.1.1", "udp.srcport":"39698", "udp.dstport":"53",
            "dns.id":"15202", "dns.flags.response":"0", "dns.qry.name":"suspicious-website.xyz",
            "dns.qry.type":"A"}) + "\n"
        output += row(**{"frame.number":"4", "frame.time_epoch":"100.195287137",
            "frame.protocols":"eth:ethertype:ip:udp:dns", "ip.src":"192.168.1.1",
            "ip.dst":"192.168.1.10", "udp.srcport":"53", "udp.dstport":"39698",
            "dns.id":"15202", "dns.flags.response":"1", "dns.flags.rcode":"3",
            "dns.qry.name":"suspicious-website.xyz", "dns.qry.type":"A"}) + "\n"
        calls = [SimpleNamespace(returncode=0, stdout=output, stderr=""),
                 SimpleNamespace(returncode=0, stdout="TShark (Wireshark) 4.4.0\n", stderr="")]
        with patch.object(pcap_analyzer.subprocess, "run", side_effect=calls) as run:
            result = pcap_analyzer.analyze_with_tshark(b"capture", "trace.pcapng", "fake-tshark")
        self.assertEqual(result["engine"], "TShark (Wireshark CLI)")
        self.assertEqual(result["dns_query_count"], 1)
        self.assertEqual(result["dns_response_count"], 1)
        self.assertEqual(result["matched_dns_pairs"][0]["rcode"], 3)
        self.assertEqual(result["average_dns_response_seconds"], 0.195287137)
        self.assertEqual(run.call_count, 2)


if __name__ == "__main__":
    unittest.main()
