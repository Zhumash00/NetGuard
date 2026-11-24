import json
import os
import queue
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

os.environ["QT_QPA_PLATFORM"] = "offscreen"

import main
from ids_detector import IDSDetector
from ids_logger import IDSLogger
from risk_scoring import RiskScorer
from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, Raw
from PySide6.QtWidgets import QApplication


def event(**changes):
    return {
        "src": "192.0.2.1", "dst": "192.0.2.2", "sport": 40000,
        "dport": 443, "transport": "TCP", "protocol": "HTTPS",
        "tcp_flags": 2, "flags": "S", "timestamp": time.time(),
        "size": 80, "direction": "IN", **changes,
    }


class DetectorRegressions(unittest.TestCase):
    def test_dns_responses_are_not_queries(self):
        ids = IDSDetector()
        ids.rules["dns_flood"] = (10, 2)
        for _ in range(5):
            alerts = ids.detect(event(protocol="DNS", transport="UDP", tcp_flags=0,
                                      dns_is_query=False, dns_query="a" * 60 + ".test"))
            self.assertFalse(any(a["rule"] in ("dns_flood", "suspicious_dns") for a in alerts))
        ids.detect(event(protocol="DNS", dns_is_query=True, dns_query="example.test"))
        alerts = ids.detect(event(protocol="DNS", dns_is_query=True, dns_query="example.test"))
        self.assertTrue(any(a["rule"] == "dns_flood" for a in alerts))

    def test_distributed_requires_several_active_sources(self):
        for count in (1, 10):
            ids = IDSDetector()
            ids.rules["distributed_udp"] = (5, 20)
            alerts = []
            for index in range(30):
                alerts.extend(ids.detect(event(src=f"192.0.2.{10 + index % count}",
                                               transport="UDP", tcp_flags=0)))
            self.assertEqual(any(a["rule"] == "distributed_udp" for a in alerts), count == 10)

    def test_target_isolation_and_legacy_flags(self):
        ids = IDSDetector()
        ids.rules["port_scan"] = (10, 3)
        for index in range(10):
            old = event(dst=f"198.51.100.{index}", dport=1000 + index)
            del old["tcp_flags"]
            self.assertFalse(ids.detect(old))
        alerts = []
        for port in range(1000, 1004):
            old = event(dport=port)
            del old["tcp_flags"]
            alerts.extend(ids.detect(old))
        self.assertTrue(any(a["rule"] == "port_scan" for a in alerts))

    def test_independent_rules_survive_cooldown(self):
        ids = IDSDetector()
        ids.rules["syn_flood"] = (5, 2)
        ids.rules["ssh_bruteforce"] = (60, 3)
        ids.detect(event(dport=22))
        ids.detect(event(dport=22))
        alerts = ids.detect(event(dport=22, size=10000))
        self.assertTrue({"ssh_bruteforce", "large_packet"} <= {a["rule"] for a in alerts})

    def test_limits_and_idle_cleanup(self):
        ids = IDSDetector()
        ids.max_keys = 3
        ids.max_source_groups = 2
        ids.max_sources_per_group = 3
        ids.max_ports_per_window = 4
        for index in range(20):
            ids.track("udp_flood", str(index), "target", now=100)
            ids.track_sources("distributed_udp", str(index), str(index % 4), now=100)
            ids.alert("large_packet", event(src=str(index)), "MEDIUM", "test", now=100)
        for port in range(20):
            ids.track("port_scan", "source", "target", port, now=100)
        self.assertLessEqual(len(ids.windows), 3)
        self.assertLessEqual(len(ids.cooldowns), 3)
        self.assertLessEqual(len(ids.source_windows), 2)
        self.assertEqual(len(ids.windows[("port_scan", "source", "target")]), 4)
        ids.cleanup(200, force=True)
        self.assertFalse(ids.windows or ids.cooldowns or ids.source_windows)


class RiskAndLogRegressions(unittest.TestCase):
    def test_pairs_and_duplicate_groups(self):
        scorer = RiskScorer(max_keys=3)
        scorer.evaluate({"rule": "syn_flood", "src": "A", "dst": "X"})
        other = scorer.evaluate({"rule": "port_scan", "src": "B", "dst": "X"})
        self.assertEqual(other["risk_score"], 40)
        for _ in range(10000):
            scorer.evaluate({"rule": "syn_flood", "src": "A", "dst": "X"})
        self.assertEqual(len(scorer.history[("pair", "A", "X")]), 1)
        scorer.evaluate({"rule": "distributed_syn", "src": "*", "dst": "X"})
        related = scorer.evaluate({"rule": "syn_flood", "src": "A", "dst": "X"})
        self.assertEqual(related["risk_score"], 70)
        for index in range(10):
            scorer.evaluate({"rule": "port_scan", "src": str(index), "dst": "Y"})
        self.assertLessEqual(len(scorer.history), 3)
        scorer.cleanup(time.monotonic() + 120)
        self.assertFalse(scorer.history)

    def test_rotation_and_old_jsonl(self):
        with TemporaryDirectory() as directory:
            logger = IDSLogger(directory, max_bytes=500, max_files=2)
            for index in range(10):
                logger.write({"rule": "port_scan", "message": "Тексеру" * 20, "risk_score": index})
            files = sorted(Path(directory).glob("*.jsonl"))
            self.assertEqual(len(files), 2)
            self.assertEqual(logger.read(files[-1].name)[-1]["risk_score"], 9)
            old = Path(directory) / "ids_2026-01-01.jsonl"
            old.write_text('{"rule":"port_scan"}\ninvalid\n', encoding="utf-8")
            self.assertEqual(logger.read(old.name), [{"rule": "port_scan"}])


class ApplicationIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_capture_fields_and_queue_limit(self):
        packets = [
            IP() / TCP(dport=443, flags="S"),
            IP() / UDP(sport=68, dport=67),
            IP() / ICMP(),
            IP() / UDP(dport=53) / DNS(qr=0, qd=DNSQR(qname="example.test")),
            IP() / TCP(sport=21, dport=40000) / Raw(b"530 Login failed\r\n"),
        ]
        self.assertEqual([main.protocol_for_packet(p) for p in packets],
                         ["HTTPS", "DHCP", "ICMP", "DNS", "FTP"])
        self.assertEqual(main.protocol_for_packet(IP() / UDP(sport=40000, dport=22)), "OTHER")
        for packet in packets:
            captured = queue.Queue(maxsize=1)
            worker = main.CaptureWorker("test", captured)
            def sniff_once(**kwargs):
                kwargs["prn"](packet)
                kwargs["prn"](packet)
                worker.stop()
            with patch.object(main, "sniff", side_effect=sniff_once):
                worker.run()
            self.assertEqual(captured.qsize(), 1)
            item = captured.get_nowait()
            self.assertIn("monotonic_time", item)
            self.assertEqual(item["transport"], main.transport_for_packet(packet))
            self.assertEqual(item["tcp_flags"], main.tcp_flags_for_packet(packet))
            self.assertEqual(item["dns_is_query"], bool(packet.haslayer(DNS)))

    def test_alerts_reach_ui_and_selected_log_folder(self):
        with TemporaryDirectory() as directory:
            settings = {"auto_capture": False, "autostart": False,
                        "log_dir": directory, "save_ids": True}
            with patch.object(main, "load_settings", return_value=settings), \
                 patch.object(main, "save_settings"), \
                 patch.object(main, "default_log_dir", return_value=Path(directory)), \
                 patch.object(main, "set_windows_autostart"), \
                 patch.object(main.MainWindow, "refresh_adapters"):
                window = main.MainWindow()
                try:
                    window.ids.rules["port_scan"] = (10, 3)
                    for port in range(1000, 1004):
                        window.process_event(event(dport=port))
                    window.update_dashboard()
                    self.assertEqual(window.total_alerts, 1)
                    self.assertEqual(window.threat_table.item(0, 7).text(), "40")
                    self.assertEqual(window.home_threat_table.rowCount(), 1)
                    records = window.ids_logger.read(next(Path(directory).glob("*.jsonl")).name)
                    self.assertEqual(records[0]["risk_score"], 40)
                    window.show()
                    for index in range(13):
                        window.layout_combo.setCurrentIndex(index)
                        self.app.processEvents()
                        self.assertEqual(window.threat_table.rowCount(), 1)
                    new_dir = str(Path(directory) / "new")
                    with patch.object(main.QFileDialog, "getExistingDirectory", return_value=new_dir):
                        window.choose_log_dir()
                    window.process_event(event(protocol="FTP", ftp_code=530))
                    self.assertEqual(len(list(Path(new_dir).glob("*.jsonl"))), 1)
                    with patch.object(window.ids_logger, "write", side_effect=OSError("disk full")):
                        window.process_event(event(dst="192.0.2.99", protocol="FTP", ftp_code="530"))
                    self.assertIn("disk full", window.status_label.text())
                    window.settings["save_ids"] = False
                    with patch.object(window.ids_logger, "write") as write:
                        window.process_event(event(dst="192.0.2.98", protocol="FTP", ftp_code="530"))
                    write.assert_not_called()
                finally:
                    window.close()


if __name__ == "__main__":
    unittest.main()
