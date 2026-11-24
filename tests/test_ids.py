import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from ids_detector import IDSDetector
from risk_scoring import RiskScorer
from ids_logger import IDSLogger

def event(
    src="192.168.1.10",
    dst="192.168.1.20",
    transport="TCP",
    protocol="OTHER",
    dport=80,
    flags=2,
    **extra
):
    return {
        "timestamp": "2026-11-21T12:00:00",
        "src": src,
        "dst": dst,
        "transport": transport,
        "protocol": protocol,
        "dport": dport,
        "tcp_flags": flags,
        **extra
    }

class TestIDSDetector(unittest.TestCase):

    def setUp(self):
        self.ids = IDSDetector()

    def test_port_scan(self):
        alerts = []

        for port in range(1000, 1020):
            alerts.extend(
                self.ids.detect(event(dport=port))
            )

        self.assertTrue(any(
            a["rule"] == "port_scan"
            for a in alerts
        ))

    def test_repeated_port_not_scan(self):
        alerts = []

        for _ in range(20):
            alerts.extend(
                self.ids.detect(event(dport=443))
            )

        self.assertFalse(any(
            a["rule"] == "port_scan"
            for a in alerts
        ))

    def test_syn_ack_not_counted(self):
        alerts = []

        for _ in range(120):
            alerts.extend(
                self.ids.detect(event(flags=0x12))
            )

        self.assertFalse(any(
            a["rule"] == "syn_flood"
            for a in alerts
        ))

    def test_udp_flood(self):
        self.ids.rules["udp_flood"] = (5, 10)
        alerts = []

        for _ in range(12):
            alerts.extend(self.ids.detect(
                event(
                    transport="UDP",
                    protocol="QUIC",
                    flags=0,
                    dport=443
                )
            ))

        self.assertTrue(any(
            a["rule"] == "udp_flood"
            for a in alerts
        ))

    def test_cooldown(self):
        self.ids.rules["port_scan"] = (10, 3)
        alerts = []

        for port in range(1000, 1010):
            alerts.extend(
                self.ids.detect(event(dport=port))
            )

        scan_alerts = [
            a for a in alerts
            if a["rule"] == "port_scan"
        ]

        self.assertEqual(len(scan_alerts), 1)

    def test_window_expiration(self):
        self.ids.rules["port_scan"] = (10, 3)

        with patch(
            "ids_detector.time.monotonic",
            return_value=100.0
        ):
            self.ids.detect(event(dport=1000))
            self.ids.detect(event(dport=1001))

        with patch(
            "ids_detector.time.monotonic",
            return_value=111.0
        ):
            alerts = self.ids.detect(
                event(dport=1002)
            )

        self.assertFalse(any(
            a["rule"] == "port_scan"
            for a in alerts
        ))

    def test_ftp_failure(self):
        alerts = self.ids.detect(event(
            protocol="FTP",
            dport=21,
            ftp_code=530
        ))

        self.assertTrue(any(
            a["rule"] == "ftp_login_failure"
            for a in alerts
        ))

class TestRiskScorer(unittest.TestCase):

    def test_duplicate_rule(self):
        scorer = RiskScorer()

        alert = {
            "rule": "syn_flood",
            "src": "192.168.1.10",
            "dst": "192.168.1.20"
        }

        first = scorer.evaluate(alert)
        second = scorer.evaluate(alert)

        self.assertEqual(
            first["risk_score"],
            second["risk_score"]
        )

    def test_combined_rules(self):
        scorer = RiskScorer()

        base = {
            "src": "192.168.1.10",
            "dst": "192.168.1.20"
        }

        scorer.evaluate({
            **base,
            "rule": "syn_flood"
        })

        result = scorer.evaluate({
            **base,
            "rule": "port_scan"
        })

        self.assertEqual(result["risk_score"], 70)
        self.assertEqual(result["level"], "HIGH")

class TestIDSLogger(unittest.TestCase):

    def test_write_and_read(self):
        with TemporaryDirectory() as directory:
            logger = IDSLogger(directory)

            logger.write({
                "rule": "port_scan",
                "level": "MEDIUM",
                "src": "192.168.1.10",
                "dst": "192.168.1.20",
                "message": "Тест"
            })

            files = list(
                Path(directory).glob("*.jsonl")
            )

            self.assertEqual(len(files), 1)

            records = logger.read(files[0].name)

            self.assertEqual(len(records), 1)
            self.assertEqual(
                records[0]["rule"],
                "port_scan"
            )

if __name__ == "__main__":
    unittest.main()
