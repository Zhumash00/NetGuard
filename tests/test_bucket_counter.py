import unittest
from unittest.mock import patch
from ids_detector import IDSDetector

class TestBucketCounter(unittest.TestCase):

    def test_high_packet_count(self):
        ids = IDSDetector()
        ids.rules["udp_flood"] = (5, 100)

        with patch(
            "ids_detector.time.monotonic",
            return_value=100.0
        ):
            for _ in range(10000):
                detected, count = ids.track(
                    "udp_flood",
                    "192.168.1.10",
                    "192.168.1.20"
                )

        self.assertTrue(detected)
        self.assertEqual(count, 10000)

        key = (
            "udp_flood",
            "192.168.1.10",
            "192.168.1.20"
        )

        # 10000 пакет, бірақ бір ғана бакет
        self.assertEqual(len(ids.windows[key]), 1)

    def test_window_expiration(self):
        ids = IDSDetector()
        ids.rules["udp_flood"] = (5, 100)

        with patch(
            "ids_detector.time.monotonic",
            return_value=100.0
        ):
            for _ in range(150):
                ids.track("udp_flood", "A", "B")

        with patch(
            "ids_detector.time.monotonic",
            return_value=106.0
        ):
            detected, count = ids.track(
                "udp_flood", "A", "B"
            )

        self.assertFalse(detected)
        self.assertEqual(count, 1)

if __name__ == "__main__":
    unittest.main()
