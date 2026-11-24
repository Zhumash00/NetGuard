import unittest
from unittest.mock import patch

from ids_detector import IDSDetector

class TestWindowFixes(unittest.TestCase):

    def test_packet_count(self):
        ids = IDSDetector()
        ids.rules["udp_flood"] = (5, 10)

        with patch(
            "ids_detector.time.monotonic",
            return_value=100.0
        ):
            result = None

            for _ in range(30):
                result = ids.track(
                    "udp_flood",
                    "192.168.1.10",
                    "192.168.1.20"
                )

        self.assertEqual(result, (True, 30))

    def test_expired_sources(self):
        ids = IDSDetector()

        with patch(
            "ids_detector.time.monotonic",
            return_value=100.0
        ):
            for i in range(10):
                ids.track_sources(
                    "distributed_udp",
                    f"192.168.1.{i + 10}",
                    "192.168.1.100"
                )

        with patch(
            "ids_detector.time.monotonic",
            return_value=110.0
        ):
            count = ids.track_sources(
                "distributed_udp",
                "192.168.1.50",
                "192.168.1.100"
            )

        self.assertEqual(count, 1)

if __name__ == "__main__":
    unittest.main()
