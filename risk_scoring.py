"""Bounded correlation of related IDS indicators."""

import time
from collections import OrderedDict


class RiskScorer:
    RULE_SCORES = {
        "ftp_login_failure": 15, "suspicious_dns": 20,
        "ssh_bruteforce": 35, "port_scan": 40, "dns_flood": 45,
        "icmp_flood": 50, "udp_flood": 50, "syn_flood": 60,
        "distributed_udp": 65, "distributed_syn": 70,
        "large_packet": 30, "suspicious_tcp_flags": 40,
    }
    RULE_GROUPS = {
        "syn_flood": "syn", "distributed_syn": "syn",
        "udp_flood": "udp", "distributed_udp": "udp",
    }

    def __init__(self, window_seconds=60, max_keys=5000):
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self.history = OrderedDict()
        self.last_cleanup = float("-inf")

    @staticmethod
    def level(score):
        if score >= 70:
            return "HIGH"
        if score >= 30:
            return "MEDIUM"
        return "LOW"

    def _expire(self, entries, now):
        for rule, timestamp in list(entries.items()):
            if now - timestamp >= self.window_seconds:
                del entries[rule]

    def cleanup(self, now=None):
        now = time.monotonic() if now is None else now
        if now - self.last_cleanup < 10:
            return
        for key, entries in list(self.history.items()):
            self._expire(entries, now)
            if not entries:
                del self.history[key]
        self.last_cleanup = now

    def evaluate(self, alert):
        now = time.monotonic()
        self.cleanup(now)
        rule = alert.get("rule", "")
        src, dst = alert.get("src") or "unknown", alert.get("dst") or "unknown"
        distributed = rule.startswith("distributed_")
        key = ("destination", dst) if distributed else ("pair", src, dst)
        if key not in self.history:
            if len(self.history) >= self.max_keys:
                self.history.popitem(last=False)
            self.history[key] = {}
        self.history.move_to_end(key)
        entries = self.history[key]
        self._expire(entries, now)
        # Unknown rules share one slot, so arbitrary names cannot grow history.
        known_rule = rule if rule in self.RULE_SCORES else "unknown"
        entries[known_rule] = now
        recent = {}
        for old_rule in entries:
            group = self.RULE_GROUPS.get(old_rule, old_rule)
            recent[group] = max(recent.get(group, 0), self.RULE_SCORES.get(old_rule, 10))
        # Destination-wide flood evidence only raises the matching flood group
        # for a pair. Unrelated source IPs never contribute independent groups.
        destination = self.history.get(("destination", dst), {})
        self._expire(destination, now)
        if not distributed:
            for old_rule in destination:
                group = self.RULE_GROUPS.get(old_rule, old_rule)
                if group in recent:
                    recent[group] = max(recent[group], self.RULE_SCORES[old_rule])
        score = min(100, max(recent.values()) + min(20, 10 * (len(recent) - 1)))
        reason = (
            f"Ереже: {rule}; бастапқы балл: {self.RULE_SCORES.get(rule, 10)}; "
            f"байланысты белгілер тобы: {len(recent)}"
        )
        return {**alert, "risk_score": score, "level": self.level(score), "risk_reason": reason}
