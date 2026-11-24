"""Bounded, monotonic-time IDS counters and heuristic alerts."""

import time
from collections import OrderedDict, deque


class IDSDetector:
    def __init__(self):
        self.windows = OrderedDict()
        self.cooldowns = OrderedDict()
        self.source_windows = OrderedDict()
        self.last_cleanup = float("-inf")
        self.max_keys = 10000
        self.max_ports_per_window = 1024
        self.min_distributed_sources = 5
        self.max_source_groups = 1000
        self.max_sources_per_group = 1024
        self.rules = {
            "port_scan": (10, 15), "syn_flood": (5, 100),
            "icmp_flood": (5, 100), "udp_flood": (5, 500),
            "dns_flood": (10, 100), "ssh_bruteforce": (60, 10),
            "distributed_syn": (5, 500), "distributed_udp": (5, 2000),
        }
        self.cooldown_rules = {
            "port_scan": 30, "syn_flood": 20, "icmp_flood": 20,
            "udp_flood": 20, "dns_flood": 30, "ssh_bruteforce": 60,
            "suspicious_dns": 60, "ftp_login_failure": 15,
            "distributed_syn": 30, "distributed_udp": 30,
        }

    def _expire_window(self, rule, window, now):
        cutoff = int(now) - self.rules[rule][0] + 1
        if rule == "port_scan":
            while window and next(iter(window.values())) < cutoff:
                window.popitem(last=False)
        else:
            while window and window[0][0] < cutoff:
                window.popleft()

    def track(self, rule, src, dst, value=None, now=None):
        now = time.monotonic() if now is None else now
        key = (rule, src, dst)
        if key not in self.windows:
            if len(self.windows) >= self.max_keys:
                self.cleanup(now, force=True)
            if len(self.windows) >= self.max_keys:
                self.windows.popitem(last=False)
            self.windows[key] = OrderedDict() if rule == "port_scan" else deque()
        self.windows.move_to_end(key)
        window = self.windows[key]
        self._expire_window(rule, window, now)
        second = int(now)
        if rule == "port_scan":
            if isinstance(value, int) and 0 <= value <= 65535:
                window[value] = second
                window.move_to_end(value)
                if len(window) > self.max_ports_per_window:
                    window.popitem(last=False)
            count = len(window)
        else:
            if window and window[-1][0] == second:
                window[-1] = (second, window[-1][1] + 1)
            else:
                window.append((second, 1))
            count = sum(count for _, count in window)
        return count >= self.rules[rule][1], count

    def _expire_sources(self, rule, sources, now):
        cutoff = int(now) - self.rules[rule][0] + 1
        while sources and next(iter(sources.values())) < cutoff:
            sources.popitem(last=False)

    def track_sources(self, rule, src, dst, now=None):
        now = time.monotonic() if now is None else now
        key = (rule, dst)
        if key not in self.source_windows:
            if len(self.source_windows) >= self.max_source_groups:
                self.source_windows.popitem(last=False)
            self.source_windows[key] = OrderedDict()
        self.source_windows.move_to_end(key)
        sources = self.source_windows[key]
        self._expire_sources(rule, sources, now)
        sources[src] = int(now)
        sources.move_to_end(src)
        if len(sources) > self.max_sources_per_group:
            sources.popitem(last=False)
        return len(sources)

    def cleanup(self, now=None, force=False):
        now = time.monotonic() if now is None else now
        if not force and now - self.last_cleanup < 10:
            return
        for key, window in list(self.windows.items()):
            self._expire_window(key[0], window, now)
            if not window:
                del self.windows[key]
        for key, sources in list(self.source_windows.items()):
            self._expire_sources(key[0], sources, now)
            if not sources:
                del self.source_windows[key]
        for key, timestamp in list(self.cooldowns.items()):
            if now - timestamp >= self.cooldown_rules.get(key[0], 30):
                del self.cooldowns[key]
        self.last_cleanup = now

    def alert(self, rule, event, level, message, now=None):
        now = time.monotonic() if now is None else now
        src = "*" if rule.startswith("distributed_") else event.get("src", "")
        key = (rule, src, event.get("dst", ""))
        last = self.cooldowns.get(key)
        if last is not None and now - last < self.cooldown_rules.get(rule, 30):
            return None
        if key not in self.cooldowns and len(self.cooldowns) >= self.max_keys:
            self.cooldowns.popitem(last=False)
        self.cooldowns[key] = now
        self.cooldowns.move_to_end(key)
        indicator = "SSH CONNECTION BURST" if rule == "ssh_bruteforce" else rule.replace("_", " ").upper()
        return {
            "time": event.get("timestamp", time.time()),
            "level": level, "protocol": event.get("protocol", "OTHER"),
            "src": src, "dst": event.get("dst", ""),
            "rule": rule, "message": message,
            "indicator": indicator, "detail": message,
        }

    def detect(self, event):
        now = event.get("monotonic_time", time.monotonic())
        self.cleanup(now)
        src, dst = event.get("src"), event.get("dst")
        if not src or not dst:
            return []
        protocol = event.get("protocol", "OTHER")
        transport = event.get("transport")
        if not transport:
            transport = "ICMP" if protocol == "ICMP" else "TCP" if event.get("flags") else "OTHER"
        flags = event.get("tcp_flags")
        if flags is None:
            flags = sum(bit for flag, bit in zip("FSRPAUEC", (1, 2, 4, 8, 16, 32, 64, 128))
                        if flag in event.get("flags", ""))
        is_syn = transport == "TCP" and bool(flags & 2) and not bool(flags & 16)
        alerts = []

        def emit(rule, level, message):
            alert = self.alert(rule, event, level, message, now)
            if alert:
                alerts.append(alert)

        def check(rule, message, value=None):
            detected, count = self.track(rule, src, dst, value, now)
            if detected:
                emit(rule, "MEDIUM", f"{message}: {count}")

        if is_syn:
            check("port_scan", "Әртүрлі мақсатты порттарға қосылу", event.get("dport"))
            check("syn_flood", "SYN пакеттерінің жоғары жиілігі")
            if event.get("dport") == 22:
                check("ssh_bruteforce", "SSH қосылымдарының жоғары жиілігі")
        if transport == "ICMP":
            check("icmp_flood", "ICMP пакеттерінің жоғары жиілігі")
        if transport == "UDP":
            check("udp_flood", "UDP пакеттерінің жоғары жиілігі")
        domain = (event.get("dns_query") or "").rstrip(".").lower()
        if protocol == "DNS" and event.get("dns_is_query") and domain:
            check("dns_flood", "DNS сұраныстарының жоғары жиілігі")
            labels = domain.split(".")
            if len(domain) > 100 or len(labels) > 8 or any(len(label) > 50 for label in labels):
                emit("suspicious_dns", "LOW", f"Күмәнді DNS домені: {domain[:120]}")
        if protocol == "FTP" and str(event.get("ftp_code")) == "530":
            emit("ftp_login_failure", "LOW", "FTP сервері авторизация әрекетін қабылдамады.")
        if event.get("size", 0) > 9000:
            emit("large_packet", "MEDIUM", f"Әдеттен тыс пакет көлемі: {event['size']} байт.")
        if transport == "TCP" and (
            flags == 0 or flags & 3 == 3 or flags & 6 == 6 or flags & 41 == 41
        ):
            emit("suspicious_tcp_flags", "MEDIUM", f"Әдеттен тыс TCP жалаушалары: {flags:#x}.")
        if is_syn or transport == "UDP":
            rule = "distributed_syn" if is_syn else "distributed_udp"
            detected, count = self.track(rule, "*", dst, now=now)
            sources = self.track_sources(rule, src, dst, now)
            if detected and sources >= self.min_distributed_sources:
                emit(rule, "MEDIUM", f"Мақсатқа жоғары жиілікті трафик: {count} пакет, {sources} дереккөз.")
        return alerts
