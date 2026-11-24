# NetGuard optimized

## Install on Windows

1. Install Python 3.11+.
2. Install Npcap from https://npcap.com/#download
3. Open PowerShell in this folder:
   `python -m pip install -r requirements.txt`
4. Start:
   `python main.py`

## Optimization

- Scapy capture runs in a QThread.
- Packets are converted to lightweight dictionaries immediately.
- UI consumes packets in batches (up to 300 every 300 ms).
- Scapy uses `store=False`, so the whole capture is not retained in RAM.
- Traffic table is limited to the configured number of rows (default 500).
- Radar keeps a bounded list of points (120).
- Radar animation is independent from packet capture (20 FPS).
- Statistics are incremented instead of rescanning the entire table.
- Windows adapter display name is separated from the internal Npcap interface name.

## Radar

Each protocol has its own sector:
HTTP, HTTPS, DNS, SSH, FTP, ICMP, QUIC, OTHER.

SSH and FTP have dedicated sectors. White = connection attempt, green = active/observed successful connection state, red = TCP reset or visible FTP 530 failure. SSH password correctness cannot be determined from ordinary encrypted packet capture.

## Important

This is a passive traffic monitor. It does not actively scan remote systems.
Heuristic events are indicators for investigation, not proof of malicious activity.

## IDS in version 0.7

- `ids_detector.py` detects port scans, SYN/UDP/ICMP/DNS bursts, SSH connection bursts, FTP failures, suspicious DNS/TCP flags, and large packets.
- Distributed SYN/UDP indicators require at least five active source IPs targeting the same destination.
- DNS replies are excluded from query counters. DHCP is classified separately.
- Flood counters use one-second buckets. Window boundaries have one-second granularity. Port history is limited to 1,024 distinct ports per pair, and detector windows/cooldowns to 10,000 keys.
- `risk_scoring.py` correlates indicators per source/destination pair, groups related flood rules, and retains at most 5,000 histories. Scores are heuristic values from 0 to 100.
- `ids_logger.py` writes UTF-8 JSONL alerts, including risk scores, to the selected log folder. The settings checkbox controls IDS logging. Files rotate at 5 MiB, with the newest 60 rotated files retained. Older daily JSONL files remain readable.
- The capture worker writes directly into the bounded packet queue. When it is full, new packets are dropped, so heavy-load monitoring may undercount traffic.

Run the detector and GUI integration tests without sending network packets:

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p "test_*.py" -v
```
