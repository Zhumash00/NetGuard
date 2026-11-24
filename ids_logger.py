"""UTF-8 JSONL alerts with bounded file rotation."""

import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path


class IDSLogger:
    def __init__(self, log_dir="logs", max_bytes=5 * 1024 * 1024, max_files=60):
        self.log_dir = Path(log_dir)
        self.max_bytes = max_bytes
        self.max_files = max_files
        self.lock = threading.Lock()

    def write(self, alert):
        now = datetime.now(timezone.utc)
        record = {
            **alert, "event_id": str(uuid.uuid4()), "timestamp": now.isoformat(),
            "message": alert.get("message", alert.get("detail", "")),
        }
        line = (json.dumps(record, ensure_ascii=False, default=str) + "\n").encode("utf-8")
        with self.lock:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            prefix = f"ids_{now:%Y-%m-%d}"
            files = sorted(self.log_dir.glob(f"{prefix}_*.jsonl"))
            path = files[-1] if files else self.log_dir / f"{prefix}_000000.jsonl"
            if path.exists() and path.stat().st_size and path.stat().st_size + len(line) > self.max_bytes:
                index = int(path.stem.rsplit("_", 1)[1]) + 1
                path = self.log_dir / f"{prefix}_{index:06d}.jsonl"
            with path.open("ab") as stream:
                stream.write(line)
            files = sorted(self.log_dir.glob("ids_????-??-??_??????.jsonl"))
            for expired in files[:-self.max_files]:
                expired.unlink()
        return record

    def read(self, filename):
        path = self.log_dir / Path(filename).name
        with self.lock:
            if not path.exists():
                return []
            records = []
            for line in path.read_text(encoding="utf-8").splitlines():
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(record, dict):
                    records.append(record)
            return records
