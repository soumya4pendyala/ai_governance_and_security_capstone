"""Append-only SHA-256 hash-chained audit records without applicant data."""

import hashlib
import hmac
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_GENESIS_HASH = "0" * 64


class TamperEvidentAuditLog:
    def __init__(self, path: str):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._previous_hash = self.verify()
        initial_stat = self.path.stat() if self.path.exists() else None
        self._file_size = initial_stat.st_size if initial_stat else 0
        self._file_mtime_ns = initial_stat.st_mtime_ns if initial_stat else None

    @staticmethod
    def _canonical_json(value: Any) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")

    @classmethod
    def _entry_hash(cls, event: dict[str, Any], previous_hash: str) -> str:
        return hashlib.sha256(cls._canonical_json({
            "event": event,
            "previous_hash": previous_hash,
        })).hexdigest()

    def _last_hash(self) -> str:
        if not self.path.exists():
            return _GENESIS_HASH

        previous_hash = _GENESIS_HASH
        try:
            with self.path.open("r", encoding="utf-8") as audit_file:
                for line_number, line in enumerate(audit_file, start=1):
                    entry = json.loads(line)
                    event = entry["event"]
                    if entry["previous_hash"] != previous_hash:
                        raise ValueError(f"Audit chain link mismatch at line {line_number}.")
                    expected_hash = self._entry_hash(event, previous_hash)
                    if not hmac.compare_digest(entry["entry_hash"], expected_hash):
                        raise ValueError(f"Audit entry integrity check failed at line {line_number}.")
                    previous_hash = expected_hash
        except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise RuntimeError("Unable to validate CRA gateway audit chain.") from exc
        except ValueError as exc:
            raise RuntimeError("CRA gateway audit chain is corrupt; refusing to append.") from exc
        return previous_hash

    def verify(self) -> str:
        return self._last_hash()

    def append(self, *, request_id: str, tool: str, outcome: str, status_code: int) -> str:
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": request_id,
            "tool": tool,
            "outcome": outcome,
            "status_code": status_code,
        }
        with self._lock:
            current_stat = self.path.stat() if self.path.exists() else None
            current_size = current_stat.st_size if current_stat else 0
            current_mtime_ns = current_stat.st_mtime_ns if current_stat else None
            if current_size != self._file_size or current_mtime_ns != self._file_mtime_ns:
                raise RuntimeError("CRA gateway audit chain changed after startup; refusing to append.")
            previous_hash = self._previous_hash
            entry_hash = self._entry_hash(event, previous_hash)
            entry = {
                "event": event,
                "previous_hash": previous_hash,
                "entry_hash": entry_hash,
            }
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as audit_file:
                    audit_file.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
                    audit_file.flush()
                    os.fsync(audit_file.fileno())
                final_stat = self.path.stat()
            except OSError as exc:
                raise RuntimeError("Unable to persist CRA gateway audit record.") from exc
            self._previous_hash = entry_hash
            self._file_size = final_stat.st_size
            self._file_mtime_ns = final_stat.st_mtime_ns
            return entry_hash
