import json
import os
from pathlib import Path
from datetime import datetime
from filelock import FileLock


class JSONStore:
    """Simple file-backed JSON store for orgs, admins, and alerts.

    Files are created under the backend/db directory next to this file.
    All read/write operations are protected by a FileLock so concurrent
    processes/threads won't corrupt files.
    """

    def __init__(self):
        self.data_dir = Path(__file__).resolve().parent
        self.orgs_file = self.data_dir / "orgs.json"
        self.admins_file = self.data_dir / "admins.json"
        self.alerts_file = self.data_dir / "alerts.json"
        self.lock_file = self.data_dir / "store.lock"
        self.lock = FileLock(str(self.lock_file))

        # ensure files exist
        for p in (self.orgs_file, self.admins_file, self.alerts_file):
            if not p.exists():
                p.write_text("[]")

    def _load(self, path: Path):
        with self.lock:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except json.JSONDecodeError:
                # If the file is empty/corrupt, return empty list
                return []

    def _save(self, path: Path, data):
        with self.lock:
            # Use default=str to serialize datetimes as ISO strings
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, default=str, indent=2)

    def load_orgs(self):
        return self._load(self.orgs_file)

    def save_orgs(self, orgs):
        return self._save(self.orgs_file, orgs)

    def load_admins(self):
        return self._load(self.admins_file)

    def save_admins(self, admins):
        return self._save(self.admins_file, admins)

    def load_alerts(self):
        return self._load(self.alerts_file)

    def save_alerts(self, alerts):
        return self._save(self.alerts_file, alerts)
