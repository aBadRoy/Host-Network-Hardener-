"""Audit Trail: append-only, timestamped log of every action taken.

Each entry records the stage, action, target and outcome so a run can be
reviewed end-to-end. The log is written incrementally (one line per action)
and is never rewritten, matching the 'audit.log' contract in the spec.
"""

import os
import threading
from datetime import datetime

from .utils import ensure_dir

_ESCAPE = str.maketrans({"|": "_", "\n": " ", "\r": " "})


def _clean(value):
    if value is None:
        return ""
    return str(value).translate(_ESCAPE)


class AuditLog:
    def __init__(self, path):
        self.path = os.path.abspath(path)
        self._lock = threading.Lock()
        ensure_dir(os.path.dirname(self.path) or ".")
        self._fh = open(self.path, "a", encoding="utf-8")
        self._fh.write(f"# audit log started {datetime.utcnow().isoformat()}Z\n")
        self._fh.flush()

    def log(self, stage, action, target="", result="", **extra):
        """Append one audit line, e.g.:

        STAGE5 | port_scan | target=10.0.0.5 | result=6 open ports
        """
        when = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        parts = [_clean(action)]
        if target:
            parts.append(f"target={_clean(target)}")
        if result:
            parts.append(f"result={_clean(result)}")
        for key, value in extra.items():
            if value not in (None, ""):
                parts.append(f"{key}={_clean(value)}")
        line = f"{when} | {_clean(stage)} | " + " | ".join(parts) + "\n"
        with self._lock:
            self._fh.write(line)
            self._fh.flush()

    def close(self):
        with self._lock:
            self._fh.close()
