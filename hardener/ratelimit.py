"""Rate Limiter: global packets/sec ceiling (masscan-style --rate).

Enforces a conservative cap on how fast probes are emitted regardless of
thread count. A rate of 0 disables the limiter (threads alone govern pace).
"""

import threading
import time


class RateLimiter:
    def __init__(self, max_rate: float = 0.0):
        self.max_rate = float(max_rate)
        self._interval = (1.0 / self.max_rate) if self.max_rate > 0 else 0.0
        self._lock = threading.Lock()
        self._last = 0.0
        self._sent = 0

    @property
    def enabled(self):
        return self._interval > 0

    def acquire(self, tokens=1):
        """Block until a probe is allowed by the rate budget."""
        with self._lock:
            self._sent += tokens
            if not self.enabled:
                return
            now = time.time()
            wait = self._last + self._interval - now
            if wait > 0:
                time.sleep(wait)
            self._last = time.time()

    @property
    def sent(self):
        with self._lock:
            return self._sent
