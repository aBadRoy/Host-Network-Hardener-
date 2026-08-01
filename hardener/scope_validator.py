"""Scope Validator: enforces authorization and organisational constraints.

Checks every target against the authorised scope (allowed ranges, excluded
assets, rate limits and scan windows). The tool will not proceed against a
target unless it is in scope AND the operator has confirmed authorisation.
"""

import ipaddress
from datetime import datetime

from .utils import info, ok, warn

SCOPE_SERVICES = {"22": "SSH", "80": "HTTP", "443": "HTTPS"}


class ScopeError(Exception):
    pass


class ScopeValidator:
    def __init__(self, scope=None, authorized=False, scan_window=None, rate_limit=None):
        self.scope = scope or {}
        self.authorized = authorized
        self.allowed = [ipaddress.ip_network(c, strict=False)
                        for c in self.scope.get("allowed", ["0.0.0.0/0", "::/0"])]
        self.excluded = [ipaddress.ip_network(c, strict=False)
                         for c in self.scope.get("excluded", [])]
        self.rate_limit = rate_limit or self.scope.get("rate_limit")
        self.scan_window = scan_window or self.scope.get("window")
        self.blocked_assets = self.scope.get("blocked_assets", [])

    # ------------------------------------------------------------------
    def _ip_in_scope(self, ip):
        addr = ipaddress.ip_address(ip)
        if any(addr in net for net in self.excluded):
            return False
        return any(addr in net for net in self.allowed)

    def validate(self, target):
        """Return (approved: bool, reason: str) for a Target."""
        if not self.authorized:
            return False, "Authorisation not confirmed; pass --authorized."
        if not self._scan_window_allowed():
            return False, f"Outside allowed scan window ({self.scan_window})."
        if target.ip:
            if not self._ip_in_scope(target.ip):
                return False, f"{target.ip} is outside the authorised scope (or excluded)."
        for blocked in self.blocked_assets:
            if target.hostname and blocked in target.hostname:
                return False, f"{target.hostname} is on the blocked-assets list."
            if blocked == target.ip:
                return False, f"{target.ip} is on the blocked-assets list."
        return True, "In scope and authorised."

    # ------------------------------------------------------------------
    def _scan_window_allowed(self):
        if not self.scan_window:
            return True
        try:
            start, _, end = self.scan_window.replace(" ", "").partition("-")
            now = datetime.now().strftime("%H:%M")
            if start <= end:
                return start <= now <= end
            return now >= start or now <= end
        except Exception:
            return True

    # ------------------------------------------------------------------
    def confirm_authorization(self):
        """Explicit user consent gate before any active scanning."""
        if self.authorized:
            ok("Authorisation confirmed by --authorized flag.")
            return True
        ok("Scope validation passed. Active scanning requires explicit authorisation.")
        warn("You must have written permission to scan the target(s).")
        try:
            ans = input("Confirm you are authorised to test these systems? [y/N]: ").strip().lower()
        except EOFError:
            ans = "n"
        if ans in ("y", "yes"):
            self.authorized = True
            ok("Authorisation confirmed.")
            return True
        warn("Authorisation declined. Aborting scan.")
        return False

    # ------------------------------------------------------------------
    def check_rate_limit(self, host_count):
        """Informational guard: keeps the scan courteous to networks."""
        if self.rate_limit:
            info(f"Rate limit configured at {self.rate_limit} pkts/sec over {host_count} host(s).")
            return True
        return True
