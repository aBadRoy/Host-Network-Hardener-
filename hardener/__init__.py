"""Host & Network Hardener - security assessment, hardening and remediation engine.

Implements a full assessment workflow: target intake -> scope validation ->
DNS/infra discovery -> host discovery -> port scanning -> service enumeration ->
banner/fingerprinting -> OS fingerprinting -> security analysis -> CVE
correlation -> risk scoring -> reporting -> remediation guidance.
"""

from .config import VERSION as __version__
from .hardener import Hardener

__author__ = "D1"

__all__ = ["Hardener", "__version__"]
