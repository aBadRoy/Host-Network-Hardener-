"""Host & Network Hardener - security assessment, hardening and remediation engine.

Implements a full assessment workflow: target intake -> scope validation ->
DNS/infra discovery -> host discovery -> port scanning -> service enumeration ->
banner/fingerprinting -> OS fingerprinting -> security analysis -> CVE
correlation -> risk scoring -> reporting -> remediation guidance.
"""

__version__ = "1.0.0"
__author__ = "network_hardener"

from .hardener import Hardener

__all__ = ["Hardener", "__version__"]
