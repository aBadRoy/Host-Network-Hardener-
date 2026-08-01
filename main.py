#!/usr/bin/env python3
"""Entry point for the Host & Network Hardener.

Usage:
    python main.py --targets <ip|cidr|hostname> [options]
"""

import sys

from hardener.cli import main

if __name__ == "__main__":
    sys.exit(main())
