"""Shared helpers: console I/O, timestamps, network utilities."""

import ipaddress
import os
import re
import sys
import time
import threading
from datetime import datetime

_PRINT_LOCK = threading.Lock()
_COLOR = sys.stdout.isatty()


class Color:
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"


def set_color(enabled):
    global _COLOR
    _COLOR = enabled and sys.stdout.isatty()


def paint(text, color=Color.RESET, bold=False):
    if not _COLOR:
        return text
    prefix = color + (Color.BOLD if bold else "")
    return f"{prefix}{text}{Color.RESET}"


def sanitize_text(text):
    """Make arbitrary (possibly binary-derived) text safe to store and print.

    Strips control characters and replaces characters the console cannot
    encode, so printing raw remote banners never crashes the tool.
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", text)
    try:
        enc = sys.stdout.encoding or "ascii"
        text.encode(enc, errors="strict")
    except UnicodeEncodeError:
        text = text.encode(enc, errors="replace").decode(enc, errors="replace")
    return text


def out(msg="", color=None, bold=False):
    """Thread-safe console output."""
    line = paint(sanitize_text(msg), color, bold) if color else sanitize_text(msg)
    with _PRINT_LOCK:
        print(line, flush=True)


def info(msg):
    out(f"[*] {msg}", Color.BLUE)


def ok(msg):
    out(f"[+] {msg}", Color.GREEN)


def warn(msg):
    out(f"[-] {msg}", Color.YELLOW)


def vuln(msg):
    out(f"[VULN] {msg}", Color.RED, bold=True)


def low_pri(msg):
    out(f"     {msg}", Color.DIM)


def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def stamp_id():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def elapsed(start):
    return time.time() - start


def fmt_time(seconds):
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    return f"{seconds:.2f} s"


def is_valid_ip(text):
    try:
        ipaddress.ip_address(text.strip())
        return True
    except ValueError:
        return False


def is_valid_cidr(text):
    try:
        ipaddress.ip_network(text.strip(), strict=False)
        return True
    except ValueError:
        return False


def is_valid_hostname(text):
    if len(text) > 253:
        return False
    if not re.match(r"^(?=.{1,253}$)([a-zA-Z0-9_]([a-zA-Z0-9\-_]{0,61}[a-zA-Z0-9_])?\.)+[a-zA-Z]{2,63}$", text):
        return False
    return True


def normalize_url_target(raw):
    """Normalise a URL-ish target string into hostname + port if given."""
    url = raw.strip()
    if "://" in url:
        url = url.split("://", 1)[1]
    url = url.rstrip("/")
    if ":" in url and not url.startswith("["):
        host, _, port = url.rpartition(":")
        if port.isdigit():
            return host, int(port)
    return url, None


def host_to_ip(hostname):
    """Best-effort DNS resolution; returns None on failure."""
    import socket
    try:
        return socket.gethostbyname(hostname)
    except OSError:
        return None


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)
    return path
