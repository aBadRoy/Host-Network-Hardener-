"""CVE Correlation: curated local database of well-known vulnerabilities.

Maps detected software+version strings to a curated subset of public CVEs.
NOTE: this is a small local reference set for demonstration/offline use; for
production assessment, sync with NVD / OSV feeds for complete coverage.
"""

import re

# entry: software key, cve, cvss, introduced, fixed, description
CVE_DB = [
    # -- OpenSSH -------------------------------------------------------------
    {"software": "openssh", "cve": "CVE-2023-38408", "cvss": 9.8,
     "introduced": "1.0", "fixed": "9.3p2",
     "description": "Remote code execution via forwarded ssh-agent (pkcs11)."},
    {"software": "openssh", "cve": "CVE-2020-15778", "cvss": 8.8,
     "introduced": "1.0", "fixed": "8.4p1",
     "description": "scp command injection allows RCE (user with write to scp)."},
    {"software": "openssh", "cve": "CVE-2021-41617", "cvss": 7.8,
     "introduced": "1.0", "fixed": "8.8",
     "description": "Privilege escalation in sshd PrivilegeSeparator."},
    {"software": "openssh", "cve": "CVE-2018-15473", "cvss": 5.3,
     "introduced": "1.0", "fixed": "7.7",
     "description": "Username enumeration via authentication failure timing."},

    # -- Apache httpd --------------------------------------------------------
    {"software": "apache", "cve": "CVE-2021-42013", "cvss": 9.8,
     "introduced": "2.4.49", "fixed": "2.4.50",
     "description": "Path traversal & RCE (bypass of CVE-2021-41773)."},
    {"software": "apache", "cve": "CVE-2021-41773", "cvss": 7.5,
     "introduced": "2.4.49", "fixed": "2.4.50",
     "description": "Path traversal & file disclosure (encoded ../)."},
    {"software": "apache", "cve": "CVE-2019-0211", "cvss": 8.8,
     "introduced": "2.4.17", "fixed": "2.4.39",
     "description": "Arbitrary code execution as root via race condition in mpm."},
    {"software": "apache", "cve": "CVE-2017-15715", "cvss": 6.5,
     "introduced": "2.4.0", "fixed": "2.4.26",
     "description": "Filename sanitisation bypass allows script upload."},

    # -- Nginx ---------------------------------------------------------------
    {"software": "nginx", "cve": "CVE-2017-7529", "cvss": 7.5,
     "introduced": "0.5.6", "fixed": "1.13.3",
     "description": "Integer overflow in range filter -> HTTP response splitting."},
    {"software": "nginx", "cve": "CVE-2013-2028", "cvss": 7.5,
     "introduced": "1.3.9", "fixed": "1.4.1",
     "description": "Stack-based buffer overflow in ngx_http_parse_chunked."},

    # -- IIS ----------------------------------------------------------------
    {"software": "iis", "cve": "CVE-2017-7269", "cvss": 9.8,
     "introduced": "6.0", "fixed": "6.1",
     "description": "Buffer overflow in WebDAV (ScStoragePathFromUrl)."},

    # -- MySQL / MariaDB -----------------------------------------------------
    {"software": "mysql", "cve": "CVE-2012-2122", "cvss": 9.8,
     "introduced": "5.1.1", "fixed": "5.5.24",
     "description": "Authentication bypass (MEMORY comparison timing flaw)."},
    {"software": "mysql", "cve": "CVE-2016-6662", "cvss": 8.8,
     "introduced": "5.5.51", "fixed": "5.7.15",
     "description": "MySQL / MariaDB remote code execution via crafted config."},
    {"software": "mariadb", "cve": "CVE-2012-2122", "cvss": 9.8,
     "introduced": "5.1.1", "fixed": "5.5.24",
     "description": "Authentication bypass (MEMORY comparison timing flaw)."},

    # -- PostgreSQL ----------------------------------------------------------
    {"software": "postgresql", "cve": "CVE-2018-1058", "cvss": 8.1,
     "introduced": "9.3", "fixed": "9.3.21",
     "description": "search_path hijacking allows command execution (Holey Beanstalk)."},
    {"software": "postgresql", "cve": "CVE-2023-5868", "cvss": 6.5,
     "introduced": "9.0", "fixed": "16.1",
     "description": "Invalid memory access may leak error messages to remote client."},

    # -- Redis ---------------------------------------------------------------
    {"software": "redis", "cve": "CVE-2022-0543", "cvss": 10.0,
     "introduced": "1.0", "fixed": "6.2.7",
     "description": "Lua sandbox escape on Debian -> remote code execution."},
    {"software": "redis", "cve": "CVE-2015-4335", "cvss": 7.5,
     "introduced": "1.0", "fixed": "2.8.21",
     "description": "EVAL command allows arbitrary Lua bytecode execution."},

    # -- MongoDB -------------------------------------------------------------
    {"software": "mongodb", "cve": "CVE-2015-2705", "cvss": 7.5,
     "introduced": "2.4.0", "fixed": "2.6.9",
     "description": "Heap overflow in BSON decoding -> denial of service/RCE."},
    {"software": "mongodb", "cve": "CVE-2013-3969", "cvss": 6.5,
     "introduced": "2.4.0", "fixed": "2.4.6",
     "description": "Memory corruption via malformed BSON objects."},

    # -- Samba / SMB ---------------------------------------------------------
    {"software": "samba", "cve": "CVE-2017-7494", "cvss": 10.0,
     "introduced": "3.5.0", "fixed": "4.6.4",
     "description": "Remote code execution via crafted SMB request (SambaCry)."},
    {"software": "smb", "cve": "CVE-2017-0144", "cvss": 9.8,
     "introduced": "1.0", "fixed": "9.0",
     "description": "SMBv1 remote code execution (EternalBlue / MS17-010)."},

    # -- PHP -----------------------------------------------------------------
    {"software": "php", "cve": "CVE-2024-4577", "cvss": 9.8,
     "introduced": "5.0", "fixed": "8.1.29",
     "description": "Windows argument injection in CGI mode -> RCE."},
    {"software": "php", "cve": "CVE-2019-11043", "cvss": 9.8,
     "introduced": "7.0", "fixed": "7.4.1",
     "description": "PHP-FPM env_path_info underflow -> remote code execution."},
    {"software": "php", "cve": "CVE-2012-1823", "cvss": 9.8,
     "introduced": "5.3.0", "fixed": "5.4.2",
     "description": "CGI query string argument injection -> arbitrary code execution."},

    # -- Apache Tomcat -------------------------------------------------------
    {"software": "tomcat", "cve": "CVE-2020-1938", "cvss": 9.8,
     "introduced": "7.0", "fixed": "9.0.31",
     "description": "Ghostcat: AJP connector file read / RCE."},
    {"software": "tomcat", "cve": "CVE-2017-12615", "cvss": 9.8,
     "introduced": "7.0", "fixed": "7.0.82",
     "description": "PUT method allows writing JSP -> remote code execution."},

    # -- Docker / runc -------------------------------------------------------
    {"software": "docker", "cve": "CVE-2019-5736", "cvss": 8.6,
     "introduced": "1.0", "fixed": "18.09.2",
     "description": "runc container escape -> host root code execution."},
    {"software": "docker", "cve": "CVE-2017-7308", "cvss": 7.8,
     "introduced": "1.12.0", "fixed": "17.04.0",
     "description": "Docker daemon socket allows remote privilege escalation (API)."},

    # -- Elasticsearch -------------------------------------------------------
    {"software": "elasticsearch", "cve": "CVE-2015-1427", "cvss": 9.8,
     "introduced": "1.0.0", "fixed": "1.3.8",
     "description": "Remote code execution via MVEL scripting."},

    # -- VNC -----------------------------------------------------------------
    {"software": "vnc", "cve": "CVE-2006-2369", "cvss": 10.0,
     "introduced": "1.0", "fixed": "4.1.1",
     "description": "RealVNC/others: buffer overflow in HTTP server -> RCE."},
    {"software": "vnc", "cve": "CVE-2013-6886", "cvss": 9.0,
     "introduced": "1.0", "fixed": "5.2.1",
     "description": "RealVNC: auth bypass via flawed session handling (authentication bypass)."},

    # -- Drupal --------------------------------------------------------------
    {"software": "drupal", "cve": "CVE-2018-7600", "cvss": 9.8,
     "introduced": "7.0", "fixed": "8.5.1",
     "description": "Drupalgeddon2: remote code execution via form API."},

    # -- Wordpress (base version) --------------------------------------------
    {"software": "wordpress", "cve": "CVE-2019-8942", "cvss": 9.8,
     "introduced": "5.0.0", "fixed": "5.1.1",
     "description": "Arbitrary file upload leading to remote code execution."},

    # -- vsftpd --------------------------------------------------------------
    {"software": "vsftpd", "cve": "CVE-2011-0762", "cvss": 7.5,
     "introduced": "2.3.0", "fixed": "2.3.4",
     "description": "Backdoor command execution (compromised binary, smiley face)."},
    {"software": "vsftpd", "cve": "CVE-2015-1419", "cvss": 5.0,
     "introduced": "2.0.0", "fixed": "3.0.3",
     "description": "Incorrect handling of user names containing backslashes."},

    # -- ProFTPD -------------------------------------------------------------
    {"software": "proftpd", "cve": "CVE-2015-3306", "cvss": 10.0,
     "introduced": "1.3.0", "fixed": "1.3.5",
     "description": "mod_copy SITE CPFR/CPTO -> arbitrary file copy / RCE."},

    # -- Exim ----------------------------------------------------------------
    {"software": "exim", "cve": "CVE-2019-10149", "cvss": 9.8,
     "introduced": "4.80", "fixed": "4.92",
     "description": "Remote command execution (CVE-2019-10149 / 'Return of the WIZARD')."},
]


def version_tuple(version_str):
    """Extract leading numeric version parts as a comparable tuple."""
    if not version_str:
        return ()
    nums = re.findall(r"\d+", version_str)
    try:
        return tuple(int(n) for n in nums[:4])
    except ValueError:
        return ()


# Software-specific version extraction from banners (avoids protocol prefixes
# like "SSH-2.0" or "220" polluting the version).
VERSION_PATTERNS = {
    "openssh": r"OpenSSH[_ ]([\d.]+[a-zA-Z0-9]*)",
    "apache": r"Apache[/ ]([\d.]+)",
    "nginx": r"nginx[/ ]([\d.]+)",
    "php": r"PHP[/ ]([\d.]+)",
    "mysql": r"(?:MySQL|MariaDB)[/\s]*([\d.]+[a-zA-Z0-9]*)",
    "mariadb": r"(?:MySQL|MariaDB)[/\s]*([\d.]+[a-zA-Z0-9]*)",
    "postgresql": r"PostgreSQL[ /]*([\d.]+)",
    "redis": r"(?:redis_version[: ]*|redis\s+)([\d.]+)",
    "vsftpd": r"vsftpd[ /]*([\d.]+)",
    "proftpd": r"ProFTPD[ /]*([\d.]+)",
    "tomcat": r"Apache[/ ]Tomcat[/ ]*([\d.]+)",
    "iis": r"Microsoft-IIS[/ ]*([\d.]+)",
}


def extract_version(software, banner):
    """Extract a version string for a software key from a banner."""
    if not banner:
        return banner or ""
    pattern = VERSION_PATTERNS.get(normalize_key(software))
    if pattern:
        m = re.search(pattern, banner, re.IGNORECASE)
        if m:
            return m.group(1)
    # fallback: strip common protocol prefixes before extracting digits
    stripped = re.sub(r"^(?:ssh-2\.0|http/\d\.\d|220[- ]|250[- ]|ftp)\s*",
                      "", banner, flags=re.IGNORECASE)
    nums = re.findall(r"\d+", stripped)
    if nums:
        return ".".join(nums[:3])
    return banner[:30]


def normalize_key(software):
    return software.lower().replace("_", "").replace("-", "").replace(" ", "")


SOFTWARE_DISPLAY = {
    "openssh": "OpenSSH",
    "apache": "Apache httpd",
    "nginx": "Nginx",
    "iis": "Microsoft IIS",
    "mysql": "MySQL",
    "mariadb": "MariaDB",
    "postgresql": "PostgreSQL",
    "redis": "Redis",
    "mongodb": "MongoDB",
    "samba": "Samba",
    "php": "PHP",
    "tomcat": "Apache Tomcat",
    "docker": "Docker",
    "elasticsearch": "Elasticsearch",
    "vnc": "VNC",
    "drupal": "Drupal",
    "wordpress": "WordPress",
    "vsftpd": "vsftpd",
    "proftpd": "ProFTPD",
    "exim": "Exim",
    "smb": "SMB",
}


def display_name(key):
    return SOFTWARE_DISPLAY.get(normalize_key(key), key.capitalize())


def match_cves(software, version_str):
    """Return list of CVE entries matching software + version."""
    key = normalize_key(software)
    vt = version_tuple(extract_version(software, version_str))
    if not vt:
        return []
    matches = []
    for entry in CVE_DB:
        if key != normalize_key(entry["software"]):
            continue
        introduced = version_tuple(entry["introduced"])
        fixed = version_tuple(entry["fixed"])
        if vt >= introduced and (not fixed or vt < fixed):
            matches.append(entry)
    return matches


# Direct service-name -> software key. Used first as it is the most reliable
# signal (e.g. service "ssh" is OpenSSH, "redis" is Redis).
SERVICE_TO_SOFTWARE = {
    "ssh": "openssh",
    "openssh": "openssh",
    "apache": "apache",
    "nginx": "nginx",
    "iis": "iis",
    "mysql": "mysql",
    "mariadb": "mariadb",
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "redis": "redis",
    "mongodb": "mongodb",
    "samba": "samba",
    "smb": "smb",
    "microsoft-ds": "smb",
    "php": "php",
    "tomcat": "tomcat",
    "docker": "docker",
    "elasticsearch": "elasticsearch",
    "vnc": "vnc",
    "drupal": "drupal",
    "wordpress": "wordpress",
    "vsftpd": "vsftpd",
    "proftpd": "proftpd",
    "exim": "exim",
}

# Strong banner signatures -> software key. These are full identifiers that are
# extremely unlikely to appear inside an unrelated banner (avoiding false
# positives such as "MKSDisplayProtocol:VNC" triggering a VNC match).
BANNER_SIGNATURES = [
    (r"\bOpenSSH[-_]", "openssh"),
    (r"\bApache/\d", "apache"),
    (r"\bnginx/\d", "nginx"),
    (r"\bMicrosoft-IIS|Microsoft-HTTPAPI", "iis"),
    (r"\b(?:MySQL|MariaDB)/", "mysql"),
    (r"\bPostgreSQL", "postgresql"),
    (r"\bredis_version\s*:|redis-server|redis-cli", "redis"),
    (r"\bvsftpd", "vsftpd"),
    (r"\bProFTPD", "proftpd"),
    (r"\bApache/\d+\.[\d.]+\s+Tomcat|\bTomcat/\d", "tomcat"),
    (r"\bPHP/\d", "php"),
    (r"\bRealVNC|TigerVNC|TightVNC|UltraVNC|RFB \d+\.\d+", "vnc"),
    (r"\bDocker|Docker Engine", "docker"),
    (r"\bElasticsearch", "elasticsearch"),
    (r"\bDrupal", "drupal"),
    (r"\bWordPress", "wordpress"),
    (r"\bExim \d|exim-config", "exim"),
    (r"\bSamba \d|Samba/", "samba"),
]


def match_software_aliases(service_name, version_str):
    """Map a service name + banner to a candidate software key."""
    svc = service_name.lower().strip()
    if svc in SERVICE_TO_SOFTWARE:
        return SERVICE_TO_SOFTWARE[svc]
    combined = f"{service_name} {version_str}".lower()
    for pattern, key in BANNER_SIGNATURES:
        if re.search(pattern, combined, re.IGNORECASE):
            return key
    return None
