"""Local mock target lab for exercising the Hardener without external hosts.

Spawns small banner servers on loopback ports that mimic real services
(old/vulnerable versions), so the full pipeline (scan -> enum -> analysis ->
CVE correlation -> risk -> report) can be demonstrated safely.
"""

import datetime
import socket
import ssl
import threading
import time

import cryptography.x509 as x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

BIND = "127.0.0.1"


def _tcp(port, handler, family=socket.AF_INET):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((BIND, port))
    s.listen(8)
    def loop():
        while True:
            try:
                conn, _ = s.accept()
                threading.Thread(target=handler, args=(conn,), daemon=True).start()
            except OSError:
                break
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return s


def _gen_cert(host="localhost"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=30))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM), \
        key.private_bytes(serialization.Encoding.PEM,
                          serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption())


# --- service handlers -------------------------------------------------------

def http_handler(conn):
    try:
        conn.settimeout(3)
        req = conn.recv(4096).decode("utf-8", errors="ignore")
        parts = req.split(" ")
        path = parts[1] if len(parts) > 1 else "/"
        method = parts[0] if parts else "GET"
        if method == "OPTIONS":
            resp = ("HTTP/1.1 200 OK\r\nAllow: GET, POST, PUT, OPTIONS\r\n"
                    "Content-Length: 0\r\nConnection: close\r\n\r\n")
        elif path.startswith("/admin"):
            body = "<html><head><title>Admin</title></head><body>admin</body></html>"
            resp = ("HTTP/1.1 200 OK\r\nServer: Apache/2.4.54 (Ubuntu)\r\n"
                    "X-Powered-By: PHP/7.2.24\r\nContent-Length: %d\r\n"
                    "Connection: close\r\n\r\n%s" % (len(body), body))
        elif path in ("/backup.zip", "/.env", "/.git/config"):
            resp = ("HTTP/1.1 200 OK\r\nServer: Apache/2.4.54 (Ubuntu)\r\n"
                    "Content-Length: 0\r\nConnection: close\r\n\r\n")
        elif path.startswith("/robots.txt"):
            resp = ("HTTP/1.1 200 OK\r\nServer: Apache/2.4.54 (Ubuntu)\r\n"
                    "Content-Length: 0\r\nConnection: close\r\n\r\n")
        elif path == "/":
            body = ("<html><head><title>Mock Corp Portal</title></head><body>"
                    "<h1>Index of /</h1><ul><li><a href='admin/'>admin/</a></li>"
                    "<li><a href='backup.zip'>backup.zip</a></li></ul></body></html>")
            resp = ("HTTP/1.1 200 OK\r\nServer: Apache/2.4.54 (Ubuntu)\r\n"
                    "X-Powered-By: PHP/7.2.24\r\nContent-Length: %d\r\n"
                    "Connection: close\r\n\r\n%s" % (len(body), body))
        else:
            resp = ("HTTP/1.1 404 Not Found\r\nServer: Apache/2.4.54 (Ubuntu)\r\n"
                    "Content-Length: 0\r\nConnection: close\r\n\r\n")
        conn.sendall(resp.encode())
    except OSError:
        pass
    finally:
        conn.close()


def ssh_handler(conn):
    try:
        conn.sendall(b"SSH-2.0-OpenSSH_7.9p1 Ubuntu-10ubuntu0.1\r\n")
        time.sleep(0.5)
    finally:
        conn.close()


def redis_handler(conn):
    try:
        conn.settimeout(3)
        data = conn.recv(1024)
        if b"INFO" in data:
            conn.sendall(b"$142\r\n# Server\r\nredis_version:5.0.7\r\n"
                         b"os:Linux 5.4.0\r\n\r\n")
        else:
            conn.sendall(b"-ERR unknown command\r\n")
    finally:
        conn.close()


def telnet_handler(conn):
    try:
        conn.sendall(b"\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfb\x01\r\n"
                     b"Telnet mock login: ")
        time.sleep(0.5)
    finally:
        conn.close()


def ftp_handler(conn):
    try:
        conn.sendall(b"220 Mock FTP (vsftpd 2.3.4) ready.\r\n")
        conn.settimeout(3)
        buf = b""
        while True:
            chunk = conn.recv(256)
            if not chunk:
                break
            buf += chunk
            if b"USER" in buf:
                conn.sendall(b"331 Please specify the password.\r\n")
                buf = b""
            elif b"PASS" in buf:
                conn.sendall(b"230 Login successful.\r\n")
                buf = b""
    except OSError:
        pass
    finally:
        conn.close()


def mysql_handler(conn):
    try:
        conn.sendall(b"\x0a\x00\x00\x00\x0a5.6.17-log\x00\x00\x00\x00\x00\x00\x00"
                     b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                     b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
        time.sleep(0.3)
    finally:
        conn.close()


def postgres_handler(conn):
    try:
        conn.recv(64)
        conn.sendall(b"S")
        time.sleep(0.3)
    finally:
        conn.close()


def https_handler(conn):
    try:
        conn.settimeout(3)
        conn.recv(4096)
        resp = ("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n"
                "Strict-Transport-Security: max-age=31536000\r\n"
                "Content-Length: 2\r\nConnection: close\r\n\r\nok")
        conn.sendall(resp.encode())
    finally:
        conn.close()


def start_lab():
    ports = {}
    cert_der, key_der = _gen_cert()
    ports["http_8080"] = _tcp(8080, http_handler)
    ports["ssh_2222"] = _tcp(2222, ssh_handler)
    ports["redis_6379"] = _tcp(6379, redis_handler)
    ports["telnet_2323"] = _tcp(2323, telnet_handler)
    ports["ftp_2121"] = _tcp(2121, ftp_handler)
    ports["mysql_13306"] = _tcp(13306, mysql_handler)
    ports["postgres_15432"] = _tcp(15432, postgres_handler)

    import tempfile, os
    tmp = tempfile.mkdtemp()
    cpath = os.path.join(tmp, "cert.pem")
    kpath = os.path.join(tmp, "key.pem")
    with open(cpath, "wb") as fh:
        fh.write(cert_der)
    with open(kpath, "wb") as fh:
        fh.write(key_der)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cpath, kpath)
    https_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    https_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    https_sock.bind((BIND, 8443))
    https_sock.listen(8)
    tls_wrap = ctx.wrap_socket(https_sock, server_side=True)
    def https_loop():
        while True:
            try:
                conn, _ = tls_wrap.accept()
                threading.Thread(target=https_handler, args=(conn,), daemon=True).start()
            except (OSError, ssl.SSLError):
                time.sleep(0.05)
    threading.Thread(target=https_loop, daemon=True).start()
    ports["https_8443"] = tls_wrap
    return ports


if __name__ == "__main__":
    print("Starting mock target lab on 127.0.0.1 ...")
    start_lab()
    print("Listening: HTTP:8080 SSH:2222 Telnet:2323 FTP:2121 Redis:6379 "
          "MySQL:13306 PG:15432 HTTPS:8443")
    while True:
        time.sleep(1)
