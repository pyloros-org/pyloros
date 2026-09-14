"""Handshake against a leaf cert with OpenSSL strict X.509 validation enabled.

Usage: x509_strict_check.py <ca.crt> <leaf.crt> <leaf.key>
Exits 0 on a successful handshake, 1 with the verification error on stderr otherwise.
"""

import socket
import ssl
import sys
import threading

ca_path, leaf_crt, leaf_key = sys.argv[1:4]

server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
server_ctx.load_cert_chain(leaf_crt, leaf_key)

listener = socket.socket()
listener.bind(("127.0.0.1", 0))
listener.listen(1)
port = listener.getsockname()[1]


def serve():
    try:
        conn, _ = listener.accept()
        server_ctx.wrap_socket(conn, server_side=True).close()
    except OSError:
        pass


threading.Thread(target=serve, daemon=True).start()

client_ctx = ssl.create_default_context(cafile=ca_path)
client_ctx.verify_flags |= ssl.VERIFY_X509_STRICT

try:
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        with client_ctx.wrap_socket(sock, server_hostname="localhost"):
            pass
except ssl.SSLError as e:
    print(e, file=sys.stderr)
    sys.exit(1)
