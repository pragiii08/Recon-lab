"""Local practice target (binds to 127.0.0.1 ONLY).

Simulates a deliberately weak host so you can practise recon safely:
  * 8080  HTTP  - missing security headers, version disclosure, exposed paths, weak cookie
  * 2121  FTP-like banner (simulated old vsftpd)
  * 2222  SSH-like banner (simulated old OpenSSH)
Nothing here is exploitable; it only returns static text.
"""
from __future__ import annotations

import socketserver
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

HOST = "127.0.0.1"


class Web(BaseHTTPRequestHandler):
    server_version = "Apache/2.2.8 (LabSim)"
    sys_version = ""

    def log_message(self, *a):  # quiet
        pass

    def do_GET(self):
        routes = {
            "/": (200, "<h1>Acme Lab Portal</h1><p>Welcome. Nothing real here.</p>"),
            "/robots.txt": (200, "User-agent: *\nDisallow: /admin\nDisallow: /backup.zip\n"),
            "/admin": (200, "<h1>Admin login (simulated)</h1>"),
            "/.git/HEAD": (200, "ref: refs/heads/main\n"),
        }
        status, body = routes.get(self.path, (404, "Not found"))
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("X-Powered-By", "PHP/5.2.4")
        self.send_header("Set-Cookie", "SESSIONID=abc123; Path=/")
        self.end_headers()
        self.wfile.write(body.encode())


def banner_server(port: int, banner: bytes):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                self.request.sendall(banner)
            except OSError:
                pass
    srv = socketserver.ThreadingTCPServer((HOST, port), H)
    srv.daemon_threads = True
    srv.allow_reuse_address = True
    return srv


def start(web_port=8080, ftp_port=2121, ssh_port=2222):
    servers = [HTTPServer((HOST, web_port), Web),
               banner_server(ftp_port, b"220 (vsFTPd 2.3.4) lab-sim\r\n"),
               banner_server(ssh_port, b"SSH-2.0-OpenSSH_5.3 lab-sim\r\n")]
    for s in servers:
        threading.Thread(target=s.serve_forever, daemon=True).start()
    return servers


def main():
    servers = start()
    print(f"[lab] target up on {HOST}: http=8080 ftp=2121 ssh=2222  (Ctrl+C to stop)")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()


if __name__ == "__main__":
    main()
