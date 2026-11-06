import json
import tempfile
import unittest
from pathlib import Path

from lab import target_server
from reconlab import http_audit, nmap_wrapper, portscan, report
from reconlab.cli import main
from reconlab.findings import number
from reconlab.scope import Scope, ScopeError


class ScopeTests(unittest.TestCase):
    def test_loopback_and_private_allowed(self):
        s = Scope()
        self.assertEqual(s.check("127.0.0.1"), ["127.0.0.1"])
        self.assertEqual(s.check("192.168.1.10"), ["192.168.1.10"])

    def test_public_blocked(self):
        with self.assertRaises(ScopeError):
            Scope().check("8.8.8.8")

    def test_allow_extra_cidr(self):
        self.assertEqual(Scope(["203.0.113.0/24"]).check("203.0.113.5"), ["203.0.113.5"])

    def test_option_injection_rejected(self):
        with self.assertRaises(ScopeError):
            Scope().check("-oN /tmp/x")


class PortTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(portscan.parse_ports("22,80-82"), [22, 80, 81, 82])
        with self.assertRaises(ValueError):
            portscan.parse_ports("0")
        with self.assertRaises(ValueError):
            portscan.parse_ports("70000")

    def test_nmap_xml(self):
        xml = ('<nmaprun><host><ports><port protocol="tcp" portid="22"><state state="open"/>'
               '<service name="ssh" product="OpenSSH" version="9.0"/></port>'
               '<port protocol="tcp" portid="23"><state state="closed"/></port></ports></host></nmaprun>')
        rows = nmap_wrapper.parse_xml(xml)
        self.assertEqual(rows, [{"port": 22, "proto": "tcp", "service": "ssh",
                                 "product": "OpenSSH", "version": "9.0"}])


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers = target_server.start(18080, 12121, 12222)

    @classmethod
    def tearDownClass(cls):
        for s in cls.servers:
            s.shutdown()
            s.server_close()

    def test_scan_finds_lab_ports(self):
        res = portscan.scan("127.0.0.1", [18080, 12121, 12222, 12345])
        self.assertEqual([r.port for r in res], [12121, 12222, 18080])
        self.assertIn("vsFTPd", res[0].banner)

    def test_http_audit(self):
        findings, meta = http_audit.audit("http://127.0.0.1:18080/")
        titles = " ".join(f.title for f in findings)
        self.assertIn("Missing security header: content-security-policy", titles)
        self.assertIn("Exposed path: /.git/HEAD", titles)
        self.assertEqual(meta["status"], 200)

    def test_report_and_cli(self):
        with tempfile.TemporaryDirectory() as d:
            rc = main(["full", "127.0.0.1", "--ports", "12121,12222,18080,8080", "--out", d])
            self.assertEqual(rc, 0)
            files = list(Path(d).glob("*.json"))
            self.assertEqual(len(files), 1)
            data = json.loads(files[0].read_text())
            self.assertGreater(len(data["findings"]), 0)

    def test_cli_blocks_public(self):
        self.assertEqual(main(["scan", "8.8.8.8"]), 2)


if __name__ == "__main__":
    unittest.main()
