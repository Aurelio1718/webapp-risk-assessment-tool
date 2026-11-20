"""Integration test of the native http-headers probe and of `wra all` against a local HTTP server."""
import http.server
import os
import re
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wra.cli import main  # noqa: E402


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Server", "nginx/1.27.4")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Set-Cookie", "session=abc; Path=/")
        self.end_headers()
        self.wfile.write(b"ok")

    do_HEAD = do_GET

    def log_message(self, *args):
        pass


class HttpProbeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def run_wra(self, tmp, *args, authorized="yes", hosts="127.0.0.1"):
        text = (ROOT / "config.example.ini").read_text()
        text = text.replace("authorized = no", f"authorized = {authorized}")
        text = text.replace("hosts = 192.168.122.93", f"hosts = {hosts}")
        text = text.replace("url = https://192.168.122.93/", f"url = http://127.0.0.1:{self.port}/")
        # never run real third-party scanners from unit tests: tool probes become "not assessed"
        text = re.sub(r"(?m)^([a-z-]+) = docker\.io/.*$", r"\1 = REPLACE_ME", text)
        cfg = Path(tmp) / "config.ini"
        cfg.write_text(text)
        os.chmod(cfg, 0o600)
        return main(list(args) + ["-c", str(cfg), "--out", str(Path(tmp) / "run")])

    def test_all_produces_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self.run_wra(tmp, "all"), 0)
            run = Path(tmp) / "run"
            report = (run / "report.md").read_text()
            csv_text = (run / "findings.csv").read_text()
            self.assertIn("Content-Security-Policy header not set", report)
            self.assertIn("server-version-disclosure", csv_text)
            self.assertIn("cookie-no-httponly:session", csv_text)
            self.assertNotIn("missing-xcto", csv_text)
            self.assertTrue((run / "evidence" / "http-headers-base.txt").is_file())
            # report can be rebuilt without rescanning
            self.assertEqual(self.run_wra(tmp, "report"), 0)

    def test_scope_violation_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self.run_wra(tmp, "external", hosts="10.0.0.0/8"), 3)
            self.assertEqual(self.run_wra(tmp, "external", authorized="no"), 3)
            self.assertFalse((Path(tmp) / "run" / "external").exists())


if __name__ == "__main__":
    unittest.main()
