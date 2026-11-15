"""Static integration-contract checks for non-destructive Stage V3 shell wrapper."""
from pathlib import Path
import ast
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT/'setup/staged_collect_v3.sh').read_text()


class TestV3Contract(unittest.TestCase):
    def test_no_legacy_compose_capture_overlay(self):
        self.assertNotIn('compose.staged.capture.yaml', SRC)
        self.assertIn('container:$GATEWAY_CID', SRC)
        self.assertIn('docker stop --signal SIGINT --timeout 8', SRC)
        self.assertIn('--cap-add NET_RAW', SRC)
        self.assertIn('staged_capture_audit', SRC)

    def test_live_progress_and_fail_closed(self):
        for marker in ('HEARTBEAT', 'collector_status_v3.json', 'CAPTURE_PREFLIGHT_FAILED',
                       'CAPTURE_TOO_SPARSE', 'cannot recreate missing PCAP',
                       'Another staged collector holds'):
            self.assertIn(marker, SRC)

    def test_probe_is_parseable_python(self):
        match = re.search(r"^  PROBE='([^']+)'$", SRC, re.M)
        self.assertIsNotNone(match)
        ast.parse(match.group(1))

    def test_restricted_capture_can_write_the_bind_mount(self):
        """--cap-drop ALL removes DAC_OVERRIDE, so the capture file must be pre-created."""
        self.assertIn('install -m 666 /dev/null "$RAW/$CAP_FILE"', SRC)
        self.assertIn('install', re.search(r'for cmd in ([^;]+); do', SRC).group(1))
        # The privileged-surface policy must remain unchanged.
        self.assertIn('--cap-drop ALL --cap-add NET_RAW', SRC)
        self.assertIn('--security-opt no-new-privileges:true', SRC)
        self.assertNotIn('--privileged', SRC)
        self.assertNotIn('--network host', SRC)
        self.assertIn('-Z root', SRC)


if __name__ == '__main__':
    unittest.main()
