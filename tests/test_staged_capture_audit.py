"""Unit test PCAP structural validation; does not require network privileges."""
import struct
from pathlib import Path
import unittest
from setup.staged_capture_audit import inspect_pcap


class TestPcapAudit(unittest.TestCase):
    def test_zero_records_fails(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as td:
            p = Path(td) / 'header_only.pcap'
            p.write_bytes(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 113))
            r = inspect_pcap(p)
            self.assertTrue(r['complete'])
            self.assertEqual(r['packets'], 0)
            self.assertIn('zero packet', r['issue'])

    def test_records_counted(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as td:
            p = Path(td) / 'two.pcap'
            data = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 113))
            for payload in (b'aaa', b'four'):
                data.extend(struct.pack('<IIII', 123, 0, len(payload), len(payload)))
                data.extend(payload)
            p.write_bytes(bytes(data))
            r = inspect_pcap(p)
            self.assertTrue(r['complete'])
            self.assertEqual(r['packets'], 2)
            self.assertEqual(r['payload_bytes'], 7)

    def test_truncated_record_rejected(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as td:
            p = Path(td) / 'truncated.pcap'
            p.write_bytes(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 113) + struct.pack('<IIII', 123, 0, 10, 10) + b'xxx')
            r = inspect_pcap(p)
            self.assertFalse(r['complete'])
            self.assertIn('Truncated', r['issue'])

    def test_invalid_header_rejected(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as td:
            p = Path(td) / 'bad.pcap'
            p.write_bytes(b'xxx' * 30)
            self.assertIn('Unsupported', inspect_pcap(p)['issue'])


if __name__ == '__main__':
    unittest.main()
