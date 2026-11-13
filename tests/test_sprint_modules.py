"""Fast tests; use fixtures ONLY for unit testing (never research evidence)."""
import struct
import tempfile
import unittest
from pathlib import Path
import numpy as np

from setup.sprint_audit import inspect_pcap
from src.code.temporal_gru_sprint import GRUDetector,examples
from src.code.features import FEATURE_COLUMNS

class SprintTests(unittest.TestCase):
    def test_pcap_parser_classic_endianness(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'sample.pcap'
            with p.open('wb') as f:
                f.write(bytes.fromhex('d4c3b2a1'))
                f.write(struct.pack('<HHIIII',2,4,0,0,65535,1))
                for payload in (b'a'*80,b'b'*160):
                    f.write(struct.pack('<IIII',1,2,len(payload),len(payload)))
                    f.write(payload)
            report=inspect_pcap(p)
            self.assertTrue(report['supported'])
            self.assertEqual(report['frames'],2)
            self.assertEqual(report['frames_over_100_bytes'],1)
            self.assertEqual(report['malformed_frames'],0)
    def test_causal_window_sequence_and_model_shape(self):
        import torch
        rows=[]
        for i in range(3):
            r={c:float(i+1) for c in FEATURE_COLUMNS}
            r.update(episode_id='case1',window_end_ts=float(i),label=1)
            rows.append(r)
        items=examples(rows,np.zeros(len(FEATURE_COLUMNS),dtype=np.float32),np.ones(len(FEATURE_COLUMNS),dtype=np.float32))
        self.assertEqual([i['x'].shape[0] for i in items],[1,2,3])
        from src.code.temporal_gru_sprint import batches
        xx,lengths,y,_=next(batches(items,8,1,False))
        pred=GRUDetector(len(FEATURE_COLUMNS))(xx,lengths)
        self.assertEqual(list(pred.shape),[3])
        self.assertTrue(torch.isfinite(pred).all())
if __name__=='__main__':unittest.main()
