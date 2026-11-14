"""Integration checks: real loopback HTTP requests, NOT a cybersecurity study dataset."""
from __future__ import annotations
import json
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time
import pytest

from lab.staged_generate import run, REQUESTS, HELD_OUT_PROFILE
from src.code.early_warning import early_warning_metrics
from src.code.features import make_windows
from src.code.ingest import load_manifest, load_events
from setup.university_extract_events import extract


def _test_gateway(path):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            return
        def do_POST(self):
            start = time.time()
            n = int(self.headers['Content-Length'])
            assert 0 <= n <= 4096
            self.rfile.read(n)
            self.send_response(200)
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b'OK')
            row = {'ts': start, 'ts_end': time.time(), 'episode_id': self.headers['X-Lab-Episode'],
                   'src_host': self.client_address[0], 'dst_host': self.path.strip('/'),
                   'proto': 'tcp', 'orig_bytes': n, 'resp_bytes': 2, 'duration': time.time()-start,
                   'status': 200, 'sensor': 'application_gateway'}
            with lock:
                with path.open('a') as fp:
                    fp.write(json.dumps(row) + '\n')
    lock = threading.Lock()
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_generation_resume_and_independent_onset(tmp_path):
    root = tmp_path / 'staged'
    log = tmp_path / 'gateway.jsonl'
    server, thread = _test_gateway(log)
    url = f'http://127.0.0.1:{server.server_port}'
    try:
        status = run(root, url, 3, 3, 8415, .01, init_only=True)
        assert status['initialised']
        partial = run(root, url, 3, 3, 8415, .01, resume=True, stop_after_rounds=2)
        assert not partial['complete'] and partial['episodes'] == 4
        finished = run(root, url, 3, 3, 8415, .01, resume=True)
        assert finished['complete'] and finished['episodes'] == 24
        assert run(root, url, 3, 3, 8415, .01, resume=True)['episodes'] == 24
        manifest = load_manifest(root / 'episodes.jsonl')
        assert len(manifest) == 24
        assert {e['profile'] for e in manifest.values() if e['policy'] == 'test' and e['condition']=='incident'} == {HELD_OUT_PROFILE}
        subset = tmp_path / 'subset.jsonl'
        info = extract(root / 'episodes.jsonl', log, subset)
        assert info['events'] == 24 * REQUESTS
        events = load_events(subset, manifest)
        from src.code.pipeline import run_pipeline
        report = run_pipeline(root / 'episodes.jsonl', subset, tmp_path / 'results', causal_labels=True)
        assert report['causal_labels'] is True
        assert report['n_episodes'] == 24
        assert set(report['methods']) == {'fixed','random','strategic'}
        # True checkpoint resume on observed loopback data: completed marker deliberately
        # removed ONLY inside the test fixture to emulate interruption after epoch 1.
        import torch
        from src.code.temporal_gru_sprint import train_policy
        torch.set_num_threads(2)
        train_windows = make_windows(events,manifest,n_events=4,causal_stage_labels=True,before_milestone_only=True)
        full_windows = make_windows(events,manifest,n_events=4,causal_stage_labels=True,before_milestone_only=False)
        checkpoint_dir = tmp_path / 'gru_fixed'
        train_policy('fixed', manifest, train_windows, full_windows, checkpoint_dir, torch.device('cpu'), 1, 123, True)
        saved = torch.load(checkpoint_dir / 'latest.pt', map_location='cpu', weights_only=True)
        assert saved['epoch'] == 1 and saved['causal_labels']
        (checkpoint_dir / 'complete.json').unlink()
        train_policy('fixed', manifest, train_windows, full_windows, checkpoint_dir, torch.device('cpu'), 2, 123, True)
        saved = torch.load(checkpoint_dir / 'latest.pt', map_location='cpu', weights_only=True)
        assert saved['epoch'] == 2
        assert len((checkpoint_dir / 'epochs.jsonl').read_text().splitlines()) == 2
        windows = make_windows(events, manifest, n_events=4, causal_stage_labels=True)
        assert windows
        for w in windows:
            e = manifest[w['episode_id']]
            if e['condition']=='incident':
                assert e['start_ts'] < e['onset_ts'] < e['escalation_ts'] < e['milestone_ts'] < e['end_ts']
                assert w['label'] == int(w['window_end_ts'] >= e['onset_ts'])
            else:
                assert w['label'] == 0
        with pytest.raises(ValueError, match='configuration differs'):
            run(root, url, 3, 3, 8416, .01, resume=True)
        with pytest.raises(FileExistsError):
            run(root, url, 3, 3, 8415, .01, resume=False)
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=5)


def test_pre_onset_alarm_does_not_create_early_warning():
    manifest = {
      'i': {'episode_id': 'i','condition': 'incident','start_ts':10.,'onset_ts':14.,'milestone_ts':20.,'end_ts':23.},
      'b': {'episode_id': 'b','condition': 'benign','start_ts':1.,'milestone_ts':None,'end_ts':9.}}
    predictions = [{'episode_id':'i','window_end_ts':12.,'score':.99},
                   {'episode_id':'i','window_end_ts':16.,'score':.30},
                   {'episode_id':'b','window_end_ts':7.,'score':.10}]
    result=early_warning_metrics(predictions,manifest,threshold=.5)
    assert result['pre_onset_warning_episodes']==1
    assert result['pre_milestone_coverage']==0
    assert result['missed_incidents']==1
    assert result['conditional_mean_lead_s'] is None
    result=early_warning_metrics(predictions+[{'episode_id':'i','window_end_ts':17.,'score':.99}],manifest,threshold=.5)
    assert result['conditional_mean_lead_s']==3


def test_stage_schedule_has_fixed_count_and_no_oversize_payload():
    from lab.staged_generate import episode_schedule, TRAIN_PROFILES, BENIGN_VARIANTS, MILESTONE_INDEX
    for variant in BENIGN_VARIANTS:
        for profile in (*TRAIN_PROFILES, HELD_OUT_PROFILE):
            for idx in range(REQUESTS):
                _, delay, payload = episode_schedule(True, profile, variant, 42, idx)
                assert 0 < delay < .5 and 0 < len(payload) <= 4096
                if idx == MILESTONE_INDEX:
                    assert len(payload) == 2048
