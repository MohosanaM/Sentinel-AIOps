"""Runs the real training script on a tiny synthetic dataset."""
import json
import subprocess
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

import schema

BACKEND = Path(__file__).resolve().parent.parent
LABELS = ['normal', 'neptune', 'smurf', 'ipsweep', 'nmap',
          'guess_passwd', 'buffer_overflow']


def _fake_dataset(path, n, seed):
    rng = np.random.default_rng(seed)
    data = {c: rng.random(n) for c in schema.COLUMN_NAMES}
    data['protocol_type'] = rng.choice(['tcp', 'udp', 'icmp'], n)
    data['service'] = rng.choice(['http', 'ftp', 'private'], n)
    data['flag'] = rng.choice(['SF', 'S0', 'REJ'], n)
    data['label'] = rng.choice(LABELS, n)
    pd.DataFrame(data)[schema.COLUMN_NAMES].to_csv(path, header=False, index=False)


def test_training_pipeline_end_to_end(tmp_path):
    data_dir, out_dir = tmp_path / 'data', tmp_path / 'out'
    data_dir.mkdir()
    _fake_dataset(data_dir / 'KDDTrain+.txt', 600, 1)
    _fake_dataset(data_dir / 'KDDTest+.txt', 300, 2)

    result = subprocess.run(
        [sys.executable, 'train.py', '--data-dir', str(data_dir),
         '--out-dir', str(out_dir), '--trees', '10', '--replay-rows', '25'],
        cwd=BACKEND, capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, result.stderr

    artifact = joblib.load(out_dir / 'sentinel_model.joblib')
    assert set(artifact) >= {'model', 'metrics', 'threat_stats', 'features',
                             'sklearn_version', 'trained_at'}
    assert artifact['features'] == schema.FEATURES

    metrics = json.loads((out_dir / 'metrics.json').read_text())
    assert len(metrics['per_family']) == 5
    assert 0.0 <= metrics['accuracy_5class'] <= 1.0

    sample = pd.read_csv(out_dir / 'replay_sample.csv.gz')
    assert len(sample) == 25
    assert 'family' in sample.columns
