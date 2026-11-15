"""
Sentinel AIOps backend (inference server)
-----------------------------------------
Loads the pre-trained model (sentinel_model.joblib, built by train.py) and
serves the API. Traffic is REPLAYED from NSL-KDD test records; nothing here
sniffs a live network.

Local:       python sentinel_bridge.py
Production:  gunicorn -w 1 --threads 4 -b 0.0.0.0:$PORT sentinel_bridge:app
             (one worker: incidents and the blocklist live in memory)

Environment variables
  PORT              listen port (default 5000)
  SENTINEL_HOST     bind address for `python sentinel_bridge.py` (default 127.0.0.1)
  ALLOWED_ORIGINS   comma-separated exact front-end origins, e.g.
                    https://yourname.github.io  (localhost is always allowed)
  TRUST_PROXY       set to 1 when behind a reverse proxy (Render, Fly, Railway)
"""
import logging
import os
import threading
import uuid
from collections import OrderedDict
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import psutil
import sklearn
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

from schema import load_nsl_kdd
from url_analyzer import URLThreatEngine

# Define frontend directory and initialize Flask ONCE with static folder support
FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend', 'build', 'web'))
app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path='')

@app.route('/')
def serve_frontend():
    return send_from_directory(FRONTEND_DIR, 'index.html')

HERE = Path(__file__).resolve().parent
MAX_INCIDENTS = 500        # oldest incidents are dropped beyond this
MAX_URL_LEN = 2048

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('sentinel')

if os.environ.get('TRUST_PROXY') == '1':
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

# CORS: exact origins only. The localhost patterns end in $ so that
# "http://localhost:5000.evil.com" cannot match.
_extra = [o.strip() for o in os.environ.get('ALLOWED_ORIGINS', '').split(',')
          if o.strip()]
CORS(app, resources={r"/api/*": {"origins": [
    r"http://localhost:\d+$", r"http://127\.0\.0\.1:\d+$", *_extra]}})

limiter = Limiter(get_remote_address, app=app, storage_uri='memory://')

url_engine = URLThreatEngine()

state = {
    'ready': False,
    'error': None,
    'warning': None,
    'model': None,
    'metrics': None,
    'threat_stats': None,
    'replay_df': None,
    'features': None,
}

PLAYBOOK = {
    'DoS': {
        'severity': 'CRITICAL',
        'action': 'Rate-limit and block source at the firewall',
        'detail': 'Flood pattern (high connection count / SYN errors). '
                  'Recommended: block source IP, enable SYN cookies.',
    },
    'Probe': {
        'severity': 'WARNING',
        'action': 'Block scanner and monitor for follow-up access',
        'detail': 'Reconnaissance (port/host scanning). Recommended: '
                  'temporary block, add source to watchlist.',
    },
    'R2L': {
        'severity': 'CRITICAL',
        'action': 'Isolate target account and force credential reset',
        'detail': 'Remote-to-local access attempt. Recommended: block '
                  'source, lock affected account.',
    },
    'U2R': {
        'severity': 'CRITICAL',
        'action': 'Quarantine host and start forensic capture',
        'detail': 'Possible privilege escalation. Recommended: isolate host '
                  'from network, snapshot memory/disk.',
    },
}


def _load_replay():
    """Small committed sample first; full KDDTest+ if it is present."""
    sample = HERE / 'replay_sample.csv.gz'
    if sample.exists():
        return pd.read_csv(sample)
    full = sorted(HERE.glob('KDDTest*'))
    if full:
        return load_nsl_kdd(full[0])
    raise FileNotFoundError(
        "No replay data: expected replay_sample.csv.gz (made by train.py) "
        "or a KDDTest* file next to this script.")


def load_artifact():
    try:
        path = HERE / 'sentinel_model.joblib'
        if not path.exists():
            raise FileNotFoundError(f"'{path.name}' not found. Run train.py first.")
        log.info("Loading model artifact %s", path.name)
        data = joblib.load(path)   # only load files you trained yourself

        trained_with = data.get('sklearn_version')
        if trained_with and trained_with != sklearn.__version__:
            state['warning'] = (f"Model trained with scikit-learn {trained_with}, "
                                f"running {sklearn.__version__}. Retrain if "
                                f"predictions look wrong.")
            log.warning(state['warning'])

        state.update(model=data['model'], metrics=data['metrics'],
                     threat_stats=data['threat_stats'],
                     features=data['features'], replay_df=_load_replay(),
                     ready=True)
        log.info("Ready. Replay pool: %d records", len(state['replay_df']))
    except Exception as e:
        state['error'] = str(e)
        log.error("Failed to load model: %s", e)


lock = threading.Lock()
incidents = OrderedDict()   # id -> incident dict, capped at MAX_INCIDENTS
blocklist = {}              # ip -> {'since', 'incident', 'action'}
session = {'scanned': 0, 'flagged': 0, 'true_pos': 0, 'false_pos': 0}
psutil.cpu_percent(interval=None)   # prime so later calls do not block


def _fake_ip():
    rng = np.random.default_rng()
    return f"192.168.1.{int(rng.integers(10, 250))}"


def _now():
    return datetime.now().strftime("%H:%M:%S")


@app.route('/api/health')
def health():
    return jsonify({'ready': state['ready'], 'error': state['error'],
                    'warning': state['warning']})


def _system_status():
    """Stats of the machine running this server, not of a monitored network."""
    cpu = psutil.cpu_percent(interval=None)
    ram = psutil.virtual_memory().percent
    level = 'CRITICAL' if cpu > 90 else 'WARNING' if cpu > 80 else 'INFO'
    msg = {
        'INFO': 'System performance within normal range',
        'WARNING': 'High CPU load - monitor closely',
        'CRITICAL': 'Sustained CPU saturation - investigate running processes',
    }[level]
    return {'level': level, 'cpu': cpu, 'ram': ram, 'message': msg,
            'time': _now()}


@app.route('/api/alerts')
def get_alerts():
    if not state['ready']:
        return jsonify({'error': state['error'] or 'Model still loading'}), 503

    pool = state['replay_df']
    batch = pool.sample(min(30, len(pool)))
    proba = state['model'].predict_proba(batch[state['features']])
    classes = list(state['model'].classes_)
    preds = [classes[i] for i in proba.argmax(axis=1)]
    confs = proba.max(axis=1)

    found = []
    with lock:
        for (_, row), pred, conf in zip(batch.iterrows(), preds, confs):
            session['scanned'] += 1
            if pred == 'Normal':
                continue
            session['flagged'] += 1
            truth_family = row['family']
            session['true_pos' if truth_family != 'Normal' else 'false_pos'] += 1

            pb = PLAYBOOK[pred]
            sev = pb['severity']
            if conf < 0.6 and sev == 'CRITICAL':
                sev = 'WARNING'            # low confidence -> downgrade
            inc = {
                'id': uuid.uuid4().hex[:8],
                'severity': sev,
                'family': pred,
                'confidence': round(float(conf), 3),
                'source_ip': _fake_ip(),   # simulated; dataset has no IPs
                'time': _now(),
                'status': 'OPEN',
                'recommended_action': pb['action'],
                'detail': pb['detail'],
                'evidence': {
                    'protocol': row['protocol_type'],
                    'service': row['service'],
                    'flag': row['flag'],
                    'src_bytes': int(row['src_bytes']),
                    'dst_bytes': int(row['dst_bytes']),
                    'connections_2s': int(row['count']),
                    'serror_rate': float(row['serror_rate']),
                },
                # Replay ground truth, shown so the demo is transparent
                'ground_truth': row['label'],
                'ground_truth_family': truth_family,
                'prediction_correct': bool(truth_family == pred),
            }
            incidents[inc['id']] = inc
            while len(incidents) > MAX_INCIDENTS:
                incidents.popitem(last=False)
            found.append(inc)

        blocked = len(blocklist)
        sess = dict(session)

    found.sort(key=lambda i: -i['confidence'])
    return jsonify({
        'mode': 'replay',
        'system': _system_status(),
        'alerts': found[:6],
        'session': sess,
        'blocked_count': blocked,
    })


@app.route('/api/incidents/<incident_id>/respond', methods=['POST'])
def respond(incident_id):
    """Simulated SOAR action: records the response and updates a blocklist."""
    with lock:
        inc = incidents.get(incident_id)
        if inc is None:
            return jsonify({'error': 'Unknown incident'}), 404
        if inc['status'] != 'OPEN':
            return jsonify(inc)
        inc['status'] = 'MITIGATED'
        inc['mitigated_at'] = _now()
        blocklist[inc['source_ip']] = {
            'since': _now(), 'incident': incident_id,
            'action': inc['recommended_action']}
        return jsonify({'incident': inc, 'blocked_count': len(blocklist)})


@app.route('/api/blocklist')
def get_blocklist():
    with lock:
        return jsonify({'blocked': [{'ip': ip, **v}
                                    for ip, v in blocklist.items()]})


@app.route('/api/metrics')
def get_metrics():
    if not state['ready']:
        return jsonify({'error': state['error'] or 'Model still loading'}), 503
    return jsonify(state['metrics'])


@app.route('/api/threat-stats')
def get_threat_stats():
    if not state['ready']:
        return jsonify({'error': state['error'] or 'Model still loading'}), 503
    return jsonify(state['threat_stats'])


@app.route('/api/scan-url', methods=['POST'])
@limiter.limit('20 per minute')
def scan_url():
    data = request.get_json(silent=True)
    url = data.get('url') if isinstance(data, dict) else None
    if not isinstance(url, str) or not url.strip():
        return jsonify({'error': 'Send JSON like {"url": "https://..."}'}), 400
    url = url.strip()
    if len(url) > MAX_URL_LEN:
        return jsonify({'error': f'URL longer than {MAX_URL_LEN} characters'}), 400
    try:
        return jsonify(url_engine.evaluate(url))
    except ValueError:
        return jsonify({'error': 'That does not look like a valid URL'}), 400
    except Exception:
        log.exception("URL scan failed")
        return jsonify({'error': 'Scan failed'}), 500


# Load at import time so gunicorn (which never runs the block below) works.
load_artifact()

if __name__ == "__main__":
    app.run(host=os.environ.get('SENTINEL_HOST', '127.0.0.1'),
            port=int(os.environ.get('PORT', 5000)),
            debug=False, threaded=True)
