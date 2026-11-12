"""
Sentinel AIOps backend
----------------------
Random Forest intrusion detector trained on NSL-KDD (KDDTrain+) and evaluated
on the held-out KDDTest+ set. The API replays KDDTest+ records as a simulated
traffic feed; it does NOT sniff live network traffic.

Dataset: Tavallaee, Bagheri, Lu, Ghorbani (2009), "A Detailed Analysis of the
KDD CUP 99 Data Set", IEEE CISDA. Hosted by the University of New Brunswick.

Files expected next to this script: KDDTrain+.txt and KDDTest+.txt
Run:  python sentinel_bridge.py
"""
import glob
import os
import threading
import time
import uuid
from datetime import datetime

import numpy as np
import pandas as pd
import psutil
from flask import Flask, jsonify, request
from flask_cors import CORS
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix,
                             precision_recall_fscore_support)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

app = Flask(__name__)
# Only local front-ends (Flutter desktop/web on localhost) may call the API.
CORS(app, resources={r"/api/*": {"origins": [
    r"http://localhost:\d+", r"http://127\.0\.0\.1:\d+"]}})

# ───────────────────────── 1. SCHEMA ─────────────────────────
COLUMN_NAMES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
    'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root',
    'num_file_creations', 'num_shells', 'num_access_files',
    'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
    'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
    'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
]
CATEGORICAL = ['protocol_type', 'service', 'flag']
FEATURES = [c for c in COLUMN_NAMES if c not in ('label', 'difficulty')]
NUMERIC = [c for c in FEATURES if c not in CATEGORICAL]

# Standard NSL-KDD grouping of attack names into 4 families.
ATTACK_FAMILY = {'normal': 'Normal'}
for _name in ['back', 'land', 'neptune', 'pod', 'smurf', 'teardrop',
              'mailbomb', 'apache2', 'processtable', 'udpstorm', 'worm']:
    ATTACK_FAMILY[_name] = 'DoS'
for _name in ['ipsweep', 'nmap', 'portsweep', 'satan', 'mscan', 'saint']:
    ATTACK_FAMILY[_name] = 'Probe'
for _name in ['ftp_write', 'guess_passwd', 'imap', 'multihop', 'phf', 'spy',
              'warezclient', 'warezmaster', 'sendmail', 'named',
              'snmpgetattack', 'snmpguess', 'xlock', 'xsnoop', 'httptunnel']:
    ATTACK_FAMILY[_name] = 'R2L'
for _name in ['buffer_overflow', 'loadmodule', 'perl', 'rootkit', 'ps',
              'sqlattack', 'xterm']:
    ATTACK_FAMILY[_name] = 'U2R'

FAMILIES = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']

PLAYBOOK = {
    'DoS': {
        'severity': 'CRITICAL',
        'action': 'Rate-limit and block source at the firewall',
        'detail': 'Flood pattern (high connection count / SYN errors). '
                  'Recommended: block source IP, enable SYN cookies, '
                  'notify on-call.',
    },
    'Probe': {
        'severity': 'WARNING',
        'action': 'Block scanner and monitor for follow-up access',
        'detail': 'Reconnaissance (port/host scanning). Recommended: '
                  'temporary block, add source to watchlist, review exposed '
                  'services.',
    },
    'R2L': {
        'severity': 'CRITICAL',
        'action': 'Isolate target account and force credential reset',
        'detail': 'Remote-to-local access attempt. Recommended: block '
                  'source, lock affected account, audit login history.',
    },
    'U2R': {
        'severity': 'CRITICAL',
        'action': 'Quarantine host and start forensic capture',
        'detail': 'Possible privilege escalation. Recommended: isolate host '
                  'from network, snapshot memory/disk, escalate to security '
                  'team.',
    },
}

# ───────────────────────── 2. LOAD + TRAIN ─────────────────────────
state = {
    'ready': False,
    'error': None,
    'train_df': None,
    'test_df': None,
    'model': None,
    'metrics': None,
}


def _read(pattern):
    files = glob.glob(pattern)
    if not files:
        raise FileNotFoundError(f"No file matching '{pattern}' next to the script")
    df = pd.read_csv(files[0], names=COLUMN_NAMES)
    df['family'] = df['label'].map(ATTACK_FAMILY).fillna('R2L')  # unseen names
    return df


def load_and_train():
    try:
        os.chdir(os.path.dirname(os.path.abspath(__file__)))
        print("Loading NSL-KDD ...")
        train_df, test_df = _read('KDDTrain*'), _read('KDDTest*')

        pre = ColumnTransformer([
            ('cat', OneHotEncoder(handle_unknown='ignore'), CATEGORICAL),
            ('num', 'passthrough', NUMERIC),
        ])
        model = Pipeline([
            ('pre', pre),
            ('rf', RandomForestClassifier(
                n_estimators=100, n_jobs=-1, random_state=42,
                class_weight='balanced_subsample')),
        ])

        print("Training Random Forest on KDDTrain+ ...")
        t0 = time.time()
        model.fit(train_df[FEATURES], train_df['family'])
        train_secs = time.time() - t0

        print("Evaluating on KDDTest+ (never seen during training) ...")
        pred = model.predict(test_df[FEATURES])
        truth = test_df['family']

        acc = accuracy_score(truth, pred)
        # Binary view: attack vs normal
        b_true = (truth != 'Normal').astype(int)
        b_pred = (pd.Series(pred, index=truth.index) != 'Normal').astype(int)
        bp, br, bf, _ = precision_recall_fscore_support(
            b_true, b_pred, average='binary', zero_division=0)
        # Per-family view
        p, r, f, s = precision_recall_fscore_support(
            truth, pred, labels=FAMILIES, zero_division=0)
        cm = confusion_matrix(truth, pred, labels=FAMILIES)

        # Top features (aggregate one-hot columns back to their parent field)
        names = model.named_steps['pre'].get_feature_names_out()
        imps = model.named_steps['rf'].feature_importances_
        agg = {}
        for n, v in zip(names, imps):
            raw = n.split('__', 1)[1]
            parent = next((c for c in CATEGORICAL if raw.startswith(c + '_')), raw)
            agg[parent] = agg.get(parent, 0.0) + float(v)
        top_features = sorted(agg.items(), key=lambda kv: -kv[1])[:8]

        state['metrics'] = {
            'model': 'RandomForest (100 trees, one-hot + 41 features)',
            'train_records': int(len(train_df)),
            'test_records': int(len(test_df)),
            'train_seconds': round(train_secs, 1),
            'accuracy_5class': round(float(acc), 4),
            'binary': {
                'precision': round(float(bp), 4),
                'recall': round(float(br), 4),
                'f1': round(float(bf), 4),
            },
            'per_family': [
                {'family': fam, 'precision': round(float(p[i]), 4),
                 'recall': round(float(r[i]), 4), 'f1': round(float(f[i]), 4),
                 'support': int(s[i])}
                for i, fam in enumerate(FAMILIES)
            ],
            'confusion_matrix': {'labels': FAMILIES, 'matrix': cm.tolist()},
            'top_features': [{'feature': k, 'importance': round(v, 4)}
                             for k, v in top_features],
            'note': 'Evaluated on KDDTest+, which contains attack types '
                    'absent from training, so scores are lower than on '
                    'random splits. R2L/U2R are rare in training data.',
        }
        state.update(train_df=train_df, test_df=test_df, model=model, ready=True)
        print(f"READY. 5-class accuracy {acc:.3f} | binary recall {br:.3f}")
    except Exception as e:  # keep the server up so /api/health can report it
        state['error'] = str(e)
        print(f"ERROR: {e}")


# ───────────────────────── 3. INCIDENT STATE ─────────────────────────
lock = threading.Lock()
incidents = {}          # id -> incident dict
blocklist = {}          # ip -> {'since': time, 'incident': id, 'action': str}
session = {'scanned': 0, 'flagged': 0, 'true_pos': 0, 'false_pos': 0}
psutil.cpu_percent(interval=None)  # prime so later calls don't block


def _fake_ip():
    rng = np.random.default_rng()
    return f"192.168.1.{int(rng.integers(10, 250))}"


def _now():
    return datetime.now().strftime("%H:%M:%S")


# ───────────────────────── 4. ROUTES ─────────────────────────
@app.route('/api/health')
def health():
    return jsonify({'ready': state['ready'], 'error': state['error']})


def _system_status():
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
        return jsonify({'error': state['error'] or 'Model still training'}), 503

    batch = state['test_df'].sample(30)           # simulated traffic window
    proba = state['model'].predict_proba(batch[FEATURES])
    classes = list(state['model'].classes_)
    preds = [classes[i] for i in proba.argmax(axis=1)]
    confs = proba.max(axis=1)

    found = []
    with lock:
        for (idx, row), pred, conf in zip(batch.iterrows(), preds, confs):
            session['scanned'] += 1
            if pred == 'Normal':
                continue
            session['flagged'] += 1
            truth_family = row['family']
            correct = truth_family != 'Normal'
            session['true_pos' if correct else 'false_pos'] += 1

            pb = PLAYBOOK[pred]
            sev = pb['severity']
            if conf < 0.6 and sev == 'CRITICAL':
                sev = 'WARNING'                   # low confidence -> downgrade
            inc = {
                'id': uuid.uuid4().hex[:8],
                'severity': sev,
                'family': pred,
                'confidence': round(float(conf), 3),
                'source_ip': _fake_ip(),          # simulated; dataset has no IPs
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
            found.append(inc)

    found.sort(key=lambda i: -i['confidence'])
    return jsonify({
        'mode': 'replay',
        'system': _system_status(),
        'alerts': found[:6],
        'session': dict(session),
        'blocked_count': len(blocklist),
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
        return jsonify({'blocked': [{'ip': ip, **v} for ip, v in blocklist.items()]})


@app.route('/api/metrics')
def get_metrics():
    if not state['ready']:
        return jsonify({'error': state['error'] or 'Model still training'}), 503
    return jsonify(state['metrics'])


@app.route('/api/threat-stats')
def get_threat_stats():
    if not state['ready']:
        return jsonify({'error': state['error'] or 'Dataset not loaded'}), 503
    df = state['train_df']
    attacks = df[df['label'] != 'normal']
    total, n_att = len(df), len(attacks)
    return jsonify({
        'threats': attacks['label'].value_counts().to_dict(),
        'families': df['family'].value_counts().to_dict(),
        'summary': {
            'total_records': total,
            'normal': total - n_att,
            'attacks': n_att,
            'attack_percentage': round(100 * n_att / total, 2),
        },
    })


# ───────────────────────── 5. RUN ─────────────────────────
if __name__ == "__main__":
    threading.Thread(target=load_and_train, daemon=True).start()
    print("Starting Sentinel AIOps server on http://127.0.0.1:5000")
    app.run(host=os.environ.get('SENTINEL_HOST', '127.0.0.1'),
            port=5000, debug=False, threaded=True)
    