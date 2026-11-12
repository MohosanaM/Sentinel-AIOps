"""
Sentinel AIOps backend (Inference Server)
---------------------------------------
Loads pre-trained model artifact (sentinel_model.joblib) and serves the API.
Replays KDDTest+ records as a simulated traffic feed.
"""
import os
import threading
import time
import uuid
from datetime import datetime
from url_analyzer import URLThreatEngine
url_engine = URLThreatEngine()
import joblib
import numpy as np
import psutil
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": [
    r"http://localhost:\d+", r"http://127\.0\.0\.1:\d+", r"https://*"]}})

# Global application state
state = {
    'ready': False,
    'error': None,
    'model': None,
    'metrics': None,
    'threat_stats': None,
    'test_df': None,
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


def load_artifact():
    try:
        os.chdir(os.path.dirname(os.path.abspath(__file__)))
        artifact_path = 'sentinel_model.joblib'
        if not os.path.exists(artifact_path):
            raise FileNotFoundError(
                f"'{artifact_path}' not found. Run 'python train.py' first.")

        print(f"Loading pre-trained model artifact from {artifact_path}...")
        data = joblib.load(artifact_path)
        
        # Also need KDDTest+ for live traffic replay
        import glob
        import pandas as pd
        test_files = glob.glob('KDDTest*')
        if not test_files:
            raise FileNotFoundError("No KDDTest* file found next to bridge.")
        
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

        test_df = pd.read_csv(test_files[0], names=COLUMN_NAMES)
        test_df['family'] = test_df['label'].map(ATTACK_FAMILY).fillna('R2L')

        state['model'] = data['model']
        state['metrics'] = data['metrics']
        state['threat_stats'] = data['threat_stats']
        state['features'] = data['features']
        state['test_df'] = test_df
        state['ready'] = True
        print("Sentinel Bridge ready to serve predictions.")
    except Exception as e:
        state['error'] = str(e)
        print(f"ERROR loading model: {e}")


lock = threading.Lock()
incidents = {}
blocklist = {}
session = {'scanned': 0, 'flagged': 0, 'true_pos': 0, 'false_pos': 0}
psutil.cpu_percent(interval=None)


def _fake_ip():
    rng = np.random.default_rng()
    return f"192.168.1.{int(rng.integers(10, 250))}"


def _now():
    return datetime.now().strftime("%H:%M:%S")


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
    return {'level': level, 'cpu': cpu, 'ram': ram, 'message': msg, 'time': _now()}


@app.route('/api/alerts')
def get_alerts():
    if not state['ready']:
        return jsonify({'error': state['error'] or 'Model still loading'}), 503

    batch = state['test_df'].sample(30)
    proba = state['model'].predict_proba(batch[state['features']])
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

            pb = PLAYBOOK.get(pred, PLAYBOOK['Probe'])
            sev = pb['severity']
            if conf < 0.6 and sev == 'CRITICAL':
                sev = 'WARNING'
            inc = {
                'id': uuid.uuid4().hex[:8],
                'severity': sev,
                'family': pred,
                'confidence': round(float(conf), 3),
                'source_ip': _fake_ip(),
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
    with lock:
        inc = incidents.get(incident_id)
        if inc is None:
            return jsonify({'error': 'Unknown incident'}), 404
        if inc['status'] != 'OPEN':
            return jsonify(inc)
        inc['status'] = 'MITIGATED'
        blocklist[inc['source_ip']] = {
            'since': _now(), 'incident': incident_id, 'action': inc['recommended_action']}
        return jsonify({'incident': inc, 'blocked_count': len(blocklist)})


@app.route('/api/metrics')
def get_metrics():
    if not state['ready']:
        return jsonify({'error': state['error'] or 'Model still loading'}), 503
    return jsonify(state['metrics'])


@app.route('/api/threat-stats')
def get_threat_stats():
    if not state['ready']:
        return jsonify({'error': state['error'] or 'Dataset not loaded'}), 503
    return jsonify(state['threat_stats'])

url_engine = URLThreatEngine()

@app.route('/api/scan-url', methods=['POST'])
def scan_url():
    data = request.get_json() or {}
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    result = url_engine.evaluate(url)
    return jsonify(result)

if __name__ == "__main__":
    load_artifact()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)