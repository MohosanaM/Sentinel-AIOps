"""
Offline training script for Sentinel AIOps intrusion detector.
Trains a Random Forest on KDDTrain+, evaluates on KDDTest+, and saves
the serialized pipeline + metrics to backend/sentinel_model.joblib.

Run once: python train.py
"""
import glob
import os
import time

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix,
                             precision_recall_fscore_support)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

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


def _read(pattern):
    files = glob.glob(pattern)
    if not files:
        raise FileNotFoundError(f"No file matching '{pattern}' in {os.getcwd()}")
    df = pd.read_csv(files[0], names=COLUMN_NAMES)
    df['family'] = df['label'].map(ATTACK_FAMILY).fillna('R2L')
    return df


def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    print("Loading NSL-KDD datasets...")
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

    print("Training Random Forest on KDDTrain+...")
    t0 = time.time()
    model.fit(train_df[FEATURES], train_df['family'])
    train_secs = time.time() - t0

    print("Evaluating on unseen KDDTest+...")
    pred = model.predict(test_df[FEATURES])
    truth = test_df['family']

    acc = accuracy_score(truth, pred)
    b_true = (truth != 'Normal').astype(int)
    b_pred = (pd.Series(pred, index=truth.index) != 'Normal').astype(int)
    bp, br, bf, _ = precision_recall_fscore_support(
        b_true, b_pred, average='binary', zero_division=0)
    p, r, f, s = precision_recall_fscore_support(
        truth, pred, labels=FAMILIES, zero_division=0)
    cm = confusion_matrix(truth, pred, labels=FAMILIES)

    names = model.named_steps['pre'].get_feature_names_out()
    imps = model.named_steps['rf'].feature_importances_
    agg = {}
    for n, v in zip(names, imps):
        raw = n.split('__', 1)[1]
        parent = next((c for c in CATEGORICAL if raw.startswith(c + '_')), raw)
        agg[parent] = agg.get(parent, 0.0) + float(v)
    top_features = sorted(agg.items(), key=lambda kv: -kv[1])[:8]

    metrics = {
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

    attacks = train_df[train_df['label'] != 'normal']
    total, n_att = len(train_df), len(attacks)
    threat_stats = {
        'threats': attacks['label'].value_counts().to_dict(),
        'families': train_df['family'].value_counts().to_dict(),
        'summary': {
            'total_records': total,
            'normal': total - n_att,
            'attacks': n_att,
            'attack_percentage': round(100 * n_att / total, 2),
        },
    }

    artifact_path = 'sentinel_model.joblib'
    joblib.dump({
        'model': model,
        'metrics': metrics,
        'threat_stats': threat_stats,
        'features': FEATURES,
    }, artifact_path, compress=3)

    size_mb = os.path.getsize(artifact_path) / (1024 * 1024)
    print(f"Saved {artifact_path} ({size_mb:.2f} MB) in {train_secs:.1f}s")
    print(f"5-class accuracy: {acc:.4f} | Binary recall: {br:.4f}")


if __name__ == '__main__':
    main()