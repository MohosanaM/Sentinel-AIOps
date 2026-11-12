"""
Offline training script for the Sentinel AIOps intrusion detector.

Trains a Random Forest on NSL-KDD KDDTrain+, evaluates it on the held-out
KDDTest+ set, and writes:
  - sentinel_model.joblib   serialized pipeline + metrics + stats (loaded by the API)
  - metrics.json            the same metrics, human-readable, for the README
  - replay_sample.csv.gz    small KDDTest+ sample so the demo API can replay
                            traffic without the full dataset (optional)

Usage (from the backend/ folder, with KDDTrain+.txt and KDDTest+.txt next to it):
    python train.py
    python train.py --trees 60 --max-depth 25     # smaller model file
"""
import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_recall_fscore_support)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

from schema import (CATEGORICAL, COLUMN_NAMES, FAMILIES, FEATURES, NUMERIC,
                    load_nsl_kdd)

HERE = Path(__file__).resolve().parent
WARN_SIZE_MB = 50          # GitHub rejects single files over 100 MB


def find_file(data_dir, pattern):
    files = sorted(data_dir.glob(pattern))
    if not files:
        raise FileNotFoundError(f"No file matching '{pattern}' in {data_dir}")
    return files[0]


def build_model(trees, max_depth, seed):
    pre = ColumnTransformer([
        ('cat', OneHotEncoder(handle_unknown='ignore'), CATEGORICAL),
        ('num', 'passthrough', NUMERIC),
    ])
    return Pipeline([
        ('pre', pre),
        ('rf', RandomForestClassifier(
            n_estimators=trees, max_depth=max_depth, n_jobs=-1,
            random_state=seed, class_weight='balanced_subsample')),
    ])


def top_features(model, n=8):
    """Feature importances, with one-hot columns summed back to their field."""
    names = model.named_steps['pre'].get_feature_names_out()
    imps = model.named_steps['rf'].feature_importances_
    agg = {}
    for name, value in zip(names, imps):
        raw = name.split('__', 1)[1]
        parent = next((c for c in CATEGORICAL if raw.startswith(c + '_')), raw)
        agg[parent] = agg.get(parent, 0.0) + float(value)
    return sorted(agg.items(), key=lambda kv: -kv[1])[:n]


def evaluate(model, test_df, train_df, train_secs, args):
    pred = model.predict(test_df[FEATURES])
    truth = test_df['family']

    acc = accuracy_score(truth, pred)
    macro_f1 = f1_score(truth, pred, labels=FAMILIES, average='macro',
                        zero_division=0)

    # Binary view: attack vs normal
    b_true = (truth != 'Normal').astype(int)
    b_pred = (pd.Series(pred, index=truth.index) != 'Normal').astype(int)
    bp, br, bf, _ = precision_recall_fscore_support(
        b_true, b_pred, average='binary', zero_division=0)

    # Per-family view
    p, r, f, s = precision_recall_fscore_support(
        truth, pred, labels=FAMILIES, zero_division=0)
    cm = confusion_matrix(truth, pred, labels=FAMILIES)

    return {
        'model': (f'RandomForest ({args.trees} trees, '
                  f'max_depth={args.max_depth}, one-hot + 41 features)'),
        'train_records': int(len(train_df)),
        'test_records': int(len(test_df)),
        'train_seconds': round(train_secs, 1),
        'accuracy_5class': round(float(acc), 4),
        'macro_f1_5class': round(float(macro_f1), 4),
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
                         for k, v in top_features(model)],
        'note': 'Evaluated on KDDTest+, which contains attack types absent '
                'from training, so scores are lower than on random splits. '
                'R2L/U2R are rare in training data and have low recall.',
    }


def threat_stats_for(train_df):
    attacks = train_df[train_df['label'] != 'normal']
    total, n_att = len(train_df), len(attacks)
    return {
        'threats': attacks['label'].value_counts().to_dict(),
        'families': train_df['family'].value_counts().to_dict(),
        'summary': {
            'total_records': total,
            'normal': total - n_att,
            'attacks': n_att,
            'attack_percentage': round(100 * n_att / total, 2),
        },
    }


def parse_args():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--data-dir', type=Path, default=HERE,
                    help='folder containing KDDTrain+.txt and KDDTest+.txt')
    ap.add_argument('--out-dir', type=Path, default=HERE,
                    help='where to write the model and metrics')
    ap.add_argument('--trees', type=int, default=100)
    ap.add_argument('--max-depth', type=int, default=None,
                    help='limit tree depth to shrink the model file')
    ap.add_argument('--seed', type=int, default=42)
    ap.add_argument('--replay-rows', type=int, default=2000,
                    help='rows of KDDTest+ to save for demo replay (0 = none)')
    return ap.parse_args()


def main():
    args = parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    print("Loading NSL-KDD ...")
    train_df = load_nsl_kdd(find_file(args.data_dir, 'KDDTrain*'))
    test_df = load_nsl_kdd(find_file(args.data_dir, 'KDDTest*'))

    model = build_model(args.trees, args.max_depth, args.seed)

    print("Training on KDDTrain+ ...")
    t0 = time.time()
    model.fit(train_df[FEATURES], train_df['family'])
    train_secs = time.time() - t0

    print("Evaluating on unseen KDDTest+ ...")
    metrics = evaluate(model, test_df, train_df, train_secs, args)

    artifact = args.out_dir / 'sentinel_model.joblib'
    joblib.dump({
        'model': model,
        'metrics': metrics,
        'threat_stats': threat_stats_for(train_df),
        'features': FEATURES,
        # A joblib file only loads reliably on the same scikit-learn version.
        'sklearn_version': sklearn.__version__,
        'trained_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
    }, artifact, compress=3)

    with open(args.out_dir / 'metrics.json', 'w', encoding='utf-8') as fh:
        json.dump(metrics, fh, indent=2)

    if args.replay_rows > 0:
        sample = test_df[COLUMN_NAMES + ['family']].sample(
            min(args.replay_rows, len(test_df)), random_state=args.seed)
        sample.to_csv(args.out_dir / 'replay_sample.csv.gz', index=False)

    size_mb = artifact.stat().st_size / (1024 * 1024)
    print(f"Saved {artifact.name} ({size_mb:.1f} MB), metrics.json"
          f"{', replay_sample.csv.gz' if args.replay_rows > 0 else ''}")
    if size_mb > WARN_SIZE_MB:
        print(f"WARNING: model is over {WARN_SIZE_MB} MB. Retrain with "
              f"--trees 60 --max-depth 25 before committing to GitHub.")
    print(f"5-class accuracy {metrics['accuracy_5class']:.4f} | "
          f"macro-F1 {metrics['macro_f1_5class']:.4f} | "
          f"binary recall {metrics['binary']['recall']:.4f}")


if __name__ == '__main__':
    main()