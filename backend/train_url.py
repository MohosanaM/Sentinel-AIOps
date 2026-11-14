"""
Train and honestly evaluate a phishing-URL classifier on PhiUSIIL.

Dataset: Prasad & Chandra (2024), PhiUSIIL Phishing URL Dataset, UCI Machine
Learning Repository, licence CC BY 4.0. Label 1 = legitimate, 0 = phishing in
the file; this script flips it so that 1 = phishing (the positive class).

Features (--features):
  host  (default) hostname only, leading "www." removed. Path, query and
        scheme are ignored because in this dataset they are artifacts.
  url   whole-URL lexical features. Kept for comparison: it scores well but
        flags ordinary links that have a path (YouTube, GitHub) as phishing.
Both come from url_analyzer.py, so training and serving cannot drift apart.

Two evaluations are reported:
  random split   optimistic: the same website can appear in train and test
  grouped split  harder: every website (domain) is entirely in train OR test
The grouped number is the one to quote.

Writes (into --out-dir, default backend/):
  url_model.joblib                    the model, host mode only (gitignored)
  url_metrics_hostonly.json / url_metrics_wholeurl.json
                                      metrics for the README (commit these)

Run from the project root:
    python backend/train_url.py
"""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix,
                             precision_recall_fscore_support, roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit, train_test_split

from url_analyzer import extract_host_features, extract_url_features

HERE = Path(__file__).resolve().parent
WARN_SIZE_MB = 50
SECOND_LEVEL = {'co', 'com', 'org', 'net', 'gov', 'edu', 'ac'}

SANITY_URLS = [
    ('legit', 'https://www.youtube.com/watch?v=b_HE9-17rIE&t=135s'),
    ('legit', 'https://github.com/pallets/flask/issues/1234'),
    ('legit', 'https://en.wikipedia.org/wiki/Random_forest'),
    ('legit', 'https://www.google.com/search?q=weather+osaka'),
    ('legit', 'https://www.zju.edu.cn/'),
    ('legit', 'https://www.amazon.com/dp/B08N5WRWNW'),
    ('legit', 'https://www.bbc.co.uk/news/world'),
    ('legit', 'https://www.microsoft.com/en-us/windows'),
    ('phish-style', 'http://192.168.1.5/login@secure-update.tk/verify'),
    ('phish-style', 'http://paypal-secure-login.verify-account.xyz/signin'),
    ('phish-style', 'http://secure-bank-update.top/account/confirm'),
]


def group_key(url):
    """Approximate registrable domain, so one site never spans train and test."""
    host = (urlparse(url if '://' in url else 'http://' + url).hostname or '').lower()
    parts = host.split('.')
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in SECOND_LEVEL:
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:]) if len(parts) >= 2 else host


def load_data(path):
    df = pd.read_csv(path, usecols=['URL', 'label'])
    n0 = len(df)
    df = df.dropna()
    df['URL'] = df['URL'].astype(str).str.strip()
    df['key'] = df['URL'].str.lower()
    # Drop URLs that appear with conflicting labels, then exact duplicates.
    conflict = df.groupby('key')['label'].nunique()
    df = df[~df['key'].isin(conflict[conflict > 1].index)]
    df = df.drop_duplicates('key')
    df['y'] = (df['label'] == 0).astype(int)        # 1 = phishing
    print(f"Loaded {n0} rows, kept {len(df)} after cleaning")
    return df.reset_index(drop=True)


def bias_report(df):
    """How different are the two classes in ways unrelated to being phishing?"""
    parsed = [urlparse(u) for u in df['URL']]
    has_extra = np.array([bool((p.path not in ('', '/')) or p.query) for p in parsed])
    https = np.array([p.scheme == 'https' for p in parsed])
    y = df['y'].to_numpy()
    rep_ = {
        'legitimate_with_path_or_query': round(float(has_extra[y == 0].mean()), 4),
        'phishing_with_path_or_query': round(float(has_extra[y == 1].mean()), 4),
        'legitimate_https': round(float(https[y == 0].mean()), 4),
        'phishing_https': round(float(https[y == 1].mean()), 4),
    }
    print("Dataset check (share of URLs):")
    for k, v in rep_.items():
        print(f"  {k}: {v}")
    return rep_


def build_matrix(df, extract):
    rows, ys, groups, urls = [], [], [], []
    skipped = 0
    for url, y in zip(df['URL'], df['y']):
        try:
            feats = extract(url)
            g = group_key(url)
        except ValueError:
            skipped += 1
            continue
        rows.append(feats)
        ys.append(y)
        groups.append(g)
        urls.append(url)
    X = pd.DataFrame(rows)
    print(f"Features built for {len(X)} URLs ({skipped} skipped as unparseable)")
    return X, np.array(ys), np.array(groups), urls


def make_model(trees, max_depth, seed):
    return RandomForestClassifier(
        n_estimators=trees, max_depth=max_depth, min_samples_leaf=5,
        n_jobs=-1, random_state=seed, class_weight='balanced')


def score(model, X_te, y_te):
    pred = model.predict(X_te)
    proba = model.predict_proba(X_te)[:, 1]
    p, r, f, _ = precision_recall_fscore_support(
        y_te, pred, average='binary', zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_te, pred, labels=[0, 1]).ravel()
    return {
        'test_urls': int(len(y_te)),
        'accuracy': round(float(accuracy_score(y_te, pred)), 4),
        'phishing_precision': round(float(p), 4),
        'phishing_recall': round(float(r), 4),
        'phishing_f1': round(float(f), 4),
        'roc_auc': round(float(roc_auc_score(y_te, proba)), 4),
        'false_positive_rate': round(float(fp / max(fp + tn, 1)), 4),
        'confusion': {'tn': int(tn), 'fp': int(fp), 'fn': int(fn), 'tp': int(tp)},
    }


def parse_args():
    ap = argparse.ArgumentParser(description='Train the URL classifier')
    ap.add_argument('--data', type=Path,
                    default=HERE / 'data' / 'PhiUSIIL_Phishing_URL_Dataset.csv')
    ap.add_argument('--out-dir', type=Path, default=HERE)
    ap.add_argument('--features', choices=['host', 'url'], default='host')
    ap.add_argument('--trees', type=int, default=100)
    ap.add_argument('--max-depth', type=int, default=18)
    ap.add_argument('--seed', type=int, default=42)
    return ap.parse_args()


def main():
    args = parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    if not args.data.exists():
        raise FileNotFoundError(f"Dataset not found: {args.data}")

    extract = extract_host_features if args.features == 'host' else extract_url_features
    df = load_data(args.data)
    bias = bias_report(df)
    X, y, groups, _ = build_matrix(df, extract)

    # 1) Random split (optimistic)
    idx = np.arange(len(X))
    tr, te = train_test_split(idx, test_size=0.2, random_state=args.seed, stratify=y)
    m_rand = make_model(args.trees, args.max_depth, args.seed).fit(X.iloc[tr], y[tr])
    random_res = score(m_rand, X.iloc[te], y[te])

    # 2) Grouped split (the honest one): no domain appears on both sides
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=args.seed)
    tr, te = next(gss.split(X, y, groups))
    m_grp = make_model(args.trees, args.max_depth, args.seed).fit(X.iloc[tr], y[tr])
    grouped_res = score(m_grp, X.iloc[te], y[te])
    grouped_res['train_domains'] = int(len(set(groups[tr])))
    grouped_res['test_domains'] = int(len(set(groups[te])))

    # Final model: trained on everything, evaluated numbers come from above.
    final = make_model(args.trees, args.max_depth, args.seed).fit(X, y)
    importances = sorted(zip(X.columns, final.feature_importances_),
                         key=lambda kv: -kv[1])

    sanity = []
    for kind, url in SANITY_URLS:
        vec = pd.DataFrame([extract(url)])[list(X.columns)]
        sanity.append({'kind': kind, 'url': url,
                       'p_phishing': round(float(final.predict_proba(vec)[0, 1]), 3)})

    metrics = {
        'dataset': 'PhiUSIIL Phishing URL Dataset (Prasad & Chandra, 2024), '
                   'UCI, CC BY 4.0',
        'feature_set': ('hostname only, leading www. removed'
                        if args.features == 'host' else 'whole-URL lexical features'),
        'dataset_bias_check': bias,
        'urls_used': int(len(X)),
        'phishing_share': round(float(y.mean()), 4),
        'features': list(X.columns),
        'model': f'RandomForest ({args.trees} trees, max_depth={args.max_depth})',
        'random_split': random_res,
        'grouped_split': grouped_res,
        'top_features': [{'feature': k, 'importance': round(float(v), 4)}
                         for k, v in importances[:8]],
        'sanity_check': sanity,
        'note': 'Quote the grouped_split numbers. The random split is optimistic '
                'because the same website can appear in train and test. '
                'PhiUSIIL has its own biases (for example, its legitimate URLs '
                'are mostly short home pages), so results here do not '
                'guarantee performance on real-world links.',
    }

    tag = 'hostonly' if args.features == 'host' else 'wholeurl'
    metrics_file = args.out_dir / f'url_metrics_{tag}.json'
    with open(metrics_file, 'w', encoding='utf-8') as fh:
        json.dump(metrics, fh, indent=2)
    print(f"\nSaved {metrics_file.name}")
    if args.features == 'host':
        artifact = args.out_dir / 'url_model.joblib'
        joblib.dump({
            'model': final,
            'features': list(X.columns),
            'feature_mode': 'host',
            'metrics': metrics,
            'sklearn_version': sklearn.__version__,
            'trained_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        }, artifact, compress=3)
        size_mb = artifact.stat().st_size / (1024 * 1024)
        print(f"Saved {artifact.name} ({size_mb:.1f} MB)")
        if size_mb > WARN_SIZE_MB:
            print(f"WARNING: over {WARN_SIZE_MB} MB; retrain with --trees 60 --max-depth 14")

    print("\n=== RESULTS (phishing = positive class) ===")
    for name, r in (('Random split ', random_res), ('Grouped split', grouped_res)):
        print(f"{name}: accuracy {r['accuracy']} | precision {r['phishing_precision']} "
              f"| recall {r['phishing_recall']} | AUC {r['roc_auc']} "
              f"| false-positive rate {r['false_positive_rate']}")
    print("\nTop features:", ', '.join(f"{k} {v:.3f}" for k, v in importances[:5]))
    print("\n=== SANITY CHECK: probability of phishing ===")
    for s in sanity:
        print(f"{s['p_phishing']:.3f}  [{s['kind']}]  {s['url']}")


if __name__ == '__main__':
    main()