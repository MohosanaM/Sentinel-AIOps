"""
Hybrid URL Threat Analyzer for Sentinel AIOps
----------------------------------------------
Combines:
1. Lexical & structural heuristics (entropy, IP hosts, suspicious tokens)
2. Scikit-learn Random Forest classifier trained on URL structural patterns
3. Live threat intelligence lookup via abuse.ch URLhaus API (no key required)
"""
import math
import os
import re
from urllib.parse import urlparse

import joblib
import numpy as np
import requests
from sklearn.ensemble import RandomForestClassifier

SUSPICIOUS_TOKENS = [
    'login', 'verify', 'update', 'secure', 'account', 'banking', 'paypal',
    'signin', 'confirm', 'wallet', 'crypto', 'free', 'bonus', 'admin', 'cmd'
]
SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.zip', '.mov'}
URLHAUS_API = 'https://urlhaus-api.abuse.ch/v1/url/'


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    probs = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in probs)


def extract_url_features(url: str) -> dict:
    """Extracts numerical & boolean lexical features from a URL."""
    raw = url.strip()
    if not raw.startswith(('http://', 'https://')):
        raw = 'http://' + raw

    parsed = urlparse(raw)
    hostname = parsed.hostname or ''
    path = parsed.path or ''

    has_ip = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname))
    tld = '.' + hostname.split('.')[-1].lower() if '.' in hostname else ''
    token_hits = sum(1 for tok in SUSPICIOUS_TOKENS if tok in raw.lower())

    return {
        'url_length': len(raw),
        'hostname_length': len(hostname),
        'dot_count': hostname.count('.'),
        'hyphen_count': hostname.count('-'),
        'at_symbol': int('@' in raw),
        'double_slash_redirect': int('//' in path),
        'has_ip_address': int(has_ip),
        'is_https': int(parsed.scheme == 'https'),
        'suspicious_tld': int(tld in SUSPICIOUS_TLDS),
        'suspicious_token_count': token_hits,
        'digit_ratio': round(sum(c.isdigit() for c in hostname) / max(len(hostname), 1), 3),
        'hostname_entropy': round(_shannon_entropy(hostname), 3),
    }


def _build_default_url_model():
    rng = np.random.default_rng(42)
    n_benign = 400
    benign = np.column_stack([
        rng.integers(18, 55, n_benign),
        rng.integers(8, 22, n_benign),
        rng.integers(1, 3, n_benign),
        rng.integers(0, 2, n_benign),
        np.zeros(n_benign),
        np.zeros(n_benign),
        np.zeros(n_benign),
        rng.choice([0, 1], n_benign, p=[0.1, 0.9]),
        np.zeros(n_benign),
        rng.choice([0, 1], n_benign, p=[0.85, 0.15]),
        rng.uniform(0.0, 0.1, n_benign),
        rng.uniform(2.2, 3.3, n_benign),
    ])

    n_mal = 400
    malicious = np.column_stack([
        rng.integers(55, 160, n_mal),
        rng.integers(18, 50, n_mal),
        rng.integers(2, 6, n_mal),
        rng.integers(1, 5, n_mal),
        rng.choice([0, 1], n_mal, p=[0.8, 0.2]),
        rng.choice([0, 1], n_mal, p=[0.75, 0.25]),
        rng.choice([0, 1], n_mal, p=[0.75, 0.25]),
        rng.choice([0, 1], n_mal, p=[0.6, 0.4]),
        rng.choice([0, 1], n_mal, p=[0.65, 0.35]),
        rng.integers(1, 5, n_mal),
        rng.uniform(0.1, 0.45, n_mal),
        rng.uniform(3.3, 4.5, n_mal),
    ])

    X = np.vstack([benign, malicious])
    y = np.array([0] * n_benign + [1] * n_mal)
    clf = RandomForestClassifier(n_estimators=80, random_state=42)
    clf.fit(X, y)
    return clf


class URLThreatEngine:
    def __init__(self, model_path='url_model.joblib'):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.model_path = os.path.join(base_dir, model_path)
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
        else:
            self.model = _build_default_url_model()
            joblib.dump(self.model, self.model_path)

    def _query_urlhaus(self, url: str) -> dict:
        try:
            resp = requests.post(URLHAUS_API, data={'url': url}, timeout=4)
            if resp.status_code == 200:
                payload = resp.json()
                if payload.get('query_status') == 'ok':
                    return {
                        'listed': True,
                        'threat': payload.get('threat', 'malware_download'),
                        'tags': payload.get('tags') or [],
                    }
            return {'listed': False, 'threat': None, 'tags': []}
        except Exception:
            return {'listed': False, 'threat': 'lookup_unavailable', 'tags': []}

    def evaluate(self, url: str) -> dict:
        feats = extract_url_features(url)
        feature_vector = np.array([[
            feats['url_length'], feats['hostname_length'], feats['dot_count'],
            feats['hyphen_count'], feats['at_symbol'], feats['double_slash_redirect'],
            feats['has_ip_address'], feats['is_https'], feats['suspicious_tld'],
            feats['suspicious_token_count'], feats['digit_ratio'], feats['hostname_entropy']
        ]])

        ml_prob = float(self.model.predict_proba(feature_vector)[0][1])
        intel = self._query_urlhaus(url.strip())

        reasons = []
        if intel['listed']:
            reasons.append(f"Flagged by URLhaus threat feed ({intel['threat']})")
        if feats['has_ip_address']:
            reasons.append("Hostname uses a raw IP address instead of a domain")
        if feats['at_symbol']:
            reasons.append("Contains '@' symbol (URL credential/redirect obfuscation)")
        if feats['suspicious_tld']:
            reasons.append("Uses high-risk top-level domain")
        if feats['suspicious_token_count'] >= 2:
            reasons.append(f"Contains {feats['suspicious_token_count']} phishing-related keywords")
        if feats['hostname_entropy'] > 3.5:
            reasons.append(f"High domain entropy ({feats['hostname_entropy']}) suggests DGA/random string")
        if not feats['is_https']:
            reasons.append("Unencrypted HTTP connection")

        final_score = max(0.95, ml_prob) if intel['listed'] else ml_prob
        verdict = 'SUSPICIOUS' if final_score >= 0.55 else 'SAFE'
        if not reasons and verdict == 'SAFE':
            reasons.append("Clean lexical structure and not listed on URLhaus")

        return {
            'url': url.strip(),
            'verdict': verdict,
            'is_suspicious': verdict == 'SUSPICIOUS',
            'risk_score': round(final_score * 100, 1),
            'ml_confidence': round(ml_prob * 100, 1),
            'threat_intel': intel,
            'reasons': reasons,
            'features': feats,
        }