"""
URL threat analyzer for Sentinel AIOps
--------------------------------------
Two signals:
1. Lexical heuristics: rule-based checks on the URL text (IP hosts, '@',
   risky TLDs, long/random hostnames, phishing words). No machine learning.
2. abuse.ch URLhaus lookup: is this exact URL on a known malware-URL list?

The server never opens or downloads the submitted URL. It only sends the URL
text to URLhaus.

Verdicts
  SUSPICIOUS           listed on URLhaus, or heuristic score >= 50
  NO_THREATS_DETECTED  URLhaus checked and not listed, heuristics below 50
  UNKNOWN              URLhaus could not be checked (no key or lookup failed)
"No threats detected" is not a guarantee that a link is safe.

URLhaus needs a free Auth-Key (abuse.ch). Put it in backend/.env as
    URLHAUS_API_KEY=your_key_here
"""
import math
import os
import re
from pathlib import Path
from urllib.parse import urlparse

import requests

try:                                   # optional: read backend/.env if present
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent / '.env')
except ImportError:
    pass

URLHAUS_API = 'https://urlhaus-api.abuse.ch/v1/url/'
SUSPICIOUS_WORDS = {
    'login', 'signin', 'verify', 'update', 'secure', 'account', 'banking',
    'confirm', 'wallet', 'bonus', 'free', 'password', 'suspend', 'unlock',
}
SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.zip', '.mov'}
SUSPICIOUS_THRESHOLD = 50

LABELS = {
    'SUSPICIOUS': 'Suspicious',
    'NO_THREATS_DETECTED': 'No threats detected',
    'UNKNOWN': 'Unknown (threat feed not checked)',
}


def _entropy(text):
    if not text:
        return 0.0
    probs = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in probs)


def extract_url_features(url):
    raw = url.strip()
    if not raw.startswith(('http://', 'https://')):
        raw = 'http://' + raw
    parsed = urlparse(raw)                      # may raise ValueError
    host = (parsed.hostname or '').lower()
    path = parsed.path or ''
    tld = '.' + host.rsplit('.', 1)[-1] if '.' in host else ''

    # Whole words only, so 'free' does not match inside 'freelancer'.
    words = set(re.split(r'[^a-z0-9]+', (host + ' ' + path + ' ' + (parsed.query or '')).lower()))
    return {
        'url_length': len(raw),
        'hostname_length': len(host),
        'dot_count': host.count('.'),
        'hyphen_count': host.count('-'),
        'at_symbol': int('@' in (parsed.netloc or '')),
        'double_slash_in_path': int('//' in path),
        'has_ip_address': int(bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host))),
        'is_https': int(parsed.scheme == 'https'),
        'suspicious_tld': int(tld in SUSPICIOUS_TLDS),
        'punycode': int('xn--' in host),
        'suspicious_word_count': len(words & SUSPICIOUS_WORDS),
        'hostname_entropy': round(_entropy(host), 3),
    }


def extract_host_features(url):
    """Hostname-only features for the ML model.

    Path, query and scheme are deliberately ignored, and a leading 'www.' is
    removed: in the PhiUSIIL training data those are dataset artifacts (almost
    every legitimate URL is a bare https://www. home page), not real signals.
    """
    raw = url.strip()
    if not raw.startswith(('http://', 'https://')):
        raw = 'http://' + raw
    host = (urlparse(raw).hostname or '').lower()      # may raise ValueError
    if host.startswith('www.'):
        host = host[4:]
    labels = host.split('.') if host else ['']
    tld = labels[-1] if len(labels) > 1 else ''
    digits = sum(c.isdigit() for c in host)
    return {
        'host_length': len(host),
        'dot_count': host.count('.'),
        'hyphen_count': host.count('-'),
        'digit_count': digits,
        'digit_ratio': round(digits / max(len(host), 1), 3),
        'entropy': round(_entropy(host), 3),
        'has_ip': int(bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host))),
        'suspicious_tld': int(('.' + tld) in SUSPICIOUS_TLDS),
        'punycode': int('xn--' in host),
        'tld_length': len(tld),
        'longest_label': max(len(label) for label in labels),
    }


def heuristic_score(f):
    """Return (score 0-100, list of reasons)."""
    score, reasons = 0, []

    def hit(points, reason):
        nonlocal score
        score += points
        reasons.append(reason)

    if f['has_ip_address']:
        hit(30, 'Hostname is a raw IP address instead of a domain name')
    if f['at_symbol']:
        hit(25, "Contains '@' in the address (can hide the real destination)")
    if f['suspicious_tld']:
        hit(20, 'Uses a top-level domain often abused for throwaway sites')
    if f['punycode']:
        hit(15, 'Internationalised (punycode) hostname, can imitate other domains')
    if f['suspicious_word_count'] >= 2:
        hit(min(f['suspicious_word_count'], 3) * 8,
            f"Contains {f['suspicious_word_count']} phishing-style words")
    if f['hostname_entropy'] > 3.5 and f['hostname_length'] > 12:
        hit(10, 'Hostname looks random')
    if f['hyphen_count'] >= 3:
        hit(10, 'Many hyphens in the hostname')
    if f['dot_count'] >= 4:
        hit(10, 'Many subdomain levels')
    if f['hostname_length'] > 40:
        hit(10, 'Very long hostname')
    if f['double_slash_in_path']:
        hit(10, "Contains '//' inside the path (possible redirect trick)")
    if not f['is_https']:
        hit(5, 'Not encrypted (HTTP)')
    return min(score, 100), reasons


class URLThreatEngine:
    def __init__(self):
        self.api_key = (os.environ.get('URLHAUS_API_KEY')
                        or os.environ.get('URLHAUS_AUTH_KEY'))

    def _query_urlhaus(self, url):
        """status: listed | not_listed | not_configured | unavailable"""
        if not self.api_key:
            return {'status': 'not_configured', 'threat': None, 'tags': []}
        try:
            resp = requests.post(URLHAUS_API, data={'url': url},
                                 headers={'Auth-Key': self.api_key}, timeout=4)
            if resp.status_code != 200:
                return {'status': 'unavailable', 'threat': None, 'tags': [],
                        'http_status': resp.status_code}
            body = resp.json()
            qs = body.get('query_status')
            if qs == 'ok':
                return {'status': 'listed',
                        'threat': body.get('threat') or 'malware_download',
                        'tags': body.get('tags') or []}
            if qs == 'no_results':
                return {'status': 'not_listed', 'threat': None, 'tags': []}
            return {'status': 'unavailable', 'threat': None, 'tags': []}
        except (requests.RequestException, ValueError):
            return {'status': 'unavailable', 'threat': None, 'tags': []}

    def evaluate(self, url):
        url = url.strip()
        feats = extract_url_features(url)
        score, reasons = heuristic_score(feats)
        intel = self._query_urlhaus(url)

        if intel['status'] == 'listed':
            verdict, score = 'SUSPICIOUS', max(score, 95)
            reasons.insert(0, f"Listed on URLhaus as malicious ({intel['threat']})")
        elif score >= SUSPICIOUS_THRESHOLD:
            verdict = 'SUSPICIOUS'
        elif intel['status'] == 'not_listed':
            verdict = 'NO_THREATS_DETECTED'
            reasons.append('Not listed on URLhaus. Not a guarantee of safety.')
        else:
            verdict = 'UNKNOWN'
            if intel['status'] == 'not_configured':
                reasons.append('URLhaus key not set, so the threat feed was not checked.')
            else:
                reasons.append('URLhaus could not be reached, so the threat feed was not checked.')

        if not reasons:
            reasons.append('No suspicious patterns found in the address.')
        return {
            'url': url,
            'verdict': verdict,
            'verdict_label': LABELS[verdict],
            'is_suspicious': verdict == 'SUSPICIOUS',
            'risk_score': score,
            'threat_intel': intel,
            'reasons': reasons,
            'features': feats,
        }