"""URL analyzer tests. requests.post is replaced, so no network is used."""
import pytest
import requests

import url_analyzer as ua

PHISHY = 'http://192.168.1.5/login@secure-update.tk/verify'
NORMAL = 'https://www.youtube.com/watch?v=b_HE9-17rIE&t=135s'


class FakeResponse:
    def __init__(self, status=200, body=None, bad_json=False):
        self.status_code = status
        self._body = body
        self._bad_json = bad_json

    def json(self):
        if self._bad_json:
            raise ValueError('not json')
        return self._body


def engine(key='test-key'):
    e = ua.URLThreatEngine()
    e.api_key = key
    return e


def stub_post(monkeypatch, response=None, exc=None, calls=None):
    def fake(url, **kwargs):
        if calls is not None:
            calls.append((url, kwargs))
        if exc:
            raise exc
        return response
    monkeypatch.setattr(ua.requests, 'post', fake)


NOT_LISTED = FakeResponse(200, {'query_status': 'no_results'})


# ---- verdict logic ----------------------------------------------------

def test_not_listed_and_clean_is_no_threats_detected(monkeypatch):
    stub_post(monkeypatch, NOT_LISTED)
    out = engine().evaluate(NORMAL)
    assert out['verdict'] == 'NO_THREATS_DETECTED'
    assert out['is_suspicious'] is False
    assert out['risk_score'] == 0
    assert any('Not a guarantee' in r for r in out['reasons'])


def test_listed_on_urlhaus_is_suspicious(monkeypatch):
    body = {'query_status': 'ok', 'threat': 'malware_download', 'tags': ['x']}
    stub_post(monkeypatch, FakeResponse(200, body))
    out = engine().evaluate('https://www.example.com/file.exe')
    assert out['verdict'] == 'SUSPICIOUS'
    assert out['risk_score'] >= 95
    assert out['reasons'][0].startswith('Listed on URLhaus')


def test_phishing_style_url_is_suspicious_by_heuristics(monkeypatch):
    stub_post(monkeypatch, NOT_LISTED)
    out = engine().evaluate(PHISHY)
    assert out['verdict'] == 'SUSPICIOUS'
    assert out['risk_score'] >= ua.SUSPICIOUS_THRESHOLD


def test_missing_key_gives_unknown_and_makes_no_request(monkeypatch):
    calls = []
    stub_post(monkeypatch, NOT_LISTED, calls=calls)
    out = engine(key=None).evaluate(NORMAL)
    assert out['verdict'] == 'UNKNOWN'
    assert calls == []


@pytest.mark.parametrize('response,exc', [
    (FakeResponse(403, {}), None),
    (FakeResponse(500, {}), None),
    (FakeResponse(200, bad_json=True), None),
    (FakeResponse(200, {'query_status': 'invalid_url'}), None),
    (FakeResponse(200, {'query_status': 'something_new'}), None),
    (None, requests.Timeout()),
    (None, requests.ConnectionError()),
])
def test_lookup_failure_is_unknown_never_clean(monkeypatch, response, exc):
    stub_post(monkeypatch, response, exc)
    out = engine().evaluate(NORMAL)
    assert out['verdict'] == 'UNKNOWN'
    assert out['is_suspicious'] is False


def test_failed_lookup_does_not_hide_heuristic_hit(monkeypatch):
    stub_post(monkeypatch, exc=requests.Timeout())
    assert engine().evaluate(PHISHY)['verdict'] == 'SUSPICIOUS'


def test_auth_key_is_sent_as_header(monkeypatch):
    calls = []
    stub_post(monkeypatch, NOT_LISTED, calls=calls)
    engine(key='abc123').evaluate(NORMAL)
    url, kwargs = calls[0]
    assert url == ua.URLHAUS_API
    assert kwargs['headers'] == {'Auth-Key': 'abc123'}
    assert kwargs['data'] == {'url': NORMAL}
    assert kwargs['timeout'] > 0


def test_every_verdict_has_a_label(monkeypatch):
    assert set(ua.LABELS) == {'SUSPICIOUS', 'NO_THREATS_DETECTED', 'UNKNOWN'}
    assert 'safe' not in ' '.join(ua.LABELS.values()).lower()


# ---- heuristics -------------------------------------------------------

def test_ip_host_detected():
    f = ua.extract_url_features(PHISHY)
    assert f['has_ip_address'] == 1
    assert f['suspicious_tld'] == 0     # the .tk is in the path, not the host


def test_at_symbol_in_the_address_part_is_detected():
    f = ua.extract_url_features('http://paypal.com@198.51.100.7/login')
    assert f['at_symbol'] == 1
    assert f['has_ip_address'] == 1     # the real host is what follows the @


def test_at_symbol_only_counts_in_the_address_part():
    assert ua.extract_url_features('https://example.com/a@b')['at_symbol'] == 0


def test_phishing_words_match_whole_words_only():
    assert ua.extract_url_features(
        'https://www.freelancer.com/jobs')['suspicious_word_count'] == 0
    assert ua.extract_url_features(
        'https://example.com/login/verify')['suspicious_word_count'] == 2


def test_punycode_and_risky_tld():
    assert ua.extract_url_features('http://xn--pple-43d.com')['punycode'] == 1
    assert ua.extract_url_features('http://shop.example.tk')['suspicious_tld'] == 1


def test_missing_scheme_is_treated_as_http():
    assert ua.extract_url_features('example.com')['is_https'] == 0


def test_malformed_url_raises_value_error():
    with pytest.raises(ValueError):
        ua.extract_url_features('http://[bad')


def test_heuristic_score_is_capped_at_100():
    f = {k: 1 for k in ua.extract_url_features(PHISHY)}
    f.update(suspicious_word_count=9, hostname_entropy=4.5, hostname_length=60,
             hyphen_count=5, dot_count=6)
    score, reasons = ua.heuristic_score(f)
    assert score == 100
    assert len(reasons) > 3


def test_clean_url_scores_zero():
    score, reasons = ua.heuristic_score(ua.extract_url_features(NORMAL))
    assert score == 0 and reasons == []


# ---- hostname-only features (used by the experimental model) ----------

def test_host_features_ignore_www_path_query_and_scheme():
    a = ua.extract_host_features('https://www.example.com/a?b=1')
    b = ua.extract_host_features('http://example.com')
    assert a == b
    assert a['host_length'] == len('example.com')


def test_host_features_detect_ip_and_digits():
    f = ua.extract_host_features('http://192.168.1.5/x')
    assert f['has_ip'] == 1
    assert f['digit_count'] == 8
