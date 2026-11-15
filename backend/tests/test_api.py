"""API tests. They use the committed model and replay sample, so they need
no dataset and no network."""
import pytest

import sentinel_bridge as sb


def _alerts_with_hits(client, tries=15):
    for _ in range(tries):
        data = client.get('/api/alerts').get_json()
        if data['alerts']:
            return data
    raise AssertionError('no alerts produced from the replay sample')


def test_health_reports_ready(client):
    data = client.get('/api/health').get_json()
    assert data['ready'] is True
    assert data['error'] is None


def test_alerts_shape(client):
    resp = client.get('/api/alerts')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['mode'] == 'replay'
    assert len(data['alerts']) <= 6
    assert data['session']['scanned'] >= 30
    for alert in data['alerts']:
        assert alert['family'] in sb.PLAYBOOK
        assert alert['severity'] in {'CRITICAL', 'WARNING'}
        assert 0.0 <= alert['confidence'] <= 1.0
        assert alert['status'] == 'OPEN'
        assert alert['source_ip'].startswith('192.168.1.')
        assert {'protocol', 'service', 'flag'} <= set(alert['evidence'])


def test_respond_mitigates_and_blocks(client):
    alert = _alerts_with_hits(client)['alerts'][0]
    resp = client.post(f"/api/incidents/{alert['id']}/respond")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body['incident']['status'] == 'MITIGATED'
    blocked = client.get('/api/blocklist').get_json()['blocked']
    assert alert['source_ip'] in {b['ip'] for b in blocked}

    # Responding twice changes nothing.
    again = client.post(f"/api/incidents/{alert['id']}/respond")
    assert again.status_code == 200
    assert again.get_json()['status'] == 'MITIGATED'


def test_respond_unknown_incident(client):
    resp = client.post('/api/incidents/doesnotexist/respond')
    assert resp.status_code == 404


def test_metrics_and_threat_stats(client):
    metrics = client.get('/api/metrics').get_json()
    assert 'accuracy_5class' in metrics
    assert len(metrics['per_family']) == 5
    stats = client.get('/api/threat-stats').get_json()
    assert stats['summary']['total_records'] > 0


def test_incident_store_is_capped(client, monkeypatch):
    monkeypatch.setattr(sb, 'MAX_INCIDENTS', 5)
    for _ in range(6):
        client.get('/api/alerts')
    assert len(sb.incidents) <= 5


# ---- /api/scan-url ----------------------------------------------------

def test_scan_url_returns_engine_result(client, monkeypatch):
    monkeypatch.setattr(sb.url_engine, 'evaluate',
                        lambda url: {'verdict': 'UNKNOWN', 'url': url})
    resp = client.post('/api/scan-url', json={'url': '  https://example.com  '})
    assert resp.status_code == 200
    assert resp.get_json()['url'] == 'https://example.com'


@pytest.mark.parametrize('payload', [
    {}, {'url': ''}, {'url': '   '}, {'url': 123}, {'url': None},
    {'url': 'x' * 3000}, {'other': 'field'},
])
def test_scan_url_rejects_bad_input(client, payload):
    assert client.post('/api/scan-url', json=payload).status_code == 400


def test_scan_url_rejects_non_object_json(client):
    resp = client.post('/api/scan-url', data='[1, 2]',
                       content_type='application/json')
    assert resp.status_code == 400


def test_scan_url_rejects_non_json(client):
    resp = client.post('/api/scan-url', data='url=http://a.com')
    assert resp.status_code == 400


def test_scan_url_malformed_url_is_400(client, monkeypatch):
    def boom(url):
        raise ValueError('bad url')
    monkeypatch.setattr(sb.url_engine, 'evaluate', boom)
    assert client.post('/api/scan-url', json={'url': 'http://[x'}).status_code == 400


def test_scan_url_internal_error_is_500_without_details(client, monkeypatch):
    def boom(url):
        raise RuntimeError('secret internal detail')
    monkeypatch.setattr(sb.url_engine, 'evaluate', boom)
    resp = client.post('/api/scan-url', json={'url': 'http://a.com'})
    assert resp.status_code == 500
    assert 'secret' not in resp.get_data(as_text=True)


def test_scan_url_is_rate_limited(client, monkeypatch):
    monkeypatch.setattr(sb.url_engine, 'evaluate', lambda url: {'url': url})
    codes = [client.post('/api/scan-url', json={'url': 'http://a.com'}).status_code
             for _ in range(25)]
    assert codes[:20] == [200] * 20
    assert codes[20] == 429


# ---- CORS -------------------------------------------------------------

def test_cors_allows_localhost(client):
    origin = 'http://localhost:5000'
    resp = client.get('/api/health', headers={'Origin': origin})
    assert resp.headers.get('Access-Control-Allow-Origin') == origin


@pytest.mark.parametrize('origin', [
    'https://evil.example',
    'http://localhost:5000.evil.com',
    'http://127.0.0.1:5000.evil.com',
])
def test_cors_blocks_other_origins(client, origin):
    resp = client.get('/api/health', headers={'Origin': origin})
    assert resp.headers.get('Access-Control-Allow-Origin') is None
