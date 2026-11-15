import pytest

import sentinel_bridge as sb


@pytest.fixture()
def client():
    """Flask test client; rate-limit counters are cleared for every test."""
    sb.app.config['TESTING'] = True
    sb.limiter.reset()
    return sb.app.test_client()
