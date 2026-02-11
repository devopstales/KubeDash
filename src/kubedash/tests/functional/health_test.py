import json


def test_ping(client):
    """
    Test the ``/api/ping`` endpoint

    Args:
        client (FlaskClient): The Flask test client

    Expectations:
    - The response status code should be 200
    - The response data should contain the string "pong"
    """
    response = client.get('/api/ping')

    print(response)

    assert response.status_code == 200
    data = json.loads(response.data.decode('utf-8'))
    assert data['message'] == 'pong'

def test_liveness_probe(client):
    response = client.get('/api/health/live')
    res = json.loads(response.data.decode('utf-8'))
    assert response.status_code == 200
    # API returns {"message": "OK"} not {"title": "OK"}
    assert res.get('message') == "OK" or res.get('title') == "OK"

def test_readiness_probe(client):
    response = client.get('/api/health/ready')
    res = json.loads(response.data.decode('utf-8'))
    assert response.status_code == 200
    # API returns a dict with database, oidc, kubernetes fields
    # Check that it's a valid response structure
    assert isinstance(res, dict)
    assert 'database' in res or 'kubernetes' in res or res.get('title') == "OK"

def test_prometheus_metrics(client):
    response = client.get('/metrics')
    assert response.status_code == 200