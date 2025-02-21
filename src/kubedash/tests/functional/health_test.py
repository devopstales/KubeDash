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
    assert response.data == b'pong'

def test_liveness_probe(client):
    response = client.get('/api/health/live')
    res = json.loads(response.data.decode('utf-8'))
    assert response.status_code == 200
    assert res['title'] == "OK"

def test_readiness_probe(client):
    response = client.get('/api/health/ready')
    res = json.loads(response.data.decode('utf-8'))
    assert response.status_code == 200
    assert res['title'] == "OK"

def test_prometheus_metrics(client):
    response = client.get('/metrics')
    assert response.status_code == 200