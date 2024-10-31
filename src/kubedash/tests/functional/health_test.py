import json

def test_ping(client):
    response = client.get('/api/ping')
    assert response.status_code == 200
    assert b"pong" in response.data

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

def test_home(client):
    response = client.get("/")
    assert b"<title>KubeDash - Login</title>" in response.data