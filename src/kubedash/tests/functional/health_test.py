import pytest, json

def test_ping(client):
    response = client.get('/ping')
    assert response.status_code == 200
    assert b"pong" in response.data

def test_health(client):
    response = client.get('/health')
    res = json.loads(response.data.decode('utf-8'))
    assert response.status_code == 200
    assert res['health'] == "healthy"

def test_dashboard__not_logged_in(client):
    res = client.get('/dashboard')
    assert res.status_code == 302

def test_dashboard__logged_in(client):
    with client:
        client.post("/", data={"username": "pytest", "password": "pytest"}, follow_redirects=True)
        res = client.get('/dashboard')
        assert res.status_code == 200

