import json

def test_ping(client):
    response = client.get('/ping')
    assert response.status_code == 200
    assert b"pong" in response.data

def test_health(client):
    response = client.get('/health')
    res = json.loads(response.data.decode('utf-8'))
    assert response.status_code == 200
    assert res['health'] == "healthy"

def test_home(client):
    response = client.get("/")
    assert b"<title>KubeDash - Login</title>" in response.data