import json

def test_blueprint_app_ping(client):
    response = client.get("/api/ping")
    assert response.status_code == 200
    
    res = json.loads(response.data.decode('utf-8'))
    assert res["message"] == 'pong'
    
def test_blueprint_app_live(client):
    response = client.get("/api/health/live")
    assert response.status_code == 200
    
def test_blueprint_app_ready(client):
    response = client.get("/api/health/ready")
    assert response.status_code == 200
    
    #res = json.loads(response.data.decode('utf-8'))
    #assert res['title'] == "OK"
    
def test_blueprint_app_swagger(client):
    response = client.get("/api/swagger-ui")
    assert response.status_code == 200
