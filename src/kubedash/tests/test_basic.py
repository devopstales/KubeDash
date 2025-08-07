def test_app(client):
    response = client.get("/")
    assert response.status_code == 200
    
def test_metrics_endpoint(client):
    response = client.get("/metrics")
    assert response.status_code == 200