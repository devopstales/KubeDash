import responses

def test_home(client):
    response = client.get("/")
    assert b"<title>KubeDash - Login</title>" in response.data

def test_sso_button(client):
    response = client.get("/")
    assert b'role="button">Login With SSO</a>' in response.data

def test_invalid_login(client):
    client.post("/", data={"username": "test", "password": "testpassword"})
    response = client.get("/cluster-metrics")
    assert response.status_code == 302

@responses.activate
def test_dashboard__not_logged_in(client):
    res = client.get('/cluster-metrics')
    assert res.status_code == 302

def test_dashboard__logged_in(client):
    client.post("/", data={"username": "pytest", "password": "pytest"}, follow_redirects=True)
    res = client.get('/cluster-metrics')
    assert res.status_code == 200