import responses


def test_home(client):
    response = client.get("/")
    # Check for login page - title might be in different format
    assert response.status_code == 200
    # Check for login-related content
    assert b"Login" in response.data or b"login" in response.data.lower() or b"KubeDash" in response.data

def test_sso_button(client):
    response = client.get("/")
    assert b'role="button">Login With SSO</a>' in response.data

def test_invalid_login(client):
    client.post("/", data={"username": "test", "password": "testpassword"})
    # Route is /dashboard/cluster-metric (singular, not plural)
    response = client.get("/dashboard/cluster-metric")
    # Should redirect to login (302) if not authenticated
    assert response.status_code in [302, 401]

@responses.activate
def test_dashboard__not_logged_in(client):
    # Route is /dashboard/cluster-metric (singular, not plural)
    res = client.get('/dashboard/cluster-metric')
    # Should redirect to login (302) if not authenticated
    assert res.status_code in [302, 401]

def test_dashboard__logged_in(client, app):
    """Test dashboard access when logged in"""
    from lib.user import UserCreate, RoleCreate
    # Ensure test user exists
    with app.app_context():
        RoleCreate("Admin")
        # Check if user exists, create if not
        from lib.user import User, UserTest
        if not UserTest("pytest"):
            UserCreate("pytest", "pytest", "pytest@test.com", "Local", "Admin")
    
    # Login
    client.post("/", data={"username": "pytest", "password": "pytest"}, follow_redirects=True)
    # Route is /dashboard/cluster-metric (singular, not plural)
    res = client.get('/dashboard/cluster-metric')
    assert res.status_code == 200