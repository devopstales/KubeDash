import responses, time
from flask import url_for

def test_invalid_login(client):
    client.post("/", data={"username": "test", "password": "testpassword"})
    response = client.get("/dashboard")
    assert response.status_code == 302

@responses.activate
def test_dashboard__not_logged_in(client):
    res = client.get('/dashboard')
    assert res.status_code == 302

def test_dashboard__logged_in(client):
    with client:
        client.post("/", data={"username": "pytest", "password": "pytest"}, follow_redirects=True)
        res = client.get('/dashboard')
        assert res.status_code == 200

def test_take_screenshot(live_server, page):
    page.goto(url_for('main.login', _external=True))
    page.screenshot(path="screenshots/home.png")

def test_login(live_server, page):
    page.goto(url_for('main.login', _external=True))
    page.get_by_placeholder("Username").fill("pytest")
    page.get_by_placeholder("Password").fill("pytest")
    page.get_by_role("button", name="Sign in").click()
    time.sleep(3)
    page.screenshot(path="screenshots/dashboard.png")

# https://playwright.dev/docs/getting-started-vscode