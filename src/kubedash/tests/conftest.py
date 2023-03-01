import pytest, logging
from flask.testing import FlaskClient
from kubedash import create_app

TEST_SQL_PATH = "pytest.db"

@pytest.fixture(scope='module')
def flask_app():
    app = create_app("testing")
    with app.app_context():
        yield app

@pytest.fixture(scope='module')
def client(flask_app):
    app = flask_app
    ctx = flask_app.test_request_context()
    ctx.push()
    app.test_client_class = FlaskClient
    return app.test_client()
    
