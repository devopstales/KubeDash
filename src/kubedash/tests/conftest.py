import pytest, logging
from flask.testing import FlaskClient
from kubedash import app

TEST_SQL_PATH = "pytest.db"

@pytest.fixture(scope='module')
def flask_app():
    with app.app_context():
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///"+TEST_SQL_PATH
        yield app

@pytest.fixture(scope='module')
def client(flask_app):
    app = flask_app
    ctx = flask_app.test_request_context()
    ctx.push()
    app.test_client_class = FlaskClient
    return app.test_client()
    
