
import logging

import pytest
from kubedash import create_app
import flask_migrate


@pytest.fixture(scope="session")
def app():
    app = create_app(app_mode="testing")

    with app.app_context():
        flask_migrate.upgrade()

    yield app

@pytest.fixture
def client(app):
    return app.test_client()


#from flask.testing import FlaskClient
#@pytest.fixture(scope='module')
#def client(app):
#    ctx = app.test_request_context()
#    # file deepcode ignore DisablesCSRFProtection/test: <please specify a reason of ignoring this>
#    ctx.push()
#    app.test_client_class = FlaskClient
#    return app.test_client()