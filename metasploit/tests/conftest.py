import pytest

from flask import current_app
from metasploit.api.controllers import flask_wrapper


@pytest.fixture(scope="session")
def test_client():
    """
    Provides a test test_client of flask for all the tests/fixtures.
    """
    app = flask_wrapper.FlaskAppWrapper().app
    app.config['TESTING'] = True

    with app.app_context():
        yield current_app.test_client()
