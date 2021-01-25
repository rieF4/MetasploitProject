import pytest

from flask import current_app
from metasploit.api.controllers import flask_wrapper


@pytest.fixture(scope="module")
def test_client():
    """
    Provides a test test_client of flask for all the tests/fixtures.
    """
    app = flask_wrapper.FlaskAppWrapper().app
    with app.app_context():
        app.config['TESTING'] = True
        yield current_app.test_client()
