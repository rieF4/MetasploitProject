import pytest
import logging


from metasploit.api.response import HttpCodes
from metasploit.tests.conftest import test_client  # noqa: F401
from metasploit.tests.helpers import (
    is_expected_code,
    is_error_response_valid
)


from . import config
from .user_api import user_api  # noqa: F401


logger = logging.getLogger("UserTests")


class TestCreateUserPostApi(object):

    @pytest.mark.parametrize(
        "invalid_user_request",
        [
            pytest.param(
                config.USER_REQUEST_WITH_INVALID_EMAIL,
                id="Create_user_with_invalid_email"
            ),
            pytest.param(
                config.USER_REQUEST_WITH_NUMBERS_IN_FIRST_NAME,
                id="Create_user_with_numbers_in_first_name"
            ),
            pytest.param(
                config.USER_REQUEST_WITH_NUMBERS_IN_LAST_NAME,
                id="Create_user_with_numbers_in_last_name"
            ),
            pytest.param(
                config.USER_REQUEST_WITH_SHORT_PASSWORD,
                id="Create_user_with_short_password"
            ),
            pytest.param(
                config.USER_REQUEST_WITHOUT_FIRST_NAME_AND_LAST_NAME,
                id="Create_user_without_first_name_and_last_name_in_body_request"
            ),
            pytest.param(
                config.USER_REQUEST_WITHOUT_PASSWORD_AND_USER_NAME,
                id="Create_user_without_username_and_password_in_body_request"
            )
        ]
    )
    def test_create_invalid_user_fails(self, invalid_user_request, user_api):
        """
        Tests scenarios where creating a user should fail.
        """
        user_response_body, actual_status_code = user_api.post(create_user_body_request=invalid_user_request)

        logger.info(f"Verify that the user body response {user_response_body} is an ERROR")
        assert is_error_response_valid(
            error_response=user_response_body,
            code=HttpCodes.BAD_REQUEST
        )

        logger.info(f"Verify that status code is {HttpCodes.BAD_REQUEST}")
        assert is_expected_code(actual_code=actual_status_code, expected_code=HttpCodes.BAD_REQUEST), (
            f"actual {actual_status_code}, expected {HttpCodes.OK}"
        )
