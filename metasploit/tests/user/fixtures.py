import pytest
import logging

from metasploit.api.response import HttpCodes

logger = logging.getLogger("UserFixtures")


@pytest.fixture(scope="class")
def create_users(request, user_api):
    """
    Creates users via post request.

    Returns:
        list[list[tuple]/tuple, int]: a list of all newly created users body responses and their status code.
    """
    create_user_body_requests = getattr(request.cls, "create_user_body_requests", [])
    users_body_responses = []
    delete_users = []

    def fin():
        """
        Deletes all the created users using DELETE.
        """
        for username in delete_users:
            logger.info(f"Delete user {username}")
            delete_body_response, status_code = user_api.delete(username=username)

            assert delete_body_response == ''
            assert status_code == HttpCodes.NO_CONTENT
    request.addfinalizer(fin)

    for user_body_request in create_user_body_requests:
        logger.info(f"Creating user {user_body_request}")
        users_body_responses.append(user_api.post(create_user_body_request=user_body_request))
        delete_users.append(user_body_request.get("username"))

    return users_body_responses
