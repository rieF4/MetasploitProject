import logging
import pytest

from metasploit.tests.test_wrapper import BaseApiInterface
from metasploit.tests.helpers import execute_rest_api_func


from . import config


logger = logging.getLogger("UserApi")


@pytest.fixture(scope="class")
def user_api(test_client):
    """
    This fixture provides the MetasploitApi object in order to make API calls.

    Returns:
        MetasploitApi: a docker server object.
    """

    class UserApi(BaseApiInterface):

        def post(self, create_user_body_request, create_user_url=config.CREATE_USER_URL):
            """
            Sends a POST request in order to create a user.

            Args:
                create_user_body_request (dict): a body request to create a new user.
                create_user_url (str): the URL to create the user.

            Returns:
                tuple[dict, int]: a tuple containing the body response as a first arg, and status code as second arg.
            """
            logger.info(f"Send POST request, URL: {create_user_url}, REQUEST: {create_user_body_request}")

            return execute_rest_api_func(
                url=create_user_url, api_func=self._test_client.post, request_body=create_user_body_request
            )

        def get_one(self, username, password, get_user_url=config.GET_USER_URL):
            """
            Sends a GET request in order to get a user.

            Args:
                username (str): user name.
                password (str): user password.
                get_user_url (str): the URL to get the user.

            Returns:
                tuple[dict, int]: a tuple containing the body response as a first arg, and status code as second arg.
            """
            get_user_url = get_user_url.format(username=username, password=password)
            logger.info(f"Send GET request, URL: {get_user_url}")

            return execute_rest_api_func(url=get_user_url, api_func=self._test_client.get)

        def get_many(self, get_all_users_url=config.GET_ALL_USERS_URL):
            """
            Sends a GET request in order to get all the users.

            Args:
                get_all_users_url (str): the URL to get all the users.

            Returns:
                tuple[dict, int]: a tuple containing the body response as a first arg, and status code as second arg.
            """
            logger.info(f"Send GET request, URL: {get_all_users_url}")

            return execute_rest_api_func(url=get_all_users_url, api_func=self._test_client.get)

        def delete(self, username, delete_user_url=config.DELETE_USER_URL):
            """
            Sends a DELETE request in order to delete a user.

            Args:
                username (str): user name.
                delete_user_url (str): the URL to delete a user.

            Returns:
                tuple[str, int]: a tuple containing the body response as a first arg, and status code as second arg.
            """
            delete_user_url = delete_user_url.format(username=username)
            logger.info(f"Send DELETE request, URL: {delete_user_url}")

            return execute_rest_api_func(url=delete_user_url, api_func=self._test_client.delete)
        
    return UserApi(test_client=test_client)