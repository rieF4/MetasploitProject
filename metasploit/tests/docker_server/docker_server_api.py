import logging
import pytest

from metasploit.tests.test_wrapper import BaseApiInterface
from metasploit.tests.helpers import (
    to_utf8,
    execute_rest_api_func
)

from . import config

logger = logging.getLogger("DockerServerApi")


@pytest.fixture(scope="class")
def docker_server_api(test_client):
    """
    This fixture provides the DockerServerApi object in order to make API calls.

    Returns:
        DockerServerApi: a docker server object.
    """
    class DockerServerApi(BaseApiInterface):

        def post(
                self,
                create_docker_server_url=config.CREATE_DOCKER_SERVER_URL,
                create_docker_server_request=config.CREATE_DOCKER_SERVER_REQUEST
        ):
            """
            Sends a POST request in order to create new docker server.

            Args:
                create_docker_server_url (str): the URL to create a docker server.
                create_docker_server_request (dict): the request to create a docker server.

            Returns:
                tuple[dict, int]: a tuple containing the body response as a first arg, and status code as second arg.
            """
            logger.info(f"Send POST request, URL: {create_docker_server_url}, REQUEST: {create_docker_server_request}")

            return execute_rest_api_func(
                url=create_docker_server_url,
                api_func=self._test_client.post,
                request_body=create_docker_server_request
            )

        def get_many(self):
            """
            Sends a GET request to retrieve all the docker server instances available.

            Returns:
                tuple[list[dict], int]: a tuple containing the body response as a first arg,
                    and status code as second arg.
            """
            get_all_docker_servers_url = config.GET_ALL_DOCKER_SERVERS_URL
            logger.info(f"Send GET request, URL: {get_all_docker_servers_url}")

            return execute_rest_api_func(url=get_all_docker_servers_url, api_func=self._test_client.get)

        def get_one(self, instance_id):
            """
            Sends a GET request to retrieve a docker server instance.

            Args:
                instance_id (str): instance ID.

            Returns:
                tuple[dict, int]: a tuple containing the body response as a first arg, and status code as second arg.
            """
            get_docker_server_url = config.GET_DOCKER_SERVER_URL.format(instance_id=instance_id)
            logger.info(f"Send GET request, URL: {get_docker_server_url}")

            return execute_rest_api_func(url=get_docker_server_url, api_func=self._test_client.get)

        def delete(self, instance_id):
            """
            Sends a DELETE request to delete a docker server instance.

            Args:
                instance_id (str): instance ID.

            Returns:
                tuple[str, int]: a tuple containing the body response as first arg, and status code as second arg.
            """
            delete_docker_server_url = config.DELETE_DOCKER_SERVER_URL.format(instance_id=instance_id)
            logger.info(f"Send DELETE request, URL: {delete_docker_server_url}")

            return execute_rest_api_func(
                url=delete_docker_server_url, api_func=self._test_client.delete, convert_func=to_utf8
            )

    return DockerServerApi(test_client=test_client)
