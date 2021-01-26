import logging
import pytest

from metasploit.tests.test_wrapper import BaseApiInterface
from metasploit.tests import constants as test_const
from metasploit.tests.helpers import (
    convert,
    to_utf8
)

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
                create_docker_server_url=test_const.CREATE_DOCKER_SERVER,
                create_docker_server_request=test_const.CREATE_DOCKER_SERVER_REQUEST
        ):
            """
            Sends a POST request in order to create new docker server.

            Args:
                create_docker_server_url (str): the URL to create a docker server.
                create_docker_server_request (dict): the request to create a docker server.

            Returns:
                tuple[dict, int]: a tuple containing the data response as a first arg, and status code as second arg.
            """
            logger.info(f"Send POST request, URL: {create_docker_server_url}, REQUEST: {create_docker_server_request}")

            new_docker_instance_response = self._test_client.post(
                create_docker_server_url, json=create_docker_server_request
            )
            data_response = convert(response_as_bytes=new_docker_instance_response.data)
            status_code = new_docker_instance_response.status_code

            return data_response, status_code

        def get_many(self, *args, **kwargs):
            """
            Sends a GET request to retrieve all the docker server instances available.

            Returns:
                tuple[list[dict], int]: a tuple containing the data response as a first arg,
                    and status code as second arg.
            """
            get_all_docker_servers_url = test_const.GET_ALL_DOCKER_SERVERS

            logger.info(f"Send GET request, URL: {get_all_docker_servers_url}")

            all_available_instances = self._test_client.get(get_all_docker_servers_url)
            data_response = convert(response_as_bytes=all_available_instances.data)
            status_code = all_available_instances.status_code

            return data_response, status_code

        def get_one(self, instance_id):
            """
            Sends a GET request to retrieve a docker server instance.

            Args:
                instance_id (str): instance ID.

            Returns:
                tuple[dict, int]: a tuple containing the data response as a first arg, and status code as second arg.
            """
            get_docker_server_url = test_const.GET_DOCKER_SERVER.format(instance_id=instance_id)

            logger.info(f"Send GET request, URL: {get_docker_server_url}")

            docker_instance = self._test_client.get(get_docker_server_url)
            data_response = convert(response_as_bytes=docker_instance.data)
            status_code = docker_instance.status_code

            return data_response, status_code

        def delete(self, instance_id):
            """
            Sends a DELETE request to delete a docker server instance.

            Args:
                instance_id (str): instance ID.

            Returns:
                tuple[str, int]: a tuple containing the data response as first arg, and status code as second arg.
            """
            delete_docker_server_url = test_const.DELETE_DOCKER_SERVER.format(instance_id=instance_id)

            logger.info(f"Send DELETE request, URL: {delete_docker_server_url}")

            delete_response = self._test_client.delete(delete_docker_server_url)
            data_response = to_utf8(response_as_bytes=delete_response.data)
            status_code = delete_response.status_code

            return data_response, status_code

    return DockerServerApi(test_client=test_client)
