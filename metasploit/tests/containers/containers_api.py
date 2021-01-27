import logging
import pytest

from metasploit.tests.test_wrapper import BaseApiInterface
from metasploit.tests.helpers import to_utf8
from metasploit.tests.helpers import execute_rest_api_func

from . import config
logger = logging.getLogger("ContainersApi")


@pytest.fixture(scope="class")
def container_api(test_client):
    """
    This fixture provides the ContainerApi object in order to make API calls.

    Returns:
        ContainerApi: a container api object.
    """
    class ContainerApi(BaseApiInterface):

        def post(self, instance_id, create_msfrpcd_container_url=config.CREATE_MSFRPCD_CONTAINER_URL):
            """
            Sends a POST request in order to create a metasploit based image container.

            Args:
                instance_id (str): instance ID that the container will be created on.
                create_msfrpcd_container_url (str): URL for the POST request to create the container.

            Returns:
                tuple[dict, int]: a tuple containing the body response as a first arg, and status code as second arg.
            """
            create_msfrpcd_container_url = create_msfrpcd_container_url.format(instance_id=instance_id)
            logger.info(f"Send POST request, URL: {create_msfrpcd_container_url}")

            return execute_rest_api_func(url=create_msfrpcd_container_url, api_func=self._test_client.post)

        def get_many(self, instance_id):
            """
            Sends a GET request to retrieve all the containers available.

            Args:
                instance_id (str): instance ID.

            Returns:
                tuple[list[dict], int]: a tuple containing the body response as a first arg,
                    and status code as second arg.
            """
            get_all_containers_url = config.GET_CONTAINERS_URL.format(instance_id=instance_id)
            logger.info(f"Send GET request, URL: {get_all_containers_url}")

            return execute_rest_api_func(url=get_all_containers_url, api_func=self._test_client.get)

        def get_one(self, instance_id, container_id):
            """
            Sends a GET request to retrieve get a single container.

            Args:
                instance_id (str): instance ID
                container_id (str): container ID.

            Returns:
                tuple[dict, int]: a tuple containing the body response as a first arg, and status code as second arg.
            """
            get_container_url = config.GET_CONTAINER_URL.format(instance_id=instance_id, container_id=container_id)
            logger.info(f"Send GET request, URL: {get_container_url}")

            return execute_rest_api_func(url=get_container_url, api_func=self._test_client.get)

        def delete(self, instance_id, container_id):
            """
            Sends a DELETE request to delete a single container.

            Args:
                instance_id (str): instance ID
                container_id (str): container ID.

            Returns:
                tuple[str, int]: a tuple containing the body response as first arg, and status code as second arg.
            """
            delete_container_url = config.DELETE_CONTAINER_URL.format(
                instance_id=instance_id, container_id=container_id
            )
            logger.info(f"Send DELETE request, URL: {delete_container_url}")

            return execute_rest_api_func(
                url=delete_container_url, api_func=self._test_client.delete, convert_func=to_utf8
            )

    return ContainerApi(test_client=test_client)
