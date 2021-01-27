import logging
import pytest

from metasploit.tests.test_wrapper import BaseApiInterface
from metasploit.tests import constants as test_const
from metasploit.tests.helpers import (
    convert,
    to_utf8
)
from metasploit.tests.helpers import execute_rest_api_func

logger = logging.getLogger("ContainersApi")


@pytest.fixture(scope="class")
def container_api(test_client):
    """
    This fixture provides the ContainerApi object in order to make API calls.

    Returns:
        ContainerApi: a container api object.
    """
    class ContainerApi(BaseApiInterface):

        def post(self, instance_id, create_msfrpcd_container_url=test_const.CREATE_MSFRPCD_CONTAINER):
            """
            Sends a POST request in order to create a metasploit based image container.

            Args:
                instance_id (str): instance ID that the container will be created on.
                create_msfrpcd_container_url (str): URL for the POST request to create the container.

            Returns:
                tuple[dict, int]: a tuple containing the data response as a first arg, and status code as second arg.
            """
            create_msfrpcd_container_url = create_msfrpcd_container_url.format(instance_id=instance_id)
            logger.info(f"Send POST request, URL: {create_msfrpcd_container_url}")

            return execute_rest_api_func(url=create_msfrpcd_container_url, api_func=self._test_client.post)

        def get_many(self, instance_id):
            """
            Sends a GET request to retrieve all the docker server instances available.

            Args:
                instance_id (str): instance ID.

            Returns:
                tuple[list[dict], int]: a tuple containing the data response as a first arg,
                    and status code as second arg.
            """
            get_all_containers_url = test_const.GET_CONTAINERS.format(instance_id=instance_id)
            logger.info(f"Send GET request, URL: {get_all_containers_url}")

            return execute_rest_api_func(url=get_all_containers_url, api_func=self._test_client)
