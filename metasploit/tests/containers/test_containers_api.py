import logging

from metasploit.api.response import HttpCodes
from metasploit.tests.conftest import test_client  # noqa: F401
from metasploit.tests.helpers import (
    is_expected_code,
)

from metasploit.tests.docker_server.fixtures import (  # noqa: F401
    docker_server_ids,
    create_docker_servers
)
from metasploit.tests.docker_server.docker_server_api import docker_server_api  # noqa: F401

from .containers_api import container_api  # noqa: F401
from . import config
from .helpers import is_container_response_valid


logger = logging.getLogger("ContainerApiTests")


class TestMetasploitContainerPostApi(object):

    def test_create_metasploit_container_succeed(self, docker_server_ids, container_api):
        """
        Tests that creating a new metasploit container succeed with the correct response body and code.
        """
        for docker_server_id in docker_server_ids:

            body_response, actual_status_code = container_api.post(instance_id=docker_server_id)

            logger.info(f"Verify that container body response {body_response} is valid")
            assert is_container_response_valid(
                container_response_body=body_response, **config.EXPECTED_NEW_CONTAINER_RESPONSE
            )

            logger.info(f"Verify the status code is {HttpCodes.OK}")
            assert is_expected_code(actual_code=actual_status_code), (
                f"actual: {actual_status_code}, expected: {HttpCodes.OK}"
            )
