from metasploit.tests.conftest import test_client  # noqa: F401
from metasploit.tests.helpers import (
    is_docker_server_response_expected,
    is_expected_code
)
from assertpy import assert_that
from metasploit.tests.docker_server.docker_server_api import DockerServerApi
from metasploit.api.response import HttpCodes
from .fixtures import create_docker_server  # noqa: F401
import logging


logger = logging.getLogger("DockerServerTests")


class TestDockerServerApi(object):

    docker_server_api = DockerServerApi

    def test_create_docker_server_success(self, create_docker_server):
        """
        Tests that creating a new docker server succeed with the right response body and code.
        """
        created_instances = create_docker_server

        for docker_server_response, status_code in created_instances:

            logger.info(f"Verify that the docker instance response contains the right json keys")
            assert_that(
                val=docker_server_response, description="Docker instance response is not a valid response"
            ).contains("Containers", "Metasploit", "IpParameters", "State", "_id")

            is_response_valid, err_msg = is_docker_server_response_expected(
                docker_response=docker_server_response,
                containers=[],
                metasploit=[],
                state={"Code": 16, "Name": "running"}
            )

            logger.info(f"Verify that the docker response {docker_server_response} is valid")
            assert is_response_valid, err_msg

            logger.info(f"Verify that status code {status_code} is valid")
            assert is_expected_code(actual_code=status_code), f"actual {status_code}, expected {HttpCodes.OK}"
