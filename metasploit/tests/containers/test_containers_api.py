import logging
import pytest

from metasploit.api.response import HttpCodes
from metasploit.tests.conftest import test_client  # noqa: F401
from metasploit.tests.helpers import (
    is_expected_code,
    is_error_response_valid
)
from metasploit.tests.docker_server import config as docker_server_config

from metasploit.tests.docker_server.fixtures import (  # noqa: F401
    docker_server_ids,
    create_docker_servers,
    stop_docker_daemon,
    docker_server_dns
)
from metasploit.tests.docker_server.docker_server_api import docker_server_api  # noqa: F401

from .containers_api import container_api  # noqa: F401
from . import config
from .helpers import is_container_response_valid


logger = logging.getLogger("ContainerApiTests")


class TestMetasploitContainerPostApi(object):

    def test_create_metasploit_container_fails(self, container_api):
        """
        Tests that given an invalid docker server ID, creating a metasploit container should fail.
        """
        body_response, actual_status_code = container_api.post(instance_id=docker_server_config.INVALID_INSTANCE_ID)

        logger.info(f"Verify that {body_response} is an ERROR")
        assert is_error_response_valid(error_response=body_response, code=HttpCodes.NOT_FOUND), (
            f"Response {body_response} is not an ERROR"
        )

        logger.info(f"Verify that status code is {HttpCodes.NOT_FOUND}")
        assert is_expected_code(actual_code=actual_status_code, expected_code=HttpCodes.NOT_FOUND)

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


class TestDockerDaemonRecover(object):

    num_of_docker_servers_to_create = 2

    @pytest.mark.usefixtures(
        stop_docker_daemon.__name__
    )
    def test_docker_daemon_start(self, docker_server_ids, container_api):
        """
        Tests that given the docker daemon is down, if the server is able to recover it and create a container.
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
