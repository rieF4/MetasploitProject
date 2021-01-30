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
from .helpers import (
    is_container_response_valid,
    get_container_expected_response,
    get_container_id_from_container_response
)
from .fixtures import (  # noqa: F401
    create_containers,
    docker_server_ids_and_container_ids
)


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
            container_id = get_container_id_from_container_response(container_body_response=body_response)
            assert container_id, f"Failed to get container ID from {body_response}"

            logger.info(f"Verify that container body response {body_response} is valid")
            assert is_container_response_valid(
                container_response_body=body_response,
                **get_container_expected_response(instance_id=docker_server_id, container_id=container_id)
            )

            logger.info(f"Verify the status code is {HttpCodes.OK}")
            assert is_expected_code(actual_code=actual_status_code), (
                f"actual: {actual_status_code}, expected: {HttpCodes.OK}"
            )


class TestMetasploitContainerGetApi(object):

    num_of_docker_servers_to_create = 2
    num_of_containers_to_create = 2

    def test_get_container_fails(self, docker_server_ids, container_api):
        """
        Tests that given an invalid container ID, the server returns Error response body and 404.
        """
        for docker_server_id in docker_server_ids:
            response_body, actual_status_code = container_api.get_one(
                instance_id=docker_server_id, container_id=config.INVALID_CONTAINER_ID
            )

            logger.info(f"Verify that response body {response_body} is an ERROR")
            assert is_error_response_valid(
                error_response=response_body,
                code=HttpCodes.NOT_FOUND,
                message=f"404 Client error: Container with ID {config.INVALID_CONTAINER_ID} was not found"
            ), f"Failed to validate that {response_body} is an ERROR"

            logger.info(f"Verify the status code is {HttpCodes.NOT_FOUND}")
            assert is_expected_code(actual_code=actual_status_code, expected_code=HttpCodes.NOT_FOUND), (
                f"actual code: {actual_status_code}, expected code: {HttpCodes.NOT_FOUND}"
            )

    def test_get_all_containers_empty(self, docker_server_ids, container_api):
        """
        Tests that given a docker server without containers, GET all containers returns []
        """
        for docker_server_id in docker_server_ids:
            response_body, actual_status_code = container_api.get_many(instance_id=docker_server_id)

            logger.info(f"Verify response body {response_body} == []")
            assert response_body == [], f"Failed to validate containers are empty"

            logger.info(f"Verify the status code is {HttpCodes.OK}")
            assert is_expected_code(actual_code=actual_status_code, expected_code=HttpCodes.OK)

    def test_get_container_succeed(self, docker_server_ids_and_container_ids, container_api):
        """
        Tests that given a docker server with containers, GET of a single container gives a valid container response.
        """
        for docker_server_id, container_ids in docker_server_ids_and_container_ids.items():

            for container_id in container_ids:

                body_response, actual_status_code = container_api.get_one(
                    instance_id=docker_server_id, container_id=container_id
                )

                assert isinstance(body_response, dict), f"response {body_response} is not a dict!"

                logger.info(f"Verify that container body response {body_response} is valid")
                assert is_container_response_valid(
                    container_response_body=body_response,
                    **get_container_expected_response(instance_id=docker_server_id, container_id=container_id)
                )

                logger.info(f"Verify the status code is {HttpCodes.OK}")
                assert is_expected_code(actual_code=actual_status_code), (
                    f"actual: {actual_status_code}, expected: {HttpCodes.OK}"
                )

    def test_get_all_containers_succeed(self, docker_server_ids, container_api):
        """
        Tests that given new containers in a docker servers, GET all containers returns all of them.
        """
        for docker_server_id in docker_server_ids:

            all_containers_response, actual_status_code = container_api.get_many(instance_id=docker_server_id)
            assert isinstance(all_containers_response, list), f"{all_containers_response} is not a list"
            assert len(all_containers_response) == self.num_of_containers_to_create, (
                f"actual number of containers {len(all_containers_response)}, "
                f"expected number of containers {self.num_of_containers_to_create}"
            )

            for single_container_response in all_containers_response:

                container_id = get_container_id_from_container_response(
                    container_body_response=single_container_response
                )
                assert container_id, f"Failed to get container ID from {single_container_response}"

                assert isinstance(single_container_response, dict), (
                    f"response {single_container_response} is not a dict!"
                )

                logger.info(f"Verify that {single_container_response} is a valid response")
                assert is_container_response_valid(
                    container_response_body=single_container_response,
                    **get_container_expected_response(instance_id=docker_server_id, container_id=container_id)
                )

            logger.info(f"Verify the status code is {actual_status_code}")
            assert is_expected_code(actual_code=actual_status_code, expected_code=HttpCodes.OK)


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
