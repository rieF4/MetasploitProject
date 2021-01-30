import pytest
import logging

from metasploit.api.response import HttpCodes
from metasploit.tests.conftest import test_client  # noqa: F401
from metasploit.tests.helpers import (
    is_expected_code,
    is_error_response_valid,
    load_json
)

from .fixtures import (  # noqa: F401
    create_docker_servers,
    docker_server_ids
)
from .docker_server_api import docker_server_api  # noqa: F401
from . import config
from .helpers import is_docker_server_response_body_valid


logger = logging.getLogger("DockerServerTests")


class TestDockerServerPostApi(object):

    def test_create_docker_server_success(self, create_docker_servers):
        """
        Tests that creating a new docker server succeed with the correct response body and code.
        """
        created_instances = create_docker_servers

        for docker_server_body_response, actual_status_code in created_instances:

            is_response_valid = is_docker_server_response_body_valid(
                docker_server_data_response=docker_server_body_response,
                **config.EXPECTED_RESPONSE_FOR_NEW_DOCKER_SERVER
            )

            logger.info(f"Verify that the docker response {docker_server_body_response} is expected")
            assert is_response_valid, f"{docker_server_body_response} is not as expected"

            logger.info(f"Verify that status code is {HttpCodes.OK}")
            assert is_expected_code(actual_code=actual_status_code), (
                f"actual {actual_status_code}, expected {HttpCodes.OK}"
            )

    @pytest.mark.parametrize(
        "invalid_create_docker_request",
        [
            pytest.param(
                config.CREATE_DOCKER_REQUEST_EMPTY_JSON,
                id="Create_docker_server_with_empty_json"
            ),
            pytest.param(
                config.CREATE_DOCKER_REQUEST_WITHOUT_IMAGE_ID,
                id="Create_docker_server_without_imageID_parameter"
            ),
            pytest.param(
                config.CREATE_DOCKER_REQUEST_WITHOUT_INSTANCE_TYPE,
                id="Create_docker_server_without_instanceType_parameter"
            )
        ]
    )
    def test_create_docker_server_fails(self, invalid_create_docker_request, docker_server_api):
        """
        Tests scenarios where the POST request to create a docker server should fail.
        """
        response_body, actual_status_code = docker_server_api.post(
            create_docker_server_request=invalid_create_docker_request
        )

        assert is_error_response_valid(error_response=response_body, code=HttpCodes.BAD_REQUEST), (
            f"Response body {response_body} is not as expected"
        )

        logger.info(f"Verify that the status code is {HttpCodes.BAD_REQUEST}")
        assert actual_status_code == HttpCodes.BAD_REQUEST, (
            f"actual: {actual_status_code}, expected: {HttpCodes.BAD_REQUEST}"
        )


class TestDockerServerGetApi(object):

    num_of_docker_servers_to_create = 3

    def test_get_docker_servers_without_instances(self, docker_server_api):
        """
        Tests that given an empty DB without docker servers, GET all dockers servers brings back []
        """
        docker_servers, actual_status_code = docker_server_api.get_many()

        logger.info(f"Verify that response {docker_servers} == []")
        assert docker_servers == [], f"Failed to verify that docker servers is empty"

        logger.info(f"Verify that the status code is {HttpCodes.OK}")
        assert is_expected_code(actual_code=actual_status_code), (
            f"actual: {actual_status_code}, expected: {HttpCodes.OK}"
        )

    def test_get_single_docker_server_fails_without_instances(self, docker_server_api):
        """
        Tests that given an empty DB without docker servers, single GET response returns an error.
        """
        docker_server_body_response, actual_status_code = docker_server_api.get_one(
            instance_id=config.INVALID_INSTANCE_ID
        )

        assert is_error_response_valid(
            error_response=docker_server_body_response,
            code=HttpCodes.NOT_FOUND,
            message=config.INSTANCE_NOT_FOUND_MSG.format(invalid_instance_id=config.INVALID_INSTANCE_ID)
        ), f"Response body {docker_server_body_response} is not as expected"

        logger.info(f"Verify that the status code is {HttpCodes.NOT_FOUND}")
        assert is_expected_code(actual_code=actual_status_code, expected_code=HttpCodes.NOT_FOUND), (
             f"actual: {actual_status_code}, expected: {HttpCodes.NOT_FOUND}"
        )

    def test_get_single_new_docker_server_succeed(self, docker_server_ids, docker_server_api):
        """
        Tests that given a new docker server that was just created, a GET response is valid.
        """
        for docker_server_id in docker_server_ids:

            docker_server_body_response, actual_status_code = docker_server_api.get_one(instance_id=docker_server_id)

            is_response_valid = is_docker_server_response_body_valid(
                docker_server_data_response=docker_server_body_response,
                **config.EXPECTED_RESPONSE_FOR_NEW_DOCKER_SERVER
            )

            logger.info(f"Verify that the docker response {docker_server_body_response} is expected")
            assert is_response_valid, f"{docker_server_body_response} is not as expected"

            logger.info(f"Verify that status code is {HttpCodes.OK}")
            assert is_expected_code(actual_code=actual_status_code), (
                f"actual {actual_status_code}, expected {HttpCodes.OK}"
            )

    def test_get_many_new_docker_servers_succeed(self, docker_server_api):
        """
        Tests that given many new docker servers that were just created, a GET response is valid.
        """
        docker_servers, actual_status_code = docker_server_api.get_many()

        for docker_server_body_response in docker_servers:

            is_response_valid = is_docker_server_response_body_valid(
                docker_server_data_response=docker_server_body_response,
                **config.EXPECTED_RESPONSE_FOR_NEW_DOCKER_SERVER
            )

            logger.info(f"Verify that the docker response {docker_server_body_response} is expected")
            assert is_response_valid, f"{docker_server_body_response} is not as expected"

        logger.info(f"Verify that status code is {HttpCodes.OK}")
        assert is_expected_code(actual_code=actual_status_code), f"actual {actual_status_code}, expected {HttpCodes.OK}"


class TestDockerServerDeleteApi(object):

    is_delete_docker_server_required = False

    def test_delete_docker_server_fails(self, docker_server_api):
        """
        Tests that given an invalid docker server, DELETE operation fails.
        """
        docker_server_body_response, actual_status_code = docker_server_api.delete(
            instance_id=config.INVALID_INSTANCE_ID
        )
        if isinstance(docker_server_body_response, str):
            docker_server_body_response = load_json(string=docker_server_body_response)

        logger.info(f"Verify that DELETE body response {docker_server_body_response} is an ERROR")
        assert is_error_response_valid(
            error_response=docker_server_body_response,
            code=HttpCodes.NOT_FOUND,
            message=config.INSTANCE_NOT_FOUND_MSG.format(invalid_instance_id=config.INVALID_INSTANCE_ID)
        ), f"Response body {docker_server_body_response} is not as expected"

        logger.info(f"Verify that the DELETE response status code is {HttpCodes.NOT_FOUND}")
        assert is_expected_code(actual_code=actual_status_code, expected_code=HttpCodes.NOT_FOUND), (
            f"actual {actual_status_code}, expected {HttpCodes.NOT_FOUND}"
        )

    def test_delete_docker_server_succeed(self, docker_server_ids,  docker_server_api):
        """
        Tests that given a valid docker server, a DELETE response is valid.
        """
        for docker_server_id in docker_server_ids:
            docker_server_body_response, actual_status_code = docker_server_api.delete(instance_id=docker_server_id)

            logger.info(f"Verify that the DELETE body response is an empty string")
            assert docker_server_body_response == '', f"Failed to delete docker server {docker_server_id}"

            logger.info(f"Verify that the DELETE response status code is {HttpCodes.NO_CONTENT}")
            assert actual_status_code == HttpCodes.NO_CONTENT, (
                f"actual {actual_status_code}, expected {HttpCodes.NO_CONTENT}"
            )
