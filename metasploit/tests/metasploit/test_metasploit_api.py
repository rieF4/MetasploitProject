import pytest
import logging
import socket
import re

from metasploit.api.response import HttpCodes
from metasploit.tests.conftest import test_client  # noqa: F401
from metasploit.tests.helpers import (
    is_expected_code,
    is_error_response_valid
)

from ..containers.fixtures import (  # noqa: F401
    create_containers,
    docker_server_ids_and_container_ids
)
from ..docker_server.fixtures import (  # noqa: F401
    docker_server_ids,
    create_docker_servers
)
from ..docker_server.docker_server_api import docker_server_api  # noqa: F401
from ..containers.containers_api import container_api  # noqa: F401

from . import config
from .metasploit_api import metasploit_api  # noqa: F401
from .helpers import is_exploit_name_response_valid, is_payload_name_response_valid


logger = logging.getLogger("MetasploitTests")


@pytest.mark.usefixtures(
    create_containers.__name__
)
class TestScanPortsApi(object):

    @pytest.mark.parametrize(
        "invalid_target_name",
        [
            pytest.param(
                config.INVALID_IP_ADDRESS,
                id="Scan_ports_of_invalid_ip_address"
            ),
            pytest.param(
                config.INVALID_DOMAIN_NAME,
                id="Scan_ports_of_invalid_domain_name"
            ),
            pytest.param(
                config.INVALID_HOST_NAME,
                id="Scan_ports_of_invalid_random_host_name"
            )
        ]
    )
    def test_scan_ports_with_invalid_target_host(self, invalid_target_name, docker_server_ids, metasploit_api):
        """
        Tests scenarios where the port scanning invalid host names
        should return an error response body and a bad request.
        """
        for docker_server_id in docker_server_ids:

            logger.info(f"Scan ports, instance: {docker_server_id}, target: {invalid_target_name}")
            response_body, actual_status_code = metasploit_api.scan_ports(
                instance_id=docker_server_id, target_host=invalid_target_name
            )

            logger.info(f"Verify scan ports of {invalid_target_name} on instance {docker_server_id} failed")
            assert is_error_response_valid(error_response=response_body, code=HttpCodes.BAD_REQUEST), (
                f"Failed to verify that response {response_body} is an ERROR"
            )

            logger.info(f"Verify the status code is {HttpCodes.BAD_REQUEST}")
            assert is_expected_code(actual_code=actual_status_code, expected_code=HttpCodes.BAD_REQUEST), (
                f"actual {actual_status_code}, expected: {HttpCodes.BAD_REQUEST}"
            )

    @pytest.mark.parametrize(
        "target_host",
        [
            pytest.param(
                config.VALID_HOST_NAME_1,
                id="Scan_ports_of_google_dns_server"
            ),
            pytest.param(
                config.VALID_HOST_NAME_2,
                id="Scan_ports_of_itsecgames"
            ),
            pytest.param(
                config.VALID_HOST_NAME_3,
                id="Scan_ports_of_defendtheweb"
            ),
            pytest.param(
                config.VALID_HOST_NAME_4,
                id="Scan_ports_of_google-gruyere.appspot"
            ),
            pytest.param(
                config.VALID_IP_ADDRESS_5,
                id=f"Scan_ports_of_{config.VALID_IP_ADDRESS_5}"
            )
        ]
    )
    def test_scan_ports_success(self, target_host, docker_server_ids, metasploit_api):
        """
        Tests scenarios where the port scanning of valid target host should be success.
        """
        for docker_server_id in docker_server_ids:

            logger.info(f"Scan ports, instance: {docker_server_id}, target: {target_host}")
            response_body, actual_status_code = metasploit_api.scan_ports(
                instance_id=docker_server_id, target_host=target_host
            )

            logger.info(f"Verify that response body {response_body} is a list")
            assert isinstance(response_body, list), f"response body {response_body} is not a list."

            logger.info(f"Verify that response body {response_body} is not empty")
            assert response_body != [], f"Failed to verify that {response_body} is not empty"

            target_ip = socket.gethostbyname(target_host)

            logger.info(f"Verify that response body {response_body} contains IP {target_ip} with a valid port")
            actual_response = re.findall(pattern=f"{target_ip}:[0-9]+", string=" ".join(response_body))
            assert len(actual_response) == len(response_body), f"actual {actual_response}, expected {response_body}"

            logger.info(f"Verify the status code is {HttpCodes.OK}")
            assert is_expected_code(actual_code=actual_status_code), (
                f"actual {actual_status_code}, expected {HttpCodes.OK}"
            )


@pytest.mark.usefixtures(
    create_containers.__name__
)
class TestGetExploitApi(object):

    @pytest.mark.parametrize(
        "invalid_exploit_name",
        [
            pytest.param(
                config.INVALID_EXPLOIT_NAME_1,
                id="get_exploit_of_invalid_exploit_with_dots"
            ),
            pytest.param(
                config.INVALID_EXPLOIT_NAME_2,
                id="get_exploit_of_invalid_exploit_with_/"
            ),
            pytest.param(
                config.INVALID_EXPLOIT_NAME_3,
                id="get_exploit_of_invalid_exploit_name_that_does_not_exist"
            )
        ]
    )
    def test_get_invalid_exploit_name(self, invalid_exploit_name, docker_server_ids, metasploit_api):
        """
        Tests scenarios where trying to get invalid exploit names should fail.
        """
        for docker_server_id in docker_server_ids:

            logger.info(f"Get exploit {invalid_exploit_name} in instance {docker_server_id}")
            response_body, actual_status_code = metasploit_api.get_exploit(
                instance_id=docker_server_id, exploit_name=invalid_exploit_name
            )

            logger.info(f"Verify get exploit of {invalid_exploit_name} on instance {docker_server_id} failed")
            assert is_error_response_valid(error_response=response_body, code=HttpCodes.BAD_REQUEST), (
                f"Failed to verify that {response_body} is an ERROR"
            )

            logger.info(f"Verify the status code is {HttpCodes.BAD_REQUEST}")
            assert is_expected_code(actual_code=actual_status_code, expected_code=HttpCodes.BAD_REQUEST), (
                f"actual {actual_status_code}, expected {HttpCodes.BAD_REQUEST}"
            )

    @pytest.mark.parametrize(
        "exploit_name",
        [
            pytest.param(
                config.VALID_EXPLOIT_NAME_1,
                id="get_exploit_details_of_a_windows_exploit"
            ),
            pytest.param(
                config.VALID_EXPLOIT_NAME_2,
                id="get_exploit_details_of_a_aix_exploit"
            ),
            pytest.param(
                config.VALID_EXPLOIT_NAME_3,
                id="get_exploit_details_of_a_unix_exploit"
            )
        ]
    )
    def test_get_exploit_name_success(self, exploit_name, docker_server_ids, metasploit_api):
        """
        Tests scenarios where trying to get a valid exploit names should succeed.
        """
        for docker_server_id in docker_server_ids:

            logger.info(f"Get exploit {exploit_name} in instance {docker_server_id}")
            response_body, actual_status_code = metasploit_api.get_exploit(
                instance_id=docker_server_id, exploit_name=exploit_name
            )

            logger.info(f"Verify get exploit of {exploit_name} on instance {docker_server_id} succeeded")
            assert is_exploit_name_response_valid(exploit_details_body_response=response_body), (
                f"Exploit details response {response_body} is not valid"
            )

            logger.info(f"Verify the status code is {HttpCodes.OK}")
            assert is_expected_code(actual_code=actual_status_code), (
                f"actual {actual_status_code}, expected {HttpCodes.OK}"
            )


@pytest.mark.usefixtures(
    create_containers.__name__
)
class TestGetPayloadApi(object):

    @pytest.mark.parametrize(
        "invalid_payload_name",
        [
            pytest.param(
                config.INVALID_PAYLOAD_NAME_1,
                id="get_payload_of_invalid_payload_with_dots"
            ),
            pytest.param(
                config.INVALID_PAYLOAD_NAME_2,
                id="get_payload_of_invalid_payload_with_/"
            ),
            pytest.param(
                config.INVALID_PAYLOAD_NAME_3,
                id="get_payload_of_invalid_payload_name_that_does_not_exist"
            )
        ]
    )
    def test_get_invalid_payload_name(self, invalid_payload_name, docker_server_ids, metasploit_api):
        """
        Tests scenarios where trying to get invalid payload names should fail.
        """
        for docker_server_id in docker_server_ids:

            response_body, actual_status_code = metasploit_api.get_payload(
                instance_id=docker_server_id, payload_name=invalid_payload_name
            )

            logger.info(f"Verify get payload of {invalid_payload_name} on instance {docker_server_id} failed")
            assert is_error_response_valid(error_response=response_body, code=HttpCodes.BAD_REQUEST), (
                f"Failed to verify that {response_body} is an ERROR"
            )

            logger.info(f"Verify the status code is {HttpCodes.BAD_REQUEST}")
            assert is_expected_code(actual_code=actual_status_code, expected_code=HttpCodes.BAD_REQUEST), (
                f"actual {actual_status_code}, expected {HttpCodes.BAD_REQUEST}"
            )

    @pytest.mark.parametrize(
        "payload_name",
        [
            pytest.param(
                config.VALID_PAYLOAD_NAME_1,
                id="get_payload_details_of_a_windows_payload"
            ),
            pytest.param(
                config.VALID_PAYLOAD_NAME_2,
                id="get_payload_details_of_a_unix_payload"
            ),
            pytest.param(
                config.VALID_PAYLOAD_NAME_3,
                id="get_payload_details_of_a_generic_payload"
            )
        ]
    )
    def test_get_payload_name_success(self, payload_name, docker_server_ids, metasploit_api):
        """
        Tests scenarios where trying to get a valid payload names should succeed.
        """
        for docker_server_id in docker_server_ids:
            logger.info(f"Get payload {payload_name} in instance {docker_server_id}")
            response_body, actual_status_code = metasploit_api.get_payload(
                instance_id=docker_server_id, payload_name=payload_name
            )

            logger.info(f"Verify get payload of {payload_name} on instance {docker_server_id} succeeded")
            assert is_payload_name_response_valid(payload_details_response_body=response_body), (
                f"Payload details response {response_body} is not valid"
            )

            logger.info(f"Verify the status code is {HttpCodes.OK}")
            assert is_expected_code(actual_code=actual_status_code), (
                f"actual {actual_status_code}, expected {HttpCodes.OK}"
            )


