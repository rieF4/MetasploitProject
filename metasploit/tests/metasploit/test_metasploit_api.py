import pytest
import logging

from metasploit.api.response import HttpCodes
from metasploit.tests.conftest import test_client  # noqa: F401
from metasploit.tests.helpers import (
    is_expected_code,
    is_error_response_valid,
    load_json
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
                config.INVALID_WWW_HOST_NAME,
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
            assert is_error_response_valid(error_response=response_body, code=HttpCodes.BAD_REQUEST)

            logger.info(f"Verify the status code is {HttpCodes.BAD_REQUEST}")
            assert is_expected_code(actual_code=actual_status_code, expected_code=HttpCodes.BAD_REQUEST)
