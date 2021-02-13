import logging
import pytest

from metasploit.tests.test_wrapper import MetasploitApiInterface
from metasploit.tests.helpers import execute_rest_api_func

from . import config

logger = logging.getLogger("MetasploitApi")


@pytest.fixture(scope="class")
def metasploit_api(test_client):
    """
    This fixture provides the MetasploitApi object in order to make API calls.

    Returns:
        MetasploitApi: a metasploit api object.
    """
    class MetasploitApi(MetasploitApiInterface):

        def post(self, instance_id, execute_exploit_body_request, execute_exploit_url=config.EXECUTE_EXPLOIT_URL):
            """
            Sends a POST request in order to run an exploit.

            Args:
                instance_id (str): instance ID.
                execute_exploit_body_request (dict): a body request to run an exploit.
                execute_exploit_url (str): the url to run the exploit.

            Returns:
                tuple[dict, int]: a tuple containing the body response as a first arg, and status code as second arg.
            """
            execute_exploit_url = execute_exploit_url.format(instance_id=instance_id)
            logger.info(f"Send POST request, URL: {execute_exploit_url}, REQUEST: {execute_exploit_body_request}")

            return execute_rest_api_func(
                url=execute_exploit_url, api_func=self._test_client.post, request_body=execute_exploit_body_request
            )

        def scan_ports(self, instance_id, target_host, scan_ports_url=config.SCAN_PORTS_URL):
            """
            Sends a GET request in order to scan ports on a remote host.

            Args:
                instance_id (str): instance ID.
                target_host (str): target host remote IP/DNS.
                scan_ports_url (str): scan ports url.

            Returns:
                tuple[dict, int]: a tuple containing the body response as a first arg, and status code as second arg.
            """
            scan_ports_url = scan_ports_url.format(instance_id=instance_id, target_host=target_host)
            logger.info(f"Send GET request, URL: {scan_ports_url}")

            return execute_rest_api_func(url=scan_ports_url, api_func=self._test_client.get)

        def get_exploit(self, instance_id, exploit_name, get_exploit_url=config.GET_EXPLOIT_URL):
            """
            Sends a GET request in order to get exploit information from metasploit.

            Args:
                instance_id (str): instance ID.
                exploit_name (str): exploit name.
                get_exploit_url (str): get exploit information url.

            Returns:
                tuple[dict, int]: a tuple containing the body response as a first arg, and status code as second arg.
            """
            get_exploit_url = get_exploit_url.format(instance_id=instance_id, exploit_name=exploit_name)
            logger.info(f"Send GET request, URL: {get_exploit_url}")

            return execute_rest_api_func(url=get_exploit_url, api_func=self._test_client.get)

        def get_payload(self, instance_id, payload_name, get_payload_url=config.GET_PAYLOAD_URL):
            """
            Sends a GET request in order to get payload information from metasploit.

            Args:
                instance_id (str): instance ID.
                payload_name (str): payload name.
                get_payload_url (str): get payload information url.

            Returns:
                tuple[dict, int]: a tuple containing the body response as a first arg, and status code as second arg.
            """
            get_payload_url = get_payload_url.format(instance_id=instance_id, payload_name=payload_name)
            logger.info(f"Send GET request, URL: {get_payload_url}")

            return execute_rest_api_func(url=get_payload_url, api_func=self._test_client.get)

    return MetasploitApi(test_client=test_client)
