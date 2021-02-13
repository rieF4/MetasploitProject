import logging

from . import config


logger = logging.getLogger("DockerServerHelpers")


def is_docker_server_response_body_expected(docker_response, **expected):
    """
    validates whether a docker server response what's expected.

    Args:
        docker_response (dict): a response of a docker server from the API.

     Keyword arguments:
         containers (list[dict]): a list of expected containers.
         metasploit (list[dict]): a list of expected metasploit executions.
         state (dict): The expected state of the docker server

    Returns:
        bool: True if the docker response is as expected, False otherwise.

    """
    actual_containers = docker_response.get(config.CONTAINERS)
    expected_containers = expected.get("containers")

    if expected_containers is not None and actual_containers != expected_containers:
        logger.error(f"actual containers: {actual_containers}, expected containers: {expected_containers}")
        return False

    actual_metasploit = docker_response.get(config.METASPLOIT)
    excpected_metasploit = expected.get("metasploit", None)

    if excpected_metasploit is not None and actual_metasploit != excpected_metasploit:
        logger.error(f"actual metasploit: {actual_metasploit}, expected metasploit: {excpected_metasploit}")
        return False

    actual_state = docker_response.get(config.STATE)
    expected_state = expected.get("state")

    if expected_state is not None and actual_state != expected_state:
        logger.error(f"actual state: {actual_state}, expected state: {expected_state}")
        return False

    return True


def is_docker_server_response_body_valid(docker_server_data_response, **expected):
    """
    Validates that a response body of a docker server is valid.

    Args:
        docker_server_data_response (dict): a docker response body request.

    Keyword arguments:
         containers (list[dict]): a list of expected containers.
         metasploit (list[dict]): a list of expected metasploit executions.
         state (dict): The expected state of the docker server

    Returns:
        bool: True if docker server response is valid, False otherwise.
    """
    if config.CONTAINERS not in docker_server_data_response:
        logger.error(f"There is no Containers key in the docker response body {docker_server_data_response}")
        return False

    if config.METASPLOIT not in docker_server_data_response:
        logger.error(f"There is not Metasploit key in the docker response body {docker_server_data_response}")
        return False

    if config.IP_PARAMETERS not in docker_server_data_response:
        logger.error(f"There is no IpParameters key in the docker response body {docker_server_data_response}")
        return False

    if config.ID not in docker_server_data_response:
        logger.error(f"There is no _id key in the docker response body {docker_server_data_response}")
        return False

    if config.STATE not in docker_server_data_response:
        logger.error(f"There is no State key in the docker response body {docker_server_data_response}")
        return False

    return is_docker_server_response_body_expected(docker_response=docker_server_data_response, **expected)
