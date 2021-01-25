import json
import logging
from metasploit.api.response import HttpCodes

from . import constants as test_const


logger = logging.getLogger("is_response_expected")


def to_utf8(response_as_bytes):
    """
    Converts bytes into a utf-8 string.

    Args:
        response_as_bytes (bytes): the bytes to convert to utf-8

    Returns:
        str: a utf-8 string.
    """
    return response_as_bytes.decode('utf-8')


def load_json(string):
    """
    Converts a string to a valid data type e.g.: dict, list.

    Args:
        string (str): a string representing a rest api response

    Returns:
        a valid data type. e.g.: list, dict.
    """
    return json.loads(string)


def convert(response_as_bytes):
    """
    converts the response from the API into a valid data type.

    Args:
        the bytes to convert into a valid data type.

    Returns:
        a valid data type. e.g.: list, dict.
    """
    return load_json(to_utf8(response_as_bytes=response_as_bytes))


def is_expected_code(actual_code, expected_code=HttpCodes.OK):
    """
    Checks whether the status code is what's expected.

    Args:
        actual_code (int): actual code from the API.
        expected_code (int): excpected code from the API.
    """
    return expected_code == actual_code


def is_docker_server_response_expected(docker_response, **expected):
    """
    validates whether a docker server response what's expected.

    Args:
        docker_response (dict): a response of a docker server from the API.

     Keyword arguments:
         containers (list(dict)): a list of expected containers.
         metasploit (list(dict)): a list of expected metasploit executions.
         state (dict): The expected state of the docker server

    """
    actual_containers = docker_response.get(test_const.CONTAINERS)
    expected_containers = expected.get("containers", False)

    if expected_containers:
        if actual_containers != expected_containers:
            logger.error(f"actual: {actual_containers}, expected: {expected_containers}")
            return False, f"actual: {actual_containers}, expected: {expected_containers}"

    actual_metasploit = docker_response.get(test_const.METASPLOIT)
    excpected_metasploit = expected.get("metasploit", False)

    if excpected_metasploit:
        if actual_metasploit != excpected_metasploit:
            logger.error(f"actual: {actual_metasploit}, expected: {excpected_metasploit}")
            return False, f"actual: {actual_metasploit}, expected: {excpected_metasploit}"

    actual_state = docker_response.get(test_const.STATE)
    expected_state = expected.get("state", False)

    if expected_state:
        if actual_state != expected_state:
            logger.error(f"actual: {actual_state}, expected: {expected_state}")
            return False, f"actual: {actual_state}, expected: {expected_state}"

    return True, ""

