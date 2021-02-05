import logging

from metasploit.api.response import create_new_response
from metasploit.api.docker.docker_operations import ContainerOperations

logger = logging.getLogger("ContainerHelpers")


def is_container_body_response_expected(container_response_body, **expected):
    """
    Validates whether a container response body is valid.

    Args:
        container_response_body (dict): container response body from the API.

    Keyword arguments:
        id (int): expected container ID.
        image (list): expected image.
        name (str): expected name.
        ports (dict): expected ports.
        status (str): expected status.

    Returns:
        bool: True if the response body params are as expected, False otherwise.
    """

    actual_container_id = container_response_body.get("_id")
    expected_container_id = expected.get("id")

    if expected_container_id is not None and actual_container_id != expected_container_id:
        logger.error(f"actual container ID: {actual_container_id}, expected container ID: {expected_container_id}")
        return False

    actual_container_image = container_response_body.get("image")
    expected_container_image = expected.get("image")

    if expected_container_image is not None and actual_container_image != expected_container_image:
        logger.error(
            f"actual container image: {actual_container_image}, expected container image: {expected_container_image}"
        )
        return False

    actual_container_name = container_response_body.get("name")
    expected_container_name = expected.get("name")

    if expected_container_name is not None and actual_container_name != expected_container_name:
        logger.error(
            f"actual container name: {actual_container_name}, expected container name: {expected_container_name}"
        )
        return False

    actual_container_ports = container_response_body.get("ports")
    expected_container_ports = expected.get("ports")

    if expected_container_ports is not None and actual_container_ports != expected_container_ports:
        logger.error(
            f"actual container ports: {actual_container_ports}, expected container ports: {expected_container_ports}"
        )
        return False

    actual_container_state = container_response_body.get("state")
    expected_container_state = expected.get("state")

    if expected_container_state is not None and actual_container_state != expected_container_state:
        logger.error(
            f"actual container state: {actual_container_state}, expected container state: {expected_container_state}"
        )
        return False

    return True


def is_container_response_valid(container_response_body, **expected):
    """
    Validates whether a container response body is valid.

    Args:
        container_response_body (dict): container response body from the API.

    Keyword arguments:
         id (int): expected container ID.
         image (list): expected image.
         name (str): expected name.
         ports (dict): expected ports.
         status (str): expected status.

    Returns:
        bool: True if the response body is as expected, False otherwise.
    """
    if "_id" not in container_response_body:
        logger.error(f"There is no _id key in the container response body {container_response_body}")
        return False

    if "image" not in container_response_body:
        logger.error(f"There is no image key in the container response body {container_response_body}")
        return False

    if "name" not in container_response_body:
        logger.error(f"There is no name key in the container response body {container_response_body}")
        return False

    if "ports" not in container_response_body:
        logger.error(f"There is no ports key in the container response body {container_response_body}")
        return False

    if "status" not in container_response_body:
        logger.error(f"There is no status key in the container response body {container_response_body}")
        return False

    return is_container_body_response_expected(container_response_body, **expected)


def get_container_expected_response(instance_id, container_id):
    """
    Returns the expected container response from the API.

    Args:
        instance_id (str): instance ID.
        container_id (str): container ID.

    Returns:
        dict: expected container response from the API.
    """
    return create_new_response(
        obj=ContainerOperations(
            docker_server_id=instance_id, docker_resource_id=container_id
        ).container, response_type='Container'
    )


def get_container_id_from_container_response(container_body_response):
    """
    Extract the container ID from the container body response.

    Args:
        container_body_response (dict): container body response.

    Returns:
        str: container ID that matches the container body response in case exists, None otherwise.
    """
    return container_body_response.get("_id")
