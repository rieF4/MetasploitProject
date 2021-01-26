import pytest
import logging

from metasploit.api.response import HttpCodes


logger = logging.getLogger("docker_api_fixtures")


@pytest.fixture(scope="class")
def create_docker_servers(request, docker_server_api):
    """
    Creates a docker server instance via post request.

    Returns:
        list[tuple[dict, int]]: a list of tuples containing the data response and status code of each post request
            where the first argument in the tuple is the data and the second argument is the status code.

    """
    num_of_docker_servers_to_create = getattr(request.cls, "num_of_docker_servers_to_create", 1)
    is_delete_docker_server_required = getattr(request.cls, "is_delete_docker_server_required", True)

    created_instances = []
    instances_to_remove = []

    def fin():
        """
        Deletes the docker server instances that were created.
        """
        if is_delete_docker_server_required:
            for instance_id in instances_to_remove:
                err_msg = f"Failed to delete docker server ID {instance_id}"

                logger.info(f"Delete docker server ID {instance_id}")
                response, code = docker_server_api.delete(instance_id=instance_id)

                assert code == HttpCodes.NO_CONTENT, err_msg
                assert response == '', err_msg
    request.addfinalizer(fin)

    for docker_num in range(1, num_of_docker_servers_to_create + 1):
        logger.info(f"Create docker server number {docker_num}")
        new_instance_response, status_code = docker_server_api.post()

        created_instances.append((new_instance_response, status_code))

        if "_id" in new_instance_response:
            instances_to_remove.append(new_instance_response.get('_id'))

    return created_instances


@pytest.fixture(scope="class")
def docker_server_ids(create_docker_servers):
    """
    Get the docker server IDS of all the created docker servers.

    Returns:
        list: a list of docker server instance IDs
    """
    return [new_instance_response.get("_id") for new_instance_response, _ in create_docker_servers]
