import pytest
import logging

from metasploit.api.response import HttpCodes


logger = logging.getLogger("docker_api_fixtures")


@pytest.fixture(scope="function")
def create_docker_servers(request, docker_server_api):
    """
    Creates a docker server instance via post request.

    Returns:
        list[tuple[dict, int]]: a list of tuples containing the data response and status code of each post request
            where the first argument in the tuple is the data and the second argument is the status code.

    """
    num_of_docker_servers_to_create = getattr(request.cls, "num_of_docker_servers_to_create", 1)

    created_instances = []
    instances_to_remove = []

    def fin():
        """
        Deletes the docker server instances that were created.
        """
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


@pytest.fixture(scope="function")
def set_number_of_dockers_servers(request):
    """
    Sets the number of docker servers to create for the 'create_docker_servers' fixture
    """
    request.node.cls.num_of_docker_servers_to_create = 3
