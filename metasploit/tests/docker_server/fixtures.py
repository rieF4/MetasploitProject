import pytest
from metasploit.tests.test_wrapper import TestWrapper
from metasploit.tests.docker_server.docker_server_api import DockerServerApi


@pytest.fixture(scope="function")
def create_docker_server(request, test_client):
    """
    Creates a docker server instance via post request.

    Returns:
        list[tuple[dict, int]]: a list of tuples containing the data response and status code of each post request
            where the first argument in the tuple is the data and the second argument is the status code.

    """
    num_of_docker_servers_to_create = getattr(request.cls, "num_of_docker_servers_to_create", 1)
    docker_api_wrapper = TestWrapper(test_client=test_client, class_type=DockerServerApi)

    created_instances = docker_api_wrapper.post(
        num_of_docker_servers_to_create=num_of_docker_servers_to_create
    )

    def fin():
        """
        Deletes the docker server instances that were created.
        """
        for docker_response, _ in created_instances:
            instance_id = docker_response.get("_id")
            docker_api_wrapper.delete(instance_id=instance_id)
    request.addfinalizer(fin)

    return created_instances
