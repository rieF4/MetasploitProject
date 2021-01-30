import pytest
import logging


logger = logging.getLogger("DockerApiFixtures")


@pytest.fixture(scope="class")
def create_containers(request, docker_server_ids, container_api):
    """
    Create new metasploit containers over the docker servers.

    Returns:
        dict[str, tuple[dict, int]]: a dict that contains docker server ID as key, and a full container response as val.
    """
    num_of_containers_to_create = getattr(request.cls, "num_of_containers_to_create", 1)
    new_containers = {}

    for docker_server_id in docker_server_ids:

        new_containers[docker_server_id] = []
        for container_num in range(1, num_of_containers_to_create + 1):

            logger.info(f"Create metasploit container number {container_num} in docker server {docker_server_id}")
            body_response, status_code = container_api.post(instance_id=docker_server_id)

            new_containers[docker_server_id].append((body_response, status_code))
    return new_containers


@pytest.fixture(scope="class")
def docker_server_ids_and_container_ids(create_containers):
    """
    Returns a mapping of docker server ids to the IDs of all the newly created containers.

    Returns:
        dict[str, list[str]]: a dict where the key is the docker server ID and
            the value is a list of all the container IDs that belong to that docker server.
    """
    return {
        docker_server_id: [
            new_container_response["_id"] for new_container_response, _ in container_response
        ] for docker_server_id, container_response in create_containers.items()
    }
