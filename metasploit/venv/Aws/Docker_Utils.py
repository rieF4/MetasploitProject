from metasploit.venv.Aws.Aws_Api_Functions import (
    get_docker_server_instance
)


def create_container(instance, image, command, kwargs):
    """
    Creates a container over an instance ID. Similar to Docker create shell command.

    Args:
        instance (DockerServerInstance): instance docker server object.
        image (str): image name that the docker will be created with.
        command (str): the command to run on the container.
        kwargs (dict): Keyword arguments: https://docker-py.readthedocs.io/en/stable/containers.html#container-objects

    Returns:
        Container: a container object if created successfully.

    Raises:
        ImageNotFound: in case the image was not found on the docker server.
        ApiError: In case the docker server returns an error.
    """
    return instance.get_docker().get_container_collection().create(image=image, command=command, **kwargs)


def get_container(instance_id, container_id):
    """
    Get container object by instance and container IDs.

    Args:
         instance_id (str): instance ID.
         container_id (str): container ID.

    Returns:
        Container: a container object if found.

    Raises:
        ApiError: in case the docker server returns an error.
    """
    return get_docker_server_instance(id=instance_id).get_docker().get_container_collection().get(
        container_id=container_id
    )


def pull_image(instance, repository, tag=None, **kwargs):
    """
    Pull an image of the given name and return it.
    Similar to the docker pull command. If no tag is specified, all tags from that repository will be pulled.

    Args:
        instance (DockerServerInstance): a docker server instance object.
        repository (str) – The repository to pull.
        tag (str) – The tag to pull.

        Keyword Args:
            auth_config (dict) – Override the credentials that are found in the config for this request.
            auth_config should contain the username and password keys to be valid.
            platform (str) – Platform in the format os[/arch[/variant]].

    Returns: Image or list: The image that has been pulled.
             If no tag was specified, the method will return a list of Image objects belonging to this repository.

    Raises:
        ApiError: If the server returns an error.
    """
    return instance.get_docker().get_image_collection().pull(repository=repository, tag=tag, **kwargs)
