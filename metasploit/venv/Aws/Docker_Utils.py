from metasploit.venv.Aws.Aws_Api_Functions import (
    get_docker_server_instance
)


def create_container(instance, image, command, kwargs):
    """
    Creates a container over an instance ID. Similar to Docker create shell command.

    Args:
        instance (DockerServerInstance): DockerServerInstance object.
        image (str): image name that the docker will be created with.
        command (str): the command to run on the container.
        kwargs (dict): Keyword arguments: https://docker-py.readthedocs.io/en/stable/containers.html#container-objects

    Returns:
        Container: a container object if created successfully.

    Raises:
        ImageNotFound: in case the image was not found on the docker server.
        ApiError: In case the docker server returns an error.
    """
    return instance.docker().get_container_collection().create(image=image, command=command, **kwargs)


def run_container(instance, image, kwargs):
    """
    runs a container over an instance ID. Similar to docker run command.

    Args:
        instance (DockerServerInstance): docker server instance object.
        image (str): image name that the docker will be created with.
        kwargs (dict): https://docker-py.readthedocs.io/en/stable/containers.html#container-objects

        Returns:
            Container: a container object if created successfully.

        Raises:
            ImageNotFound: in case the image was not found on the docker server.
            ApiError: In case the docker server returns an error.
    """

    if "detach" not in kwargs:
        kwargs["detach"] = True
    return instance.docker.get_container_collection().run(image=image, **kwargs)


def run_container_with_msfrpcd_metasploit(instance, port):
    """
    Runs a container and start an msfrpc daemon for metasploit connection on a requested port.

    Args:
        instance (DockerServerInstance): docker server instance object.
        port (int): which port msfrpc daemon will listen to.

    Returns:
        Container: a container object with msfrpcd deployed, None otherwise.

    """
    kwargs = {
        "stdin_open": True,
        "tty": True,
        "ports": {port: port},
        "detach": True,
        "network": True
    }

    container = run_container(instance=instance, image="phocean/msf", kwargs=kwargs)

    exit_code, o = container.exec_run(cmd=f"./msfrpcd -P 123456 -S -p {port}")

    print(exit_code)
    print(o)

    if not exit_code:
        return container
    return None


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
    return get_docker_server_instance(id=instance_id).docker().get_container_collection().get(
        container_id=container_id
    )


def pull_image(instance, repository, tag=None, **kwargs):
    """
    Pull an image of the given name and return it.
    Similar to the docker pull command. If no tag is specified, all tags from that repository will be pulled.

    Args:
        instance (DockerServerInstance): docker server instance object.
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
    return instance.docker.get_image_collection().pull(repository=repository, tag=tag, **kwargs)


def build_image(instance_id, **kwargs):
    """
    Builds a new image based on a docker file.

    Args:
        instance_id (str): instance ID.

    Keyword args:
        https://docker-py.readthedocs.io/en/stable/images.html#

    Returns:
        tuple (Image, Generator): The first item is the Image object for
        the image that was build. The second item is a generator of the build logs as JSON-decoded objects.

    Raises:
        docker.errors.BuildError – If there is an error during the build.
        docker.errors.APIError – If the server returns any other error.
        TypeError – If neither path nor fileobj is specified.
    """
    return get_docker_server_instance(id=instance_id).docker().get_image_collection().build(**kwargs)


def execute_command_in_container(instance_id, container_id, command, **kwargs):
    """
    Executes a command in a container by rest API.

    Args:
        instance_id (str): instance ID.
        container_id (str): container ID.
        command (str): command that should be executed, for example: ./msfrpcd -P 123456 -S

        Keyword Arguments:
            stdout (bool) – Attach to stdout. Default: True
            stderr (bool) – Attach to stderr. Default: True
            stdin (bool) – Attach to stdin. Default: False
            tty (bool) – Allocate a pseudo-TTY. Default: False
            privileged (bool) – Run as privileged.
            user (str) – User to execute command as. Default: root
            detach (bool) – If true, detach from the exec command. Default: False
            stream (bool) – Stream response data. Default: False
            socket (bool) – Return the connection socket to allow custom read/write operations. Default: False
            environment (dict or list) – A dictionary or a list of strings in the following format ["PASSWORD=xxx"] or
                                        {"PASSWORD": "xxx"}.
            workdir (str) – Path to working directory for this exec session
            demux (bool) – Return stdout and stderr separately

    Returns:
        A tuple of (exit_code, output)
            exit_code: (int): Exit code for the executed command or None if either stream or socket is True.
            output: (generator, bytes, or tuple):
                If stream=True, a generator yielding response chunks.
                If socket=True, a socket object for the connection.
                If demux=True, a tuple of two bytes: stdout and stderr.
                A bytestring containing response data otherwise.

    Raises:
        APIError: if the server returns an error.
    """
    return get_container(instance_id=instance_id, container_id=container_id).exec_run(cmd=command, **kwargs)


def create_network(instance_id, name, kwargs):
    """
    Creates docker network for the containers over an instance. Similar to the ``docker network create``.

    Args:
        instance_id (str): instance ID.
        name (str): the name of the network that will be created.

        Keyword arguments:
            see create params - https://docker-py.readthedocs.io/en/stable/networks.html

    Returns:
        str: a network ID
    """
    return get_docker_server_instance(id=instance_id).docker().get_network_collection().create(name=name, **kwargs)


# from metasploit.venv.Aws import Constants
# from metasploit.venv.Aws.Aws_Api_Functions import create_amazon_resources
# i = create_amazon_resources(Constants.CREATE_INSTANCES_DICT)
# d = i.docker()
# c = create_container(instance_id=i.get_instance_id(), image='phocean/msf', command="sleep 1000", kwargs={})
# print()


# class MetasploitContainer(object):
#     def __init__(self, instance_id, container_id=""):
#         port = get_docker_server_instance(id=instance_id).docker().get_api_client()
#         if container_id:
#             self.container = get_container(instance_id=instance_id, container_id=container_id)
#         else:
