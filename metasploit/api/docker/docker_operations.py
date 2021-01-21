
from metasploit.api.aws.amazon_operations import DockerServerInstanceOperations
from metasploit.api.errors import ContainerCommandFailure
from metasploit.api.utils.helpers import choose_port_for_msfrpcd


class DockerOperations(DockerServerInstanceOperations):
    def __init__(self, docker_server_id, docker_resource_id=None):
        super(DockerOperations, self).__init__(instance_id=docker_server_id)
        self._docker_resource_id = docker_resource_id

    @property
    def docker_resource_id(self):
        return self._docker_resource_id


class ContainerOperations(DockerOperations):

    def create_container(self, image, command, kwargs):
        """
        Creates a container over an instance ID. Similar to Docker create shell command.

        Args:
            image (str): image name that the docker will be created with.
            command (str): the command to run on the container.
            kwargs (dict): Keyword arguments:
                            https://docker-py.readthedocs.io/en/stable/containers.html#container-objects

        Returns:
            Container: a container obj if created successfully.

        Raises:
            ImageNotFound: in case the image was not found on the docker server.
            ApiError: In case the docker server returns an error.
        """
        return self.docker_server.docker.container_collection.create(
            image=image, command=command, **kwargs
        )

    def run_container(self, image, kwargs):
        """
        runs a container over an instance ID. Similar to docker run command.

        Args:
            image (str): image name that the docker will be created with.
            kwargs (dict): https://docker-py.readthedocs.io/en/stable/containers.html#container-objects

        Returns:
            Container: a container obj if created successfully.

        Raises:
            ImageNotFound: in case the image was not found on the docker server.
            ApiError: In case the docker server returns an error.
        """
        if "detach" not in kwargs:
            kwargs["detach"] = True
        return self.docker_server.docker.container_collection.run(image=image, **kwargs)

    def run_container_with_msfrpcd_metasploit(self, containers_documents):
        """
        Runs a container and start an msfrpc daemon for metasploit connection on a requested port.

        Args:
            containers_documents (dict): all of the the containers documents of the instance.

        Returns:
            Container: a container obj with msfrpcd deployed.

        Raises:
            ContainerCommandFailure: in case the command fails to be executed on the container.

        """
        port = choose_port_for_msfrpcd(containers_document=containers_documents)

        kwargs = {
            "stdin_open": True,
            "tty": True,
            "ports": {port: port},
            "detach": True
        }

        container = self.run_container(image="phocean/msf", kwargs=kwargs)
        run_msfrpcd_cmd = f"./msfrpcd -P 123456 -S -p {port}"

        exit_code, output = container.exec_run(cmd=run_msfrpcd_cmd)

        if not exit_code:
            return container
        else:
            raise ContainerCommandFailure(
                error_code=exit_code, output=output, cmd=run_msfrpcd_cmd, container_id=container.id
            )

    @property
    def container(self):
        """
        Get container object by instance and container IDs.

        Returns:
            Container: a container obj if found.

        Raises:
            ApiError: in case the docker server returns an error.
        """
        return self.docker_server.docker.container_collection.get(container_id=self.docker_resource_id)

    def execute_command_in_container(self, command, **kwargs):
        """
        Executes a command in a container by rest API.

        Args:
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
                    If socket=True, a socket obj for the connection.
                    If demux=True, a tuple of two bytes: stdout and stderr.
                    A bytestring containing response data otherwise.

        Raises:
            APIError: if the server returns an error.
        """
        return self.container.exec_run(cmd=command, **kwargs)


class ImageOperations(DockerOperations):

    def pull_image(self, repository, tag=None, **kwargs):
        """
        Pull an image of the given name and return it.
        Similar to the docker pull command. If no tag is specified, all tags from that repository will be pulled.

        Args:
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
        return self.docker_server.docker.image_collection.pull(repository=repository, tag=tag, **kwargs)

    def build_image(self, **kwargs):
        """
        Builds a new image based on a docker file.

        Keyword args:
            https://docker-py.readthedocs.io/en/stable/images.html#

        Returns:
            tuple (Image, Generator): The first item is the Image obj for
            the image that was build. The second item is a generator of the build logs as JSON-decoded objects.

        Raises:
            docker.errors.BuildError – If there is an error during the build.
            docker.errors.APIError – If the server returns any other error.
            TypeError – If neither path nor fileobj is specified.
        """
        return self.docker_server.docker.image_collection.build(**kwargs)
