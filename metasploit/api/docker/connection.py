
import docker

from metasploit.api.connections import Connection


class Docker(Connection):
    """
    This class attempts to connect to a specified docker server.

    Attributes:
        _docker_client (DockerClient): The docker client obj can be used to maintain docker operations.
        _api_client (APIClient): The low level API obj for docker.
    """

    def __init__(self, protocol, docker_server_ip, docker_port=2375):
        """
        Initialize the connection to the docker server over an AWS ec2 instance using a chosen protocol,
        docker server ip and a port that the docker server listens to.

        Args:
            protocol (str): a protocol to use in order to connect to the docker server. etc: tcp/udp.
            docker_server_ip (str): the docker server public ip.
            docker_port (int): the port that the docker server listens to.
        """
        base_url = f"{protocol}://{docker_server_ip}:{docker_port}"

        self._docker_client = docker.DockerClient(base_url=base_url)

        self._api_client = docker.APIClient(base_url=base_url)

    @property
    def api_client(self):
        return self._api_client

    @property
    def docker_client(self):
        return self._docker_client

    @property
    def info(self):
        """
        Display system-wide information about the docker, Identical to the docker info command.

        Returns:
            dict: information about the the docker such as containers running, images, etc.
        """
        return self._docker_client.info()

    @property
    def container_collection(self):
        """
        Get a container collection obj.

        Returns:
            ContainerCollection: a container collection obj.
        """
        return self._docker_client.containers

    @property
    def network_collection(self):
        """
        Get a network collection obj.

        Returns:
            NetworkCollection: a network collection obj.
        """
        return self._docker_client.networks

    @property
    def image_collection(self):
        """
        Get an image collection obj.

        Returns:
            ImageCollection: a image collection obj.
        """
        return self._docker_client.images

    @property
    def config_collection(self):
        """
        Get a config collection obj.

        Returns:
            ConfigCollection: a config collection obj.

        """
        return self._docker_client.configs
