import docker


class Docker(object):
    """
    This class attempts to connect to a specified docker server.

    Attributes:
        docker_client (DockerClient): The docker client object can be used to maintain docker operations.
        api_client (APIClient): The low level API object for docker.
    """

    def __init__(self, protocol, docker_server_ip, docker_port):
        """
        Initialize the connection to the docker server over an AWS ec2 instance using a chosen protocol,
        docker server ip and a port that the docker server listens to.

        Args:
            protocol (str): a protocol to use in order to connect to the docker server. etc: tcp/udp.
            docker_server_ip (str): the docker server public ip.
            docker_port (int): the port that the docker server listens to.
        """
        base_url = f"{protocol}://{docker_server_ip}:{docker_port}"

        self.docker_client = docker.DockerClient(base_url=base_url)

        self.api_client = docker.APIClient(base_url=base_url)

    def info(self):
        """
        Display system-wide information about the docker, Identical to the docker info command.

        Returns:
            dict: information about the the docker such as containers running, images, etc.
        """
        return self.docker_client.info()

    def get_container_collection(self):
        """
        Get a container collection object.

        Returns:
            ContainerCollection: a container collection object.
        """
        return self.docker_client.containers

    def get_network_collection(self):
        """
        Get a network collection object.

        Returns:
            NetworkCollection: a network collection object.
        """
        return self.docker_client.networks

    def get_image_collection(self):
        """
        Get an image collection object.

        Returns:
            ImageCollection: a image collection object.
        """
        return self.docker_client.images

    def get_config_collection(self):
        """
        Get a config collection object.

        Returns:
            ConfigCollection: a config collection object.

        """
        return self.docker_client.configs



