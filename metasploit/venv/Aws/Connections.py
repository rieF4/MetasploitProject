import docker
import paramiko
from pymetasploit3.msfrpc import MsfRpcClient


class Connection(object):
    """
    Base class for a connection in the api.
    """
    pass


class Docker(Connection):
    """
    This class attempts to connect to a specified docker server.

    Attributes:
        _docker_client (DockerClient): The docker client object can be used to maintain docker operations.
        _api_client (APIClient): The low level API object for docker.
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

        self._docker_client = docker.DockerClient(base_url=base_url)

        self._api_client = docker.APIClient(base_url=base_url)

    def get_api_client(self):
        return self._api_client

    def get_docker_client(self):
        return self._docker_client

    def info(self):
        """
        Display system-wide information about the docker, Identical to the docker info command.

        Returns:
            dict: information about the the docker such as containers running, images, etc.
        """
        return self._docker_client.info()

    def get_container_collection(self):
        """
        Get a container collection object.

        Returns:
            ContainerCollection: a container collection object.
        """
        return self._docker_client.containers

    def get_network_collection(self):
        """
        Get a network collection object.

        Returns:
            NetworkCollection: a network collection object.
        """
        return self._docker_client.networks

    def get_image_collection(self):
        """
        Get an image collection object.

        Returns:
            ImageCollection: a image collection object.
        """
        return self._docker_client.images

    def get_config_collection(self):
        """
        Get a config collection object.

        Returns:
            ConfigCollection: a config collection object.

        """
        return self._docker_client.configs


class SSH(Connection):
    """
    This is a class to connect with ssh to a remote machine.

    Attributes:
        _ssh_client (SSHClient): a SSHClient for the remote server.
        _private_key (str): a private key used to authenticate the server.
        _sftp (SFTPClient): the SFTPClient that is connected to the server.
    """

    def __init__(self, hostname, username, private_key):
        """
        initialize the SSH class with a new connection to a remote machine.

        Args:
            hostname (str): host name to connect.
            username (str): user name of the host name.
            private_key (str): the private key to authenticate the hostname.
        """
        self._ssh_client = paramiko.SSHClient()
        self._ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._private_key = paramiko.RSAKey.from_private_key(open(private_key))
        while True:
            try:
                self._ssh_client.connect(hostname=hostname, username=username, pkey=self._private_key)
                break
            except Exception:
                pass
        self._sftp = self._ssh_client.open_sftp()

    def get_client(self):
        """
        Returns the SSH client

        Returns:
            SSHClient: a SSHClient for the remote server.
        """
        return self._ssh_client

    def get_sftp(self):
        """
        Open an SFTP session on the SSH server.

        Returns:
            SFTPClient: The SFTPClient to the server.
        """
        return self._sftp

    def get_private_key(self):
        """
        Returns the private key used to authenticate the server.

        Returns:
            str: the private key for the server.
        """
        return self._private_key


class Metasploit(Connection):
    """
    Class that represents a connection to msfrpc daemon of metasploit.

    Attributes:
        _metasploit_client (MsfRpcClient): msfrpc client object.
    """
    def __init__(self, server, password=123456, port=55553):
        """
        Initialize a connection to msfrpc daemon of metasploit.

        Args:
            server (str): server IP.
            password (str): password that msfrpc daemon was deployed with.
            port (int): the port that msfrpc listens to.
        """
        self._metasploit_client = MsfRpcClient(password=password, server=server, port=port)

    @property
    def metasploit_client(self):
        return self._metasploit_client

    def get_exploits(self):
        """
        Get all the available exploits in metasploit.

        Returns:
           list(str): a list of strings representing all the available exploits on metasploit
        """
        return self.metasploit_client.modules.exploits
