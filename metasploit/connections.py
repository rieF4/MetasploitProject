import paramiko

from pymetasploit3.msfrpc import MsfRpcClient


class Connection(object):
    """
    Base class for a connection in the api.
    """
    pass


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
    def __init__(self, server, password='123456', port=55553):
        """
        Initialize a connection to msfrpc daemon of metasploit.

        Args:
            server (str): public IP/DNS of docker server instance.
            password (str): password that msfrpc daemon was deployed with.
            port (int): the port that msfrpc listens to.
        """
        self._metasploit_client = MsfRpcClient(password=password, server=server, port=port)

    @property
    def metasploit_client(self):
        return self._metasploit_client

    @property
    def modules(self):
        return self.metasploit_client.modules

    @property
    def auxiliaries(self):
        return self.modules.auxiliary

    @property
    def exploits(self):
        """
        Get all the available exploits in metasploit.

        Returns:
           list(str): a list of strings representing all the available exploits on metasploit
        """
        return self.modules.exploits
