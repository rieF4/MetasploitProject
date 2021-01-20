import paramiko

from pymetasploit3 import msfrpc
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
        num_tries = 0
        while num_tries < 1000:
            try:
                self._ssh_client.connect(hostname=hostname, username=username, pkey=self._private_key)
                break
            except Exception:
                num_tries += 1
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
        _metasploit_client (MsfRpcClient): msfrpc client obj.
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
        self._host_console = self._console

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

    @property
    def payloads(self):
        return self.modules.payloads

    @property
    def _console(self):
        return msfrpc.MsfConsole(rpc=self.metasploit_client)

    def destory_console(self):
        self.host_console.destroy()

    @property
    def host_console(self):
        return self._host_console
