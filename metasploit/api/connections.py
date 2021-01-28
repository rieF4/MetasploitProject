import paramiko
from paramiko.ssh_exception import (
    SSHException,
    NoValidConnectionsError
)

from pymetasploit3 import msfrpc
from pymetasploit3.msfrpc import MsfRpcClient
from metasploit.api.utils.helpers import TimeoutSampler
from metasploit.api.errors import (
    TimeoutExpiredError,
    SSHConnectionError
)
from metasploit.api.aws import constants as aws_const


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

    def __init__(self, hostname, username=aws_const.USER_NAME, private_key=aws_const.DEFAULT_PRIVATE_KEY_PATH):
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
        self._hostname = hostname

        is_connection_established = False
        while not is_connection_established:
            try:
                for _ in TimeoutSampler(
                        timeout=90,
                        sleep=3,
                        func=self._ssh_client.connect,
                        hostname=hostname,
                        username=username,
                        pkey=self._private_key
                ):
                    is_connection_established = True
                    break
            except (SSHException, NoValidConnectionsError, TimeoutExpiredError) as err:
                if isinstance(err, TimeoutExpiredError):
                    raise SSHConnectionError(host=hostname)

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

    def execute_commands(self, commands):
        """
        Executes commands over a remote host via SSH.

        Args:
            commands (list[str]): list of commands to execute.

        Returns:
            bool: True if all the commands were successful, False if one of the commands failed.

        Raises:
            SSHException: in case the SSH server fails to execute the command.
        """
        try:
            for command in commands:
                stdin, stdout, stderr = self.get_client().exec_command(command=command, timeout=10)
                exit_cmd_status = stdout.channel.recv_exit_status()
                if exit_cmd_status:  # means the command was not successful - similar to echo $?
                    return False, command
            return True, 'Success'
        except SSHException:
            raise SSHConnectionError(host=self._hostname)


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
        """
        Gets metasploit client.

        Returns:
            MsfRpcClient: msfrpc client object.
        """
        return self._metasploit_client

    @property
    def modules(self):
        """
        Gets the ModuleManager object.

        Returns:
            ModuleManager: a module manager object.
        """
        return self.metasploit_client.modules

    @property
    def auxiliaries(self):
        """
        Gets all the available auxiliaries in metasploit.

        Returns:
           list(str): a list of strings representing all the available auxiliaries on metasploit.
        """
        return self.modules.auxiliary

    @property
    def exploits(self):
        """
        Gets all the available exploits in metasploit.

        Returns:
           list(str): a list of strings representing all the available exploits on metasploit
        """
        return self.modules.exploits

    @property
    def payloads(self):
        """
        Gets all the available payloads in metasploit.

        Returns:
            list(str): a list of strings representing all the available payloads on metasploit
        """
        return self.modules.payloads

    @property
    def _console(self):
        """
        Creates a new msfConsole object.

        Returns:
            msfConsole: msf console object.
        """
        return msfrpc.MsfConsole(rpc=self.metasploit_client)

    def destory_console(self):
        """
        Destroys the msfConsole.
        """
        self.host_console.destroy()

    @property
    def host_console(self):
        """
        Gets the host console attribute which represents a msfConsole object.
        """
        return self._host_console
