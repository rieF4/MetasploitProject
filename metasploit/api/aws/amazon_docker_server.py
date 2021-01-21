from metasploit.api.docker.connection import (
    Docker
)

from . import constants as aws_constants
from .. import constants as global_constants
from metasploit.api.connections import SSH

from metasploit.api.errors import (
    CommandFailureError
)


class DockerServerInstance(object):
    """
    This class represents an instance in AWS with a docker server configured.

    Attributes:
        _instance_obj (Aws.Instance): a aws instance obj.
        _commands (list(Command)): a list of all the _commands that were executed on this instance.
        _ssh (SSH): a SSH client that opens a connection to the instance.
        _docker (Docker): a docker class that represents docker-container over an instance.
    """

    def __init__(self, instance_obj, ssh_flag=False, init_docker_server_flag=False):
        """
        Args:
            instance_obj (Aws.Instance): Aws instance obj.
            ssh_flag (bool): indicate if the instance requires a SSH connection.
            True to open connection, False otherwise.
            init_docker_server_flag (bool): indicate if the instance needs to be configured with a docker server.
            True to deploy docker server, False means it's already deployed.

        """
        self._instance_obj = instance_obj
        self._commands = []

        if ssh_flag:
            self._ssh = SSH(
                hostname=self.public_dns_name,
                username=aws_constants.USER_NAME,
                private_key=aws_constants.DEFAULT_PRIVATE_KEY_PATH
            )

        if init_docker_server_flag:
            self._init_docker_server_on_instance()

        self._docker = Docker(
            protocol=global_constants.IP_PROTOCOL,
            docker_server_ip=self.public_ip_address,
            docker_port=global_constants.DOCKER_PORT
        )

    @property
    def get_commands(self):
        return self._commands

    @property
    def docker(self):
        return self._docker

    @property
    def instance_id(self):
        return self._instance_obj.instance_id

    @property
    def public_ip_address(self):
        return self._instance_obj.public_ip_address

    @property
    def public_dns_name(self):
        return self._instance_obj.public_dns_name

    @property
    def state(self):
        return self._instance_obj.state

    @property
    def key_name(self):
        return self._instance_obj.key_name

    @property
    def security_groups(self):
        return self._instance_obj.security_groups

    @property
    def image_id(self):
        return self._instance_obj.image_id

    @property
    def private_ip_address(self):
        return self._instance_obj.private_ip_address

    @property
    def private_dns_name(self):
        return self._instance_obj.private_dns_name

    @property
    def instance_obj(self):
        return self._instance_obj

    def _reload(self):
        self._instance_obj.reload()

    def start(self):
        """
        Start the instance and wait till is is on running state
        """
        if self.state['Name'] == aws_constants.STOPPED_STATE:
            self._instance_obj.start()
            self._instance_obj.wait_until_running()
            self._reload()

    def stop(self):
        """
        Stop the instance and wait till it's in a stopped state
        """
        if self.state['Name'] == aws_constants.RUNNING_STATE:
            self._instance_obj.stop()
            self._instance_obj.wait_until_stopped()
            self._reload()

    def reboot(self):
        """
        Reboot the instance and wait till it's in a running state
        """
        if self.state['Name'] == aws_constants.RUNNING_STATE:
            self._instance_obj.reboot()
            self._instance_obj.wait_until_running()
            self._reload()

    def terminate(self):
        """
        Terminate the instance and delete the current instance
        """
        self._instance_obj.terminate()

    def execute_shell_commands(self, commands):
        """
        Executes the given _commands over the instance using SSH and add them to the _commands attribute

        Args:
            commands (list(str)) - list of all the _commands to execute on the instance

        Raises:
            CommandFailureError in case the command fails over the instance
        """
        if self.state['Name'] == aws_constants.RUNNING_STATE:
            ssh_flag = True
            while ssh_flag:
                try:
                    for command in commands:
                        stdin, stdout, stderr = self._ssh.get_client().exec_command(command=command, timeout=10)
                        exit_cmd_status = stdout.channel.recv_exit_status()
                        if exit_cmd_status:  # means the command was not successful - similar to echo $?
                            ssh_flag = False
                            raise CommandFailureError(
                                cmd=command, instance_id=self.instance_id
                            )
                    ssh_flag = False
                except Exception as error:
                    print(error)

    def write_to_file(self, filename, mode, data=None):
        """
        Write to a file in the instance.

        Args:
            filename (str): the exact file path. etc: /etc/docker/my_file.
            mode (str): read or write on the file etc ("w" for write, "r" for read).
            data (str): which data should be written on the file.

        Returns:
            True if the write operation is success, False otherwise.
        """
        sftp = self._ssh.get_sftp()
        try:
            file_obj = sftp.open(filename=filename, mode=mode)
            if mode == 'w':
                file_obj.write(data=data)
            return True
        except Exception:
            return False

    def _init_docker_server_on_instance(self):
        """
        Initialize the docker server over an instance in AWS.
        """
        self.execute_shell_commands(
            commands=aws_constants.MAKE_DOCKER_FILES_COMMANDS
        )

        self.write_to_file(
            filename='/etc/docker/daemon.json',
            mode='w',
            data='{"hosts": ["tcp://0.0.0.0:2375", "unix:///var/run/docker.sock"]}\n'
        )

        self.write_to_file(
            filename='/etc/systemd/system/docker.service.d/override.conf',
            mode='w',
            data='[Service]\nExecStart=\nExecStart=/usr/bin/dockerd\n'
        )

        self.execute_shell_commands(
            commands=aws_constants.RELOAD_DOCKER_DAEMON
        )
