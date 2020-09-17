import boto3
from metasploit.venv.Aws.custom_exceptions import (
    CommandFailureError,
    InitializeNewInstanceUsingConstructorException
)
from metasploit.venv.Aws import Constants
from metasploit.venv.Aws.Connections import (
    Docker,
    SSH
)


EC2 = 'ec2'


class AwsAccess:
    """
    This is a class for API calls to the AWS ec2 service per one user

    Attributes:
        _client(put here the type of variable) - client for api calls to ec2
        _resource(put here the type of variable) - resource for api calls to ec2

    Documentation:
        https://boto3.amazonaws.com/v1/documentation/api/latest/index.html
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#service-resource
    """

    aws_access_instance = None

    def __init__(self):
        if AwsAccess.aws_access_instance is not None:
            raise InitializeNewInstanceUsingConstructorException
        self._client = boto3.client(EC2)
        self._resource = boto3.resource(EC2)
        self._session = boto3.Session()
        AwsAccess.aws_access_instance = self

    @staticmethod
    def get_aws_access_instance():
        if AwsAccess.aws_access_instance is None:
            AwsAccess()
        return AwsAccess.aws_access_instance

    def get_client(self):
        return self._client

    def get_resource(self):
        return self._resource

    def get_session(self):
        return self._session


class DockerServerInstance(object):
    """
    This class represents an instance in AWS with a docker server configured.

    Attributes:
        _instance_obj (Aws.Instance): a aws instance object.
        _commands (list(Command)): a list of all the _commands that were executed on this instance.
        _ssh (SSH): a SSH client that opens a connection to the instance.
        _docker (Docker): a docker class that represents docker-container over an instance.
    """

    def __init__(self, instance_obj, ssh_flag=False, init_docker_server_flag=False):
        """
        Args:
            instance_obj (Aws.Instance): Aws instance object.
            ssh_flag (bool): indicate if the instance requires a SSH connection.
            True to open connection, False otherwise.
            init_docker_server_flag (bool): indicate if the instance needs to be configured with a docker server.
            True to deploy docker server, False means it's already deployed.

        """
        self._instance_obj = instance_obj
        self._commands = []

        if ssh_flag:
            self._ssh = SSH(
                hostname=self.get_public_dns_name(),
                username=Constants.USER_NAME,
                private_key=Constants.DEFAULT_PRIVATE_KEY_PATH
            )

        if init_docker_server_flag:
            self._init_docker_server_on_instance()

        self._docker = Docker(
            protocol='tcp', docker_server_ip=self.get_public_ip_address(), docker_port=Constants.DOCKER_PORT
        )

    def get_commands(self):
        return self._commands

    def get_docker(self):
        return self._docker

    def get_instance_id(self):
        return self._instance_obj.instance_id

    def get_public_ip_address(self):
        return self._instance_obj.public_ip_address

    def get_public_dns_name(self):
        return self._instance_obj.public_dns_name

    def get_state(self):
        return self._instance_obj.state

    def get_key_name(self):
        return self._instance_obj.key_name

    def get_security_groups(self):
        return self._instance_obj.security_groups

    def get_image_id(self):
        return self._instance_obj.image_id

    def get_private_ip_address(self):
        return self._instance_obj.private_ip_address

    def get_private_dns_name(self):
        return self._instance_obj.private_dns_name

    def get_instance_obj(self):
        return self._instance_obj

    def _reload(self):
        self._instance_obj.reload()

    def start(self):
        """
        Start the instance and wait till is is on running state

        """
        if self.get_state()['Name'] == Constants.STOPPED_STATE:
            self._instance_obj.start()
            self._instance_obj.wait_until_running()
            self._reload()

    def stop(self):
        """
        Stop the instance and wait till it's in a stopped state

        """
        if self.get_state()['Name'] == Constants.RUNNING_STATE:
            self._instance_obj.stop()
            self._instance_obj.wait_until_stopped()
            self._reload()

    def reboot(self):
        """
        Reboot the instance and wait till it's in a running state

        """
        if self.get_state()['Name'] == Constants.RUNNING_STATE:
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
        if self.get_state()['Name'] == Constants.RUNNING_STATE:
            ssh_flag = True
            while ssh_flag:
                try:
                    for command in commands:
                        stdin, stdout, stderr = self._ssh.get_client().exec_command(command=command, timeout=10)
                        exit_cmd_status = stdout.channel.recv_exit_status()
                        if not exit_cmd_status:  # means the command was successful - similar to echo $?
                            cmd_details = self.Command(stdin=stdin, stdout=stdout, stderr=stderr, command=command)
                            self._commands.append(cmd_details)
                        else:
                            ssh_flag = False
                            raise CommandFailureError(
                                cmd=command, instance_id=self.get_instance_id()
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
            commands=Constants.MAKE_DOCKER_FILES_COMMANDS
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
            commands=Constants.RELOAD_DOCKER_DAEMON
        )

    class Command:
        """
        This class represents a command that was sent through SSH AWS

        Attributes:
            stdin (paramiko.channel.ChannelStdinFile) - The stdin of the running command
            stdout (paramiko.channel.ChannelFile) - The stdout of the running command
            stderr (paramiko.channel.ChannelStderrFile) - The stderr of the running command
            command (str) - The command name that was executed

        stdout and stderr can be treated as python files, if you want to print all the out put according to lines:
            for line in stdout.read().splitlines():
                print(line)
        """

        def __init__(self, stdin, stdout, stderr, command):
            self._stdin = stdin
            self._stdout = stdout
            self._stderr = stderr
            self._command = command

        def get_stdin(self):
            return self._stdin

        def get_stdout(self):
            return self._stdout

        def get_stderr(self):
            return self._stderr

        def get_executed_command_name(self):
            return self._command


aws_api = AwsAccess.get_aws_access_instance()


# a = {1: {1:[]}}
# if a[1]:
#     print("good")
# sg = delete_security_group(security_group_id="dsfdsf")
# sg = create_security_group({
#     "1": {
#         "Description11": "dsfdsf",
#         "GroupName11": "sdfdsf"
#     }
# })

# ins = create_instance(kwargs=config.CREATE_INSTANCES_DICT)
# d = ins.get_docker()
# d2 = DockerServerInstance(instance_obj=aws_api.get_resource().Instance(ins.get_instance_id())).get_docker()
#
# print("started AWS file ")
# ins.terminate()

