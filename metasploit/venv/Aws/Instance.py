
import paramiko
from metasploit.venv.Aws import config
from metasploit.venv.Aws import custom_exceptions
from metasploit.venv.Aws import Aws
from metasploit.venv.Aws.utils import SSH
from metasploit.venv.Aws.Docker import Docker


class Instance:
    """
    This class represents an instance in AWS

    Attributes:
        _instance_obj (Instance) - a aws instance type
        _commands (list(Command)) - a list of all the _commands that were executed on this instance

    """
    aws = Aws.AwsAccess.get_aws_access_instance()

    def __init__(self, kwargs):
        """
        Args:
            kwargs (dict) - The API post request to create the instance

        Examples:
            kwargs =
                ImageId='ami-0bdcc6c05dec346bf',
                InstanceType='t2.micro',
                MaxCount=1,
                MinCount=1,
                KeyName='MyFirstInstance'
                SecurityGroupIds=['group_id']

            instance = self.resource.create_instances(**kwargs)
            The get API call is an instance object
        """
        self._instance_obj = Instance.aws.resource.create_instances(**kwargs)[0]
        self._instance_obj.wait_until_running()
        self._reload()
        self._commands = []
        self._ssh = SSH(
            hostname=self.get_public_dns_name(), username=config.USER_NAME, private_key=config.DEFAULT_PRIVATE_KEY_PATH
        )

    def get_commands(self):
        return self._commands

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

    def get_instance_obj(self):
        return self._instance_obj

    def _reload(self):
        self._instance_obj.reload()

    def start(self):
        """
        Start the instance and wait till is is on running state

        """
        if self.get_state()['Name'] == config.STOPPED_STATE:
            self._instance_obj.start()
            self._instance_obj.wait_until_running()
            self._reload()

    def stop(self):
        """
        Stop the instance and wait till it's in a stopped state

        """
        if self.get_state()['Name'] == config.RUNNING_STATE:
            self._instance_obj.stop()
            self._instance_obj.wait_until_stopped()
            self._reload()

    def reboot(self):
        """
        Reboot the instance and wait till it's in a running state

        """
        if self.get_state()['Name'] == config.RUNNING_STATE:
            self._instance_obj.reboot()
            self._instance_obj.wait_until_running()
            self._reload()

    def terminate(self):
        """
        Terminate the instance and delete the current instance

        """
        self._instance_obj.terminate()
        del self

    def execute_shell_commands(self, commands):
        """
        Executes the given _commands over the instance using SSH and add them to the _commands attribute

        Args:
            commands (list(str)) - list of all the _commands to execute on the instance

        Raises:
            CommandFailureException in case the command fails over the instance
        """
        if self.get_state()['Name'] == config.RUNNING_STATE:
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
                            raise custom_exceptions.CommandFailureException(
                                cmd=command, instance_id=self.get_instance_id()
                            )
                    ssh_flag = False
                except Exception as error:
                    print(error)

    def write_to_file(self, filename, mode, data):
        sftp = self._ssh.get_sftp()
        file_obj = sftp.open(filename=filename, mode=mode)
        if mode == 'w':
            file_obj.write(data=data)

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





ins = Instance(config.CREATE_INSTANCES_DICT)
ins.execute_shell_commands(commands=
    [
        'sudo yum install -y docker',
        'sudo systemctl start docker',
        'sudo chmod 666 /var/run/docker.sock',
        'sudo touch /etc/docker/daemon.json',
        'sudo chmod 666 /etc/docker/daemon.json',
        'sudo mkdir /etc/systemd/system/docker.service.d',
        'sudo touch /etc/systemd/system/docker.service.d/override.conf',
        'sudo chmod 666 /etc/systemd/system/docker.service.d/override.conf'
    ]
)
ins.write_to_file(
    filename='/etc/docker/daemon.json',
    mode='w',
    data='{"hosts": ["tcp://0.0.0.0:2375", "unix:///var/run/docker.sock"]}\n'
)
ins.write_to_file(
    filename='/etc/systemd/system/docker.service.d/override.conf',
    mode='w',
    data='[Service]\nExecStart=\nExecStart=/usr/bin/dockerd'
)
ins.execute_shell_commands(commands=
    [
        'sudo systemctl daemon-reload',
        'sudo systemctl restart docker.service',
        'sudo chmod 666 /var/run/docker.sock'
    ]
)
ip = ins.get_public_ip_address()
docker = Docker(protocol='tcp', docker_server_ip=ip, docker_port=2375)
print(docker.info())
print(docker.get_container_collection().list())
print(docker.get_image_collection().list())
print()

# ins.modify_files_in_instance(path_to_file="", mode="wb", data="")
# ins.execute_shell_commands(['sudo yum install -y docker', 'sudo systemctl start docker',
#                       'sudo chmod 666 /var/run/docker.sock'])

