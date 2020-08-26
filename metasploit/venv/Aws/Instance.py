
import paramiko
from metasploit.venv.Aws import config
from metasploit.venv.Aws import custom_exceptions
from metasploit.venv.Aws import AwsAccess


class Instance:
    """
    This class represents an instance in AWS

    Attributes:
        instance_obj (Instance) - a aws instance type
        commands (list(Command)) - a list of all the commands that were executed on this instance

    """
    aws = AwsAccess.get_aws_access_instance()

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
        self.instance_obj = Instance.aws.resource.create_instances(**kwargs)[0]
        self.instance_obj.wait_until_running()
        self._reload()
        self.commands = []

    def get_instance_id(self):
        return self.instance_obj.instance_id

    def get_public_ip_address(self):
        return self.instance_obj.public_ip_address

    def get_public_dns_name(self):
        return self.instance_obj.public_dns_name

    def get_state(self):
        return self.instance_obj.state

    def get_key_name(self):
        return self.instance_obj.key_name

    def get_security_groups(self):
        return self.instance_obj.security_groups

    def get_image_id(self):
        return self.instance_obj.image_id

    def get_instance_obj(self):
        return self.instance_obj

    def _reload(self):
        self.instance_obj.reload()

    def start(self):
        """
        Start the instance and wait till is is on running state

        """
        if self.get_state()['Name'] == config.STOPPED_STATE:
            self.instance_obj.start()
            self.instance_obj.wait_until_running()
            self._reload()

    def stop(self):
        """
        Stop the instance and wait till it's in a stopped state

        """
        if self.get_state()['Name'] == config.RUNNING_STATE:
            self.instance_obj.stop()
            self.instance_obj.wait_until_stopped()
            self._reload()

    def reboot(self):
        """
        Reboot the instance and wait till it's in a running state

        """
        if self.get_state()['Name'] == config.RUNNING_STATE:
            self.instance_obj.reboot()
            self.instance_obj.wait_until_running()
            self._reload()

    def terminate(self):
        """
        Terminate the instance and delete the current instance

        """
        self.instance_obj.terminate()
        del self

    def execute_shell_commands(self, commands):
        """
        Executes the given commands over the instance using SSH and add them to the commands attribute

        Args:
            commands (list(str)) - list of all the commands to execute on the instance

        Raises:
            CommandFailureException in case the command fails over the instance
        """
        if self.get_state()['Name'] == config.RUNNING_STATE:
            ssh_flag = True
            while ssh_flag:
                try:
                    ssh = self.SSH(
                        hostname=self.get_public_dns_name(),
                        username=config.USER_NAME,
                        private_key=config.DEFAULT_PRIVATE_KEY_PATH
                    )
                    for command in commands:
                        stdin, stdout, stderr = ssh.execute_command(command=command)
                        exit_cmd_status = stdout.channel.recv_exit_status()
                        if not exit_cmd_status:  # means the command was successful - similar to echo $?
                            cmd_details = self.Command(stdin=stdin, stdout=stdout, stderr=stderr, command=command)
                            self.commands.append(cmd_details)
                        else:
                            ssh_flag = False
                            raise custom_exceptions.CommandFailureException(
                                cmd=command, instance_id=self.get_instance_id()
                            )
                    ssh.close_connection()
                    ssh_flag = False
                except Exception as error:
                    print(error)

    def modify_files_in_instance(self, path_to_file, mode, data):
        """
        Modify files in linux OS
        """
        transport = paramiko.Transport((self.get_public_dns_name(), config.SSH_PORT))
        transport.connect(username=config.USER_NAME, pkey=config.DEFAULT_PRIVATE_KEY_PATH)
        sftp = paramiko.SFTPClient.from_transport(transport)

        f = sftp.open(filename=path_to_file, mode=mode)
        if mode == "wb":
            f.write(data=data)
        f.close()

    class SSH:
        """
        This is a class to connect with ssh to the instance
        """
        def __init__(self, hostname, username, private_key):
            self.hostname = hostname
            self.username = username
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.private_key = paramiko.RSAKey.from_private_key(open(private_key))
            self.ssh_client.connect(hostname=self.hostname, username=self.username, pkey=self.private_key)

        def execute_command(self, command):
            return self.ssh_client.exec_command(command=command, timeout=10)

        def close_connection(self):
            self.ssh_client.close()

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