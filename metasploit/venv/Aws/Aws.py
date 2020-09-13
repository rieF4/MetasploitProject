import boto3
import docker
import paramiko
from metasploit.venv.Aws import custom_exceptions
from metasploit.venv.Aws import config
from botocore.exceptions import ClientError, ParamValidationError

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
            raise custom_exceptions.InitializeNewInstanceUsingConstructorException()
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

    # def get_credentials(self):
    #     """
    #     Get the aws access key and aws secret key for the user's _session
    # 
    #     Returns:
    #         tuple(str, str) - The first argument is access key, the second one is secret key
    #     """
    #     credentials = self._session.get_credentials().get_frozen_credentials()
    #     
    #     return credentials.access_key, credentials.secret_key
    # 
    # def create_new_pair_key(self, kwargs):
    #     """
    #     Create new pair key for the user's _session
    # 
    #     Args:
    #         kwargs(dict) - This is the API post request to AWS
    # 
    #     Examples:
    #         kwargs =
    #             KeyName='string',
    #             DryRun=True|False,
    #             TagSpecifications=[
    #             {
    #                 'ResourceType': '_client-vpn-endpoint'|'customer-gateway'
    #                 'Tags': [
    #                     {
    #                         'Key': 'string',
    #                         'Value': 'string'
    #                     },
    #                 ]
    #             },
    #         ]
    #     )
    #         response = _client.create_key_pair(**kwargs)
    # 
    #     Returns:
    #         bool - True if successful, False otherwise
    #     """
    #     return True if self._client.create_key_pair(**kwargs) else False
    # 
    # def delete_key_pairs(self, kwargs):
    #     """
    #     Deletes the specified key pairs
    # 
    #     Args:
    #         kwargs(dict) - This is the API post request to AwsAccess
    # 
    #     Examples:
    #         kwargs =
    #                 KeyName='string',KeyPairId='string',DryRun=True|False
    # 
    #         response = _client.delete_key_pair(**kwargs)
    # 
    #     Returns:
    #         True if successful, False otherwise
    #     """
    #     keys_pairs_names = self.get_pair_keys_names()
    #     for value in kwargs.values():
    #         if value not in keys_pairs_names:
    #             return False
    #     self._client.delete_key_pair(**kwargs)
    #     return True
    # 
    # def get_pair_keys_names(self):
    #     """
    #     Get all the available key pairs names available in aws
    # 
    #     Returns:
    #         list(str) - all the pair keys available for the user to authenticate the instance
    #     """
    #     keys_list = []
    #     for key in self._client.describe_key_pairs()['KeyPairs']:
    #         keys_list.append(key['KeyName'])
    #     return keys_list
    # 
    # def get_all_available_instances(self):
    #     """
    #     Get all available instances
    # 
    #     Returns:
    #         list(str) - a list of all instances ids
    #     """
    #     instances_ids = []
    #     response = self._client.describe_instances()
    #     for reservation in response["Reservations"]:
    #         for instance in reservation["Instances"]:
    #             instances_ids.append(instance["InstanceId"])
    #     return instances_ids
    # 
    # def get_chosen_state_of_instances(self, state="running"):
    #     """
    #     Get all the instances ids according to the requested state
    # 
    #     Args: state(str) - default is running state, state could be : "stopped", "pending", "terminated", "running"
    # 
    #     Returns:
    #         list(strings) - all instances ids according to requested state
    # 
    #     raises:
    #         AttributeError in case the requested state is not supported
    #     """
    # 
    #     available_states = ["stopped", "pending", "terminated", "running"]
    #     if state not in available_states:
    #         raise AttributeError(
    #             "AwsAccess Class - get_chosen_state_of_instances method - the wanted state is not part of available states"
    #         )
    #     instances_ids = []
    #     response = self._client.describe_instances()
    #     for reservation in response["Reservations"]:
    #         for instance in reservation["Instances"]:
    #             if instance["State"]["Name"] == state:
    #                 instances_ids.append(instance["InstanceId"])
    #     return instances_ids



# class KeyPair:
#     """
#     This class represents a Key pair in AWS ec2
#
#     Attributes:
#         key_pair_obj (KeyPair) - The object of the key pair
#     """
#     aws = AwsAccess.get_aws_access_instance()
#
#     def __init__(self, key_name):
#         """
#         Creates a new keyPair object
#
#         Args:
#             key_name (str) - The key pair will be created with the provided given name
#         """
#         self.key_pair_obj = KeyPair.aws.resource.KeyPair(key_name)
#
#     def get_name(self):
#         return self.key_pair_obj.key_name
#
#     def get_id(self):
#         return self.key_pair_obj.key_id
#
#     def delete(self, kwargs):
#         """
#         Deletes the specified key pair, by removing the public key from Amazon EC2.
#
#         Args:
#             kwargs =
#                 KeyPairId='string',
#                 DryRun=True|False
#         """
#         self.key_pair_obj.delete(**kwargs)


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
                username=config.USER_NAME,
                private_key=config.DEFAULT_PRIVATE_KEY_PATH
            )

        if init_docker_server_flag:
            self._init_docker_server_on_instance()

        self._docker = Docker(
            protocol='tcp', docker_server_ip=self.get_public_ip_address(), docker_port=config.DOCKER_PORT
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
            commands=config.MAKE_DOCKER_FILES_COMMANDS
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
            commands=config.RELOAD_DOCKER_DAEMON
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


class SSH:
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


def get_security_group_object(id):
    """
    Returns the security group object by the ID.

    Args:
        id (str): security group ID.

    Returns:
        SecurityGroup: a security group object
    """
    return aws_api.get_resource().SecurityGroup(id)


def create_security_group(kwargs):
    """
    Creates a new security group in ec2 AWS.

        Args:
            kwargs(dict) - This is the API post request to create a security group in AWS.

        Examples:
            kwargs =
                Description='string',
                GroupName='string',
                VpcId='string',
                TagSpecifications=[
                {
                    'ResourceType': '_client-vpn-endpoint'|'customer-gateway'
                    'Tags': [
                        {
                            'Key': 'string',
                            'Value': 'string'
                        },
                    ]
                },
            ],
                DryRun=True|False

        Returns:
            SecurityGroup: a security group object if created.

        Raises:
            ParamValidationError: in case kwargs params are not valid to create a new security group.
            ClientError: in case there is a duplicate security group that exits with the same name.
    """
    return get_security_group_object(aws_api.get_client().create_security_group(**kwargs)['GroupId'])


def modify_security_group(security_group_id, kwargs):
    """
    Modify the security group configuration.

            Args:
                security_group_id (str) - The security group id that should be modified.
                kwargs(dict) - This is the API post request to modify a security group in AWS.

            Examples:
                kwargs =
                         DryRun=True|False,
                         IpPermissions=[
                    {
                        'FromPort': 123,
                        'IpProtocol': 'string',
                        'IpRanges': [
                            {
                                'CidrIp': 'string',
                                'Description': 'string'
                            },
                        ],
                        'Ipv6Ranges': [
                            {
                                'CidrIpv6': 'string',
                                'Description': 'string'
                            },
                        ],
                        'PrefixListIds': [
                        {
                            'Description': 'string',
                            'PrefixListId': 'string'
                        },
                     ],
                    'ToPort': 123,
                    'UserIdGroupPairs': [
                        {
                            'Description': 'string',
                            'GroupId': 'string',
                            'GroupName': 'string',
                            'PeeringStatus': 'string',
                            'UserId': 'string',
                            'VpcId': 'string',
                            'VpcPeeringConnectionId': 'string'
                        },
                    ]
                },
            ],
                        CidrIp='string',
                        FromPort=123,
                        IpProtocol='string',
                        ToPort=123,
                        SourceSecurityGroupName='string',
                        SourceSecurityGroupOwnerId='string'
            Raises:
                ParamValidationError: in case kwargs params are not valid to create a new security group.
                ClientError: in case the security group ID is not valid.
    """
    aws_api.get_resource().SecurityGroup(security_group_id).authorize_ingress(**kwargs)


def create_instance(kwargs):
    """
    Args:
        kwargs (dict) - The API post request to create the instance.

        Examples:
            kwargs =
            ImageId='ami-0bdcc6c05dec346bf',
            InstanceType='t2.micro',
            MaxCount=1,
            MinCount=1,
            KeyName='MyFirstInstance'
            SecurityGroupIds=['group_id']

        instance = self._resource.create_instances(**kwargs)
        The get API call is an instance object

    Returns:
        DockerServerInstance: instance object if successful, None otherwise
    """
    try:
        aws_instance = aws_api.get_resource().create_instances(**kwargs)[0]
        aws_instance.wait_until_running()
        aws_instance.reload()
        return DockerServerInstance(instance_obj=aws_instance, ssh_flag=True, init_docker_server_flag=True)
    except Exception as e:
        print(e)
        return None


def get_docker_server_instance(id, ssh_flag=False):
    """
    Get the docker server instance object.

    Args:
        id (str): instance id.
        ssh_flag (bool): True if ssh connection needs to be deployed, False otherwise.

    Returns:
        DockerServerInstance: a docker server object if exits, None otherwise.
    """
    try:
        return DockerServerInstance(instance_obj=aws_api.get_resource().Instance(id), ssh_flag=ssh_flag)
    except Exception as e:
        print(e)
        return None


def create_container(instance, image, command, kwargs):
    """
    Create a container over a an instance ID.

    Args:
        instance (DockerServerInstance): instance docker server object.
        image (str): image name that the docker will be created with.
        command (str): the command to run on the container.
        kwargs (dict): Keyword arguments: https://docker-py.readthedocs.io/en/stable/containers.html#container-objects

    Returns:
        Container: a container object if created successfully, False otherwise.
    """
    try:
        return instance.get_docker().get_container_collection().create(
            image=image, command=command, **kwargs
        )
    except Exception as e:
        print(e)
        return None


def create_new_key_pair(key_name):
    """
    Creates a new keyPair object.

    Args:
        key_name (str) - The key pair will be created with the provided given name.

    Returns:
        KeyPair: a key pair object in AWS.
    """
    try:
        return aws_api.get_resource().KeyPair(key_name)
    except Exception:
        return None



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


aws_api = AwsAccess.get_aws_access_instance()



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

