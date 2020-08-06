import boto3
import paramiko
from . import config

EC2 = 'ec2'


class Aws:
    """
    This is a class for API calls to the AWS ec2 service per one user

    Attributes:
        client(put here the type of variable) - client for api calls to ec2
        resource(put here the type of variable) - resource for api calls to ec2

    Documentation:
        https://boto3.amazonaws.com/v1/documentation/api/latest/index.html
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#service-resource
    """

    aws_instance = None

    def __init__(self):
        if Aws.aws_instance is not None:
            raise Exception("cannot init the instance, please use Aws.get_aws_instance() method")
        self.client = boto3.client(EC2)
        self.resource = boto3.resource(EC2)
        self.session = boto3.Session()
        Aws.aws_instance = self

    @staticmethod
    def get_aws_instance():
        if Aws.aws_instance is None:
            Aws()
        return Aws.aws_instance

    def get_credentials(self):
        """
        Get the aws access key and aws secret key for the user's session

        Returns:
            tuple(str, str) - The first argument is access key, the second one is secret key
        """
        credentials = self.session.get_credentials()
        credentials = credentials.get_frozen_credentials()
        return credentials.access_key, credentials.secret_key

    def create_new_pair_key(self, kwargs):
        """
        Create new pair key for the user's session

        Args:
            kwargs(dict) - This is the API post request to AWS

        Examples:
            kwargs =
                KeyName='string',
                DryRun=True|False,
                TagSpecifications=[
                {
                    'ResourceType': 'client-vpn-endpoint'|'customer-gateway'
                    'Tags': [
                        {
                            'Key': 'string',
                            'Value': 'string'
                        },
                    ]
                },
            ]
        )
            response = client.create_key_pair(**kwargs)

        Returns:
            bool - True if successful, False otherwise
        """
        return True if self.client.create_key_pair(**kwargs) else False

    def delete_key_pairs(self, kwargs):
        """
        Deletes the specified key pairs

        Args:
            kwargs(dict) - This is the API post request to Aws

        Examples:
            kwargs =
                    KeyName='string',KeyPairId='string',DryRun=True|False

            response = client.delete_key_pair(**kwargs)

        Returns:
            True if successful, False otherwise
        """
        keys_pairs_names = self.get_pair_keys_names()
        for value in kwargs.values():
            if value not in keys_pairs_names:
                return False
        self.client.delete_key_pair(**kwargs)
        return True

    def get_pair_keys_names(self):
        """
        Get all the available key pairs names available in aws

        Returns:
            list(str) - all the pair keys available for the user to authenticate the instance
        """
        keys_list = []
        for key in self.client.describe_key_pairs()['KeyPairs']:
            keys_list.append(key['KeyName'])
        return keys_list

    def get_all_available_instances(self):
        """
        Get all available instances

        Returns:
            list(str) - a list of all instances ids
        """
        instances_ids = []
        response = self.client.describe_instances()
        for reservation in response["Reservations"]:
            for instance in reservation["Instances"]:
                instances_ids.append(instance["InstanceId"])
        return instances_ids

    def get_chosen_state_of_instances(self, state="running"):
        """
        Get all the instances ids according to the requested state

        Args: state(str) - default is running state, state could be : "stopped", "pending", "terminated", "running"

        Returns:
            list(strings) - all instances ids according to requested state

        raises:
            AttributeError in case the requested state is not supported
        """

        available_states = ["stopped", "pending", "terminated", "running"]
        if state not in available_states:
            raise AttributeError(
                "Aws Class - get_chosen_state_of_instances method - the wanted state is not part of available states"
            )
        instances_ids = []
        response = self.client.describe_instances()
        for reservation in response["Reservations"]:
            for instance in reservation["Instances"]:
                if instance["State"]["Name"] == state:
                    instances_ids.append(instance["InstanceId"])
        return instances_ids


class Image:
    """
    This class represents an image in the AWS ec2

    Attributes:
        image_obj (Image) - The object of the image
    """
    aws = Aws.get_aws_instance()

    def __init__(self, image_id):
        """
        Creates a new Image object

        Args:
            image_id  (str) - The image id will be used to define the image object
        """
        self.image_obj = Image.aws.resource.Image(image_id)

    def get_id(self):
        return self.image_obj.image_id

    def get_type(self):
        return self.image_obj.image_type

    def get_state(self):
        return self.image_obj.state

    def reload(self):
        self.image_obj.reload()


class KeyPair:
    """
    This class represents a Key pair in AWS ec2

    Attributes:
        key_pair_obj (KeyPair) - The object of the key pair
    """
    aws = Aws.get_aws_instance()

    def __init__(self, key_name):
        """
        Creates a new keyPair object

        Args:
            key_name (str) - The key pair will be created with the provided given name
        """
        self.key_pair_obj = KeyPair.aws.resource.KeyPair(key_name)

    def get_name(self):
        return self.key_pair_obj.key_name

    def get_id(self):
        return self.key_pair_obj.key_id

    def delete(self, kwargs):
        """
        Deletes the specified key pair, by removing the public key from Amazon EC2.

        Args:
            kwargs =
                KeyPairId='string',
                DryRun=True|False
        """
        self.key_pair_obj.delete(**kwargs)


class SecurityGroup:
    """
    This class represents a security group in AWS ec2

    Attributes:
        security_group_obj (SecurityGroup) - Object of the security group
    """
    aws = Aws.get_aws_instance()

    def __init__(self, kwargs):
        """
            Creates a new security group in the user's session in ec2 AWS

            Args:
                kwargs(dict) - This is the API post request to create a security group in AWS

            Examples:
                kwargs =
                    Description='string',
                    GroupName='string',
                    VpcId='string',
                    TagSpecifications=[
                    {
                        'ResourceType': 'client-vpn-endpoint'|'customer-gateway'
                        'Tags': [
                            {
                                'Key': 'string',
                                'Value': 'string'
                            },
                        ]
                    },
                ],
                    DryRun=True|False
        """
        self.security_group_obj = SecurityGroup.aws.client.create_security_group(**kwargs)

    def get_group_id(self):
        return self.security_group_obj.group_id

    def get_group_name(self):
        return self.security_group_obj.group_name

    def reload(self):
        self.security_group_obj.reload()

    def modify(self, kwargs):
        """
        Modify the security group configuration

        Args:
            kwargs(dict) - This is the API post request to modify a security group in AWS

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
        """
        self.security_group_obj.authorize_ingress(**kwargs)

    def delete(self, kwargs):
        """
        Deletes a security group in ec2 AWS

        Args:
            kwargs =
                GroupId='string',
                GroupName='string',
                DryRun=True|False
        """
        self.security_group_obj.delete(**kwargs)


class Instance:
    """
    This class represents an instance in AWS

    Attributes:
        instance_obj (Instance) - a aws instance type
        commands_list (list(Command)) - a list of all the commands that were executed on this instance

    """
    aws = Aws.get_aws_instance()

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
        self.reload()
        self.commands_list = []

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

    def reload(self):
        self.instance_obj.reload()

    def start(self):
        """
        Start the instance and wait till is is on running state

        """
        if self.get_state()['Name'] == 'stopped':
            self.instance_obj.start()
            self.instance_obj.wait_until_running()
            self.reload()

    def stop(self):
        """
        Stop the instance and wait till it's in a stopped state

        """
        if self.get_state()['Name'] == 'running':
            self.instance_obj.stop()
            self.instance_obj.wait_until_stopped()
            self.reload()

    def reboot(self):
        """
        Reboot the instance and wait till it's in a running state

        """
        if self.get_state()['Name'] == 'running':
            self.instance_obj.reboot()
            self.instance_obj.wait_until_running()
            self.reload()

    def terminate(self):
        """
        Terminate the instance and make the current instance None

        """
        self.instance_obj.terminate()
        self.instance_obj = None

    def execute_commands(self, commands):
        """
        Executes the given commands over the instance using SSH and add them to the commands_list attribute

        Args:
            commands (list(str)) - list of all the commands to execute on the instance

        """
        if self.get_state()['Name'] == 'running':
            ssh_flag = True
            while ssh_flag:
                try:
                    ssh = self.SSH(
                        hostname=self.get_public_dns_name(),
                        username=config.USER_NAME,
                        private_key='/home/gafik/MetasploitFinalProject/default_key_pair_name.pem'
                    )
                    for command in commands:
                        stdin, stdout, stderr = ssh.execute_command(command=command)
                        exit_cmd_status = stdout.channel.recv_exit_status()
                        if not exit_cmd_status:
                            cmd_details = self.Command(
                                stdin=stdin, stdout=stdout, stderr=stderr,
                                instance_id=self.get_instance_id(), command=command
                            )
                            self.commands_list.append(cmd_details)
                        else:
                            ssh_flag = False
                            raise Exception("Command execution failed!")
                    ssh.close_connection()
                    ssh_flag = False
                except Exception as error:
                    print(error)
            print("done")

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
            instance_id (str) - The instance that this command was executed on
            command (str) - The command name that was executed

        stdout and stderr can be treated as python files, if you want to print all the out put according to lines:
            for line in stdout.read().splitlines():
                print(line)
        """

        def __init__(self, stdin, stdout, stderr, instance_id, command):
            self._stdin = stdin
            self._stdout = stdout
            self._stderr = stderr
            self._instance_id = instance_id
            self._command = command

        def get_stdin(self):
            return self._stdin

        def get_stdout(self):
            return self._stdout

        def get_stderr(self):
            return self._stderr

        def get_instance_id(self):
            return self._instance_id

        def get_executed_command_name(self):
            return self._command


ins = Instance(config.CREATE_INSTANCES_DICT)
ins.execute_commands(['sudo yum install -y docker'])


#
# # aws.get_credentials()
# # print(aws.get_pair_keys_names())
# # print(aws.delete_key_pairs(**{"KeyName": "myFirstInstance"}))
# group_id = aws.create_security_group(GroupName='new_security_group', Description='something')
# aws.modify_security_group(group_id=group_id, IpProtocol='tcp', FromPort=22, ToPort=22, CidrIp='0.0.0.0/0')
#aws.create_instances(config.CREATE_INSTANCES_DICT)
# print("all done")
# aws.stop_instances()
#aws.get_chosen_state_of_instances("terminated")
# aws.launch_instances()
# aws.stop_instances()