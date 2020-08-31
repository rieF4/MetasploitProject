# import paramiko
# from metasploit.venv.Aws.Instance import Instance
# from metasploit.venv.Aws import config
# from metasploit.venv.Aws import Aws
#
#
# aws_api = Aws.get_aws_access_instance()
#
#
# class SSH:
#     """
#     This is a class to connect with ssh to a remote machine.
#
#     Attributes:
#         _ssh_client (SSHClient): a SSHClient for the remote server.
#         _private_key (str): a private key used to authenticate the server.
#         _sftp (SFTPClient): the SFTPClient that is connected to the server.
#     """
#
#     def __init__(self, hostname, username, private_key):
#         """
#         initialize the SSH class with a new connection to a remote machine.
#
#         Args:
#             hostname (str): host name to connect.
#             username (str): user name of the host name.
#             private_key (str): the private key to authenticate the hostname.
#         """
#         self._ssh_client = paramiko.SSHClient()
#         self._ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#         self._private_key = paramiko.RSAKey.from_private_key(open(private_key))
#         while True:
#             try:
#                 self._ssh_client.connect(hostname=hostname, username=username, pkey=self._private_key)
#                 break
#             except Exception:
#                 pass
#         self._sftp = self._ssh_client.open_sftp()
#
#     def get_client(self):
#         """
#         Returns the SSH client
#
#         Returns:
#             SSHClient: a SSHClient for the remote server.
#         """
#         return self._ssh_client
#
#     def get_sftp(self):
#         """
#         Open an SFTP session on the SSH server.
#
#         Returns:
#             SFTPClient: The SFTPClient to the server.
#         """
#         return self._sftp
#
#     def get_private_key(self):
#         """
#         Returns the private key used to authenticate the server.
#
#         Returns:
#             str: the private key for the server.
#         """
#         return self._private_key
#
#
# def create_security_group(kwargs):
#     """
#     Creates a new security group in ec2 AWS.
#
#         Args:
#             kwargs(dict) - This is the API post request to create a security group in AWS.
#
#         Examples:
#             kwargs =
#                 Description='string',
#                 GroupName='string',
#                 VpcId='string',
#                 TagSpecifications=[
#                 {
#                     'ResourceType': '_client-vpn-endpoint'|'customer-gateway'
#                     'Tags': [
#                         {
#                             'Key': 'string',
#                             'Value': 'string'
#                         },
#                     ]
#                 },
#             ],
#                 DryRun=True|False
#
#         Returns:
#             SecurityGroup: a security group object of AWS, None otherwise.
#     """
#     try:
#         return aws_api.get_client().create_security_group(**kwargs)
#     except Exception:
#         return None
#
#
# def modify_security_group(security_group_id, kwargs):
#     """
#     Modify the security group configuration.
#
#             Args:
#                 security_group_id (str) - The security group id that should be modified.
#                 kwargs(dict) - This is the API post request to modify a security group in AWS.
#
#             Examples:
#                 kwargs =
#                          DryRun=True|False,
#                          IpPermissions=[
#                     {
#                         'FromPort': 123,
#                         'IpProtocol': 'string',
#                         'IpRanges': [
#                             {
#                                 'CidrIp': 'string',
#                                 'Description': 'string'
#                             },
#                         ],
#                         'Ipv6Ranges': [
#                             {
#                                 'CidrIpv6': 'string',
#                                 'Description': 'string'
#                             },
#                         ],
#                         'PrefixListIds': [
#                         {
#                             'Description': 'string',
#                             'PrefixListId': 'string'
#                         },
#                      ],
#                     'ToPort': 123,
#                     'UserIdGroupPairs': [
#                         {
#                             'Description': 'string',
#                             'GroupId': 'string',
#                             'GroupName': 'string',
#                             'PeeringStatus': 'string',
#                             'UserId': 'string',
#                             'VpcId': 'string',
#                             'VpcPeeringConnectionId': 'string'
#                         },
#                     ]
#                 },
#             ],
#                         CidrIp='string',
#                         FromPort=123,
#                         IpProtocol='string',
#                         ToPort=123,
#                         SourceSecurityGroupName='string',
#                         SourceSecurityGroupOwnerId='string'
#             Returns:
#                 True if success security group modification was successful, False otherwise
#     """
#     try:
#         aws_api.get_resource().SecurityGroup(security_group_id).authorize_ingress(**kwargs)
#         return True
#     except Exception:
#         return False
#
#
# def create_instance(kwargs):
#     """
#     Args:
#         kwargs (dict) - The API post request to create the instance.
#
#         Examples:
#             kwargs =
#             ImageId='ami-0bdcc6c05dec346bf',
#             InstanceType='t2.micro',
#             MaxCount=1,
#             MinCount=1,
#             KeyName='MyFirstInstance'
#             SecurityGroupIds=['group_id']
#
#         instance = self._resource.create_instances(**kwargs)
#         The get API call is an instance object
#
#     Returns:
#         Instance: instance object if successful, None otherwise
#             """
#     try:
#         return Instance(**kwargs)
#     except Exception:
#         return None
#
#
# def init_docker_server_on_instance(instance):
#     instance.execute_shell_commands(
#         commands=[
#             'sudo yum install -y docker',
#             'sudo systemctl start docker',
#             'sudo chmod 666 /var/run/docker.sock',
#             'sudo touch /etc/docker/daemon.json',
#             'sudo chmod 666 /etc/docker/daemon.json',
#             'sudo mkdir /etc/systemd/system/docker.service.d',
#             'sudo touch /etc/systemd/system/docker.service.d/override.conf',
#             'sudo chmod 666 /etc/systemd/system/docker.service.d/override.conf'
#         ]
#     )
#
#     instance.write_to_file(
#         filename='/etc/docker/daemon.json',
#         mode='w',
#         data='{"hosts": ["tcp://0.0.0.0:2375", "unix:///var/run/docker.sock"]}\n'
#     )
#
#     instance.write_to_file(
#         filename='/etc/systemd/system/docker.service.d/override.conf',
#         mode='w',
#         data='[Service]\nExecStart=\nExecStart=/usr/bin/dockerd\n'
#     )
#
#     instance.execute_shell_commands(
#         commands=[
#             'sudo systemctl daemon-reload',
#             'sudo systemctl restart docker.service',
#             'sudo chmod 666 /var/run/docker.sock'
#         ]
#     )
#
#

