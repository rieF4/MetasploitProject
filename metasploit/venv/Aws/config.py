

DEFAULT_SECURITY_GROUP_ID = 'sg-08604b8d820a35de6'
DEFAULT_CPU_TYPE = 't2.micro'
DEFAULT_IMAGE_ID = 'ami-016b213e65284e9c9'
DEFAULT_PAIR_KEY_NAME = 'default_key_pair_name'
DEFAULT_PRIVATE_KEY_PATH = '/home/gafik/MetasploitProject/default_key_pair_name.pem'
DEFAULT_MAX_MIN_COUNT = 1

SSH_PORT = 22
IP_PROTOCOL = 'tcp'
CIDR_IP = '0.0.0.0/0'

CREATE_INSTANCES_DICT = {"ImageId": DEFAULT_IMAGE_ID,
                     'InstanceType': DEFAULT_CPU_TYPE,
                     'MaxCount': DEFAULT_MAX_MIN_COUNT, 'MinCount': DEFAULT_MAX_MIN_COUNT,
                     'KeyName': DEFAULT_PAIR_KEY_NAME,
                     'SecurityGroupIds': [DEFAULT_SECURITY_GROUP_ID]}

MODIFY_SECURITY_GROUP_DICT = {'group_id': DEFAULT_SECURITY_GROUP_ID,
                              'IpProtocol': IP_PROTOCOL,
                              'FromPort': SSH_PORT,
                              'ToPort': SSH_PORT,
                              'CidrIp': CIDR_IP}

SEND_COMMAND_DICT = {'InstanceIds': ['i-0d88035ac1884d2f6'],
                     "DocumentName": 'AWS-RunShellScript',
                     "Parameters": {'commands': ["ls -la"]}}

USER_NAME = 'ec2-user'
RUNNING_STATE = 'running'
STOPPED_STATE = 'stopped'
