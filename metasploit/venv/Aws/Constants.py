

DEFAULT_SECURITY_GROUP_ID = 'sg-08604b8d820a35de6'
DEFAULT_CPU_TYPE = 't2.micro'
DEFAULT_IMAGE_ID = 'ami-016b213e65284e9c9'
DEFAULT_PAIR_KEY_NAME = 'default_key_pair_name'
DEFAULT_PRIVATE_KEY_PATH = '/home/gafik/MetasploitProject/default_key_pair_name.pem'
DEFAULT_MAX_MIN_COUNT = 1

ID = "_id"
CONTAINERS = "Containers"
CONTAINER = "Container"
DOCKER = "Docker"
PUSH = "$push"
SET = "$set"
INSTANCES = "Instances"
INSTANCE = "Instance"
SECURITY_GROUPS = "SecurityGroups"
SECURITY_GROUP = "SecurityGroup"
IMAGES = "Images"

SSH_PORT = 22
DOCKER_PORT = 2375
IP_PROTOCOL = 'tcp'
CIDR_IP = '0.0.0.0/0'

CREATE_INSTANCES_DICT = {
    "ImageId": DEFAULT_IMAGE_ID,
    'InstanceType': DEFAULT_CPU_TYPE,
    'MaxCount': DEFAULT_MAX_MIN_COUNT,
    'MinCount': DEFAULT_MAX_MIN_COUNT,
    'KeyName': DEFAULT_PAIR_KEY_NAME,
    'SecurityGroupIds': [DEFAULT_SECURITY_GROUP_ID]
}

CREATE_SECURITY_GROUP_DICT = {
    'Description': 'Metasploit project security group',
    'GroupName': 'MetasploitSecurityGroup'
}

MODIFY_SECURITY_GROUP_DICT = {
    'IpProtocol': IP_PROTOCOL,
    'FromPort': SSH_PORT,
    'ToPort': SSH_PORT,
    'CidrIp': CIDR_IP
}

USER_NAME = 'ec2-user'
RUNNING_STATE = 'running'
STOPPED_STATE = 'stopped'

MAKE_DOCKER_FILES_COMMANDS = [
    'sudo yum install -y docker',
    'sudo systemctl start docker',
    'sudo chmod 666 /var/run/docker.sock',
    'sudo touch /etc/docker/daemon.json',
    'sudo chmod 666 /etc/docker/daemon.json',
    'sudo mkdir /etc/systemd/system/docker.service.d',
    'sudo touch /etc/systemd/system/docker.service.d/override.conf',
    'sudo chmod 666 /etc/systemd/system/docker.service.d/override.conf'
]

RELOAD_DOCKER_DAEMON = [
    'sudo systemctl daemon-reload',
    'sudo systemctl restart docker.service',
    'sudo chmod 666 /var/run/docker.sock'
]