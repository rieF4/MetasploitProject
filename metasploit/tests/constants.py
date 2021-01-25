

CREATE_DOCKER_SERVER = '/DockerServerInstances/Create'
DELETE_DOCKER_SERVER = '/DockerServerInstances/Delete/{instance_id}'
GET_ALL_DOCKER_SERVERS = '/DockerServerInstances/Get'
GET_DOCKER_SERVER = '/DockerServerInstances/Get/{instance_id}'

CREATE_DOCKER_SERVER_REQUEST = {
    "ImageId": "ami-016b213e65284e9c9",
    "InstanceType": "t2.micro"
}

CONTAINERS = "Containers"
METASPLOIT = "Metasploit"
SECURITY_GROUPS = "SecurityGroups"
STATE = "State"
IP_PARAMETERS = "IpParameters"
ID = "_id"
