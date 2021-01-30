
CREATE_DOCKER_SERVER_URL = '/DockerServerInstances/Create'
DELETE_DOCKER_SERVER_URL = '/DockerServerInstances/Delete/{instance_id}'
GET_ALL_DOCKER_SERVERS_URL = '/DockerServerInstances/Get'
GET_DOCKER_SERVER_URL = '/DockerServerInstances/Get/{instance_id}'

CREATE_DOCKER_SERVER_REQUEST = {
    "ImageId": "ami-016b213e65284e9c9",
    "InstanceType": "t2.micro"
}
CREATE_DOCKER_REQUEST_WITHOUT_IMAGE_ID = {
     "InstanceType": "t2.micro"
}
CREATE_DOCKER_REQUEST_WITHOUT_INSTANCE_TYPE = {
    "ImageId": "ami-016b213e65284e9c9"
}
CREATE_DOCKER_REQUEST_EMPTY_JSON = {}

EXPECTED_RESPONSE_FOR_NEW_DOCKER_SERVER = {
    "containers": [],
    "metasploit": [],
    "state": {"Code": 16, "Name": "running"}
}

INVALID_INSTANCE_ID = "i-07841d983a"
INSTANCE_NOT_FOUND_MSG = "404 Client error: Instance with ID {invalid_instance_id} was not found"

CONTAINERS = "Containers"
METASPLOIT = "Metasploit"
SECURITY_GROUPS = "SecurityGroups"
STATE = "State"
IP_PARAMETERS = "IpParameters"
ID = "_id"
