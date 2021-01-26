

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
