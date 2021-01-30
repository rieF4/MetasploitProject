

CREATE_MSFRPCD_CONTAINER_URL = '/DockerServerInstances/{instance_id}/Containers/CreateMetasploitContainer'
GET_CONTAINERS_URL = '/DockerServerInstances/{instance_id}/Containers/Get'
GET_CONTAINER_URL = '/DockerServerInstances/{instance_id}/Containers/Get/{container_id}'
DELETE_CONTAINER_URL = '/DockerServerInstances/{instance_id}/Containers/Delete/{container_id}'

EXPECTED_NEW_CONTAINER_RESPONSE = {
    "image": [
        "phocean/msf:latest"
    ],
    "ports": {
        "50000/tcp": [
            {
                "HostIp": "0.0.0.0",
                "HostPort": "50000"
            }
        ]
    },
    "status": "running"
}

INVALID_CONTAINER_ID = "2c152455e2c4913a257a2a549bd16b2a8630a08a3a5b2347539d"
CONTAINER_NOT_FOUND_MSG = "404 Client error: Container with ID {invalid_container_id} was not found"
