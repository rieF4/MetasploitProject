

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
