
from metasploit.api.logic.services import DockerServerService
from metasploit.api.database import DatabaseOperations, DatabaseCollections
from metasploit.api.aws.amazon_operations import create_instance
from metasploit.api.aws import constants as aws_const
from metasploit.api.aws.amazon_operations import DockerServerInstanceOperations
from metasploit.api.response import (
    create_new_response
)
from metasploit.api.utils.decorators import (
    validate_json_request
)


class DockerServerServiceImplementation(DockerServerService):
    """
    Implements the docker server instance service.

    Attributes:
        database (DatabaseOperations): DatabaseOperations object.
    """
    type = "Instance"

    def __init__(self):
        self.database = DatabaseOperations(collection_type=DatabaseCollections.INSTANCES)

    def create(self, *args, **kwargs):
        return self.create_docker_server(**kwargs)

    def get_all(self):
        return self.get_all_docker_servers()

    def get_one(self, *args, **kwargs):
        return self.get_docker_server(**kwargs)

    def delete_one(self, *args, **kwargs):
        return self.delete_docker_server(**kwargs)

    def get_docker_server(self, instance_id):
        """
        Gets a docker server from the DB

        Args:
            instance_id (str): instance ID.

        Returns:
            dict: docker server document in case found
        """
        return self.database.get_amazon_document(type=self.type, resource_id=instance_id)

    def get_all_docker_servers(self):
        """
        Gets all available docker servers from the DB.

        Returns:
            list(dict): docker server documents in case there are, empty list otherwise
        """
        return self.database.get_all_documents()

    @validate_json_request("ImageId", "InstanceType")
    def create_docker_server(self, docker_server_json):
        """
        Creates a docker server instance.

        docker_server_json example:

        {
            "ImageId": "ami-016b213e65284e9c9",
            "InstanceType": "t2.micro"
        }

        Args:
            docker_server_json (dict): docker server Json input from the client.

        Returns:
            dict: a new docker server document.
        """
        new_docker_server = create_instance(
            ImageId=docker_server_json.get("ImageId"),
            InstanceType=docker_server_json.get("InstanceType"),
            KeyName=aws_const.DEFAULT_PAIR_KEY_NAME,
            SecurityGroupIds=[aws_const.DEFAULT_SECURITY_GROUP_ID],
            MaxCount=aws_const.DEFAULT_MAX_MIN_COUNT,
            MinCount=aws_const.DEFAULT_MAX_MIN_COUNT
        )

        docker_server_response = create_new_response(obj=new_docker_server, response_type=self.type)
        self.database.insert_amazon_document(new_amazon_document=docker_server_response)

        return docker_server_response

    def delete_docker_server(self, instance_id):
        """
        Deletes a docker server from the DB.

        Args:
            instance_id (str): instance ID.

        Returns:
            empty string as a response in case of success.
        """
        self.database.delete_amazon_document(resource_id=instance_id, type=self.type)
        DockerServerInstanceOperations(instance_id=instance_id).docker_server.terminate()
        return ''
