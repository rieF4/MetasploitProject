
from metasploit.api.interfaces.services import DockerServerService
from metasploit.api.database import DatabaseOperations, DatabaseCollections
from metasploit.aws.amazon_operations import create_instance
from metasploit.api.errors import AmazonResourceNotFoundError, DeleteDatabaseError
from metasploit.api import response
from metasploit.aws import constants as aws_const
from metasploit.aws.amazon_operations import DockerServerInstanceOperations


class DockerServerServiceImplementation(DockerServerService):

    type = "Instance"

    def __init__(self):
        self.database = DatabaseOperations(collection_type=DatabaseCollections.INSTANCES)

    def create(self, *args, **kwargs):
        return self.create_docker_server(docker_server_json=kwargs.get("docker_server_json"))

    def get_all(self):
        return self.get_all_docker_servers()

    def get_one(self, *args, **kwargs):
        return self.get_docker_server(instance_id=kwargs.get("instance_id"))

    def delete_one(self, *args, **kwargs):
        return self.delete_docker_server(instance_id=kwargs.get("instance_id"))

    def get_docker_server(self, instance_id):
        """
        Gets a docker server from the DB

        Args:
            instance_id (str): instance ID.

        Returns:
            ApiResponse: parsed ApiResponse obj with the docker server instance document in case of success
        """
        try:
            return response.ApiResponse(
                response=self.database.get_amazon_document(type=self.type, resource_id=instance_id),
                http_status_code=response.HttpCodes.OK
            ).make_response
        except AmazonResourceNotFoundError as err:
            return response.ErrorResponse(
                error_msg=str(err), http_error_code=response.HttpCodes.NOT_FOUND
            ).make_response


    def get_all_docker_servers(self):
        """
        Gets all available docker servers from the DB.

        Returns:
            ApiResponse: parsed ApiResponse obj with the docker server instance documents.
        """
        return response.ApiResponse(response=self.database.get_all_amazon_documents()).make_response

    def create_docker_server(self, docker_server_json):
        """
        Creates a docker server

        docker_server_json example:

        {
            "ImageId": "ami-016b213e65284e9c9",
            "InstanceType": "t2.micro"
        }

        Args:
            docker_server_json (dict): docker server Json input from the client.

        Returns:
            ApiResponse: parsed ApiResponse obj with a new docker server instance document.
        """

        new_docker_server = create_instance(
            ImageId=docker_server_json.get("ImageId"),
            InstanceType=docker_server_json.get("InstanceType"),
            KeyName=aws_const.DEFAULT_PAIR_KEY_NAME,
            SecurityGroupIds=[aws_const.DEFAULT_SECURITY_GROUP_ID],
            MaxCount=aws_const.DEFAULT_MAX_MIN_COUNT,
            MinCount=aws_const.DEFAULT_MAX_MIN_COUNT
        )

        docker_server_response = response.create_new_response(obj=new_docker_server, response_type=self.type)
        self.database.insert_amazon_document(new_amazon_document=docker_server_response)

        return response.ApiResponse(
            response=docker_server_response, http_status_code=response.HttpCodes.OK
        ).make_response

    def delete_docker_server(self, instance_id):
        """
        Deletes a docker server from the DB.

        Args:
            instance_id (str): instance ID.
        """
        try:
            DockerServerInstanceOperations(instance_id=instance_id).docker_server.terminate()
            self.database.delete_amazon_document(resource_id=instance_id, type=self.type)
            return response.ApiResponse(response='', http_status_code=response.HttpCodes.NO_CONTENT).make_response
        except DeleteDatabaseError as err:
            return response.ErrorResponse(
                error_msg=str(err), http_error_code=response.HttpCodes.INTERNAL_SERVER_ERROR
            ).make_response
