from metasploit.api.interfaces.services import ContainerService
from metasploit.api.database import (
    DatabaseOperations,
    DatabaseCollections
)
from metasploit.docker.docker_operations import ContainerOperations
from metasploit.api.errors import (
    AmazonResourceNotFoundError,
    DockerResourceNotFoundError,
    UpdateDatabaseError,
    ContainerCommandFailure
)
from metasploit.utils.decorators import update_containers_status
from metasploit.api import response


class ContainerServiceImplementation(ContainerService):

    type = "Container"

    def __init__(self):
        self.database = DatabaseOperations(collection_type=DatabaseCollections.INSTANCES)

    def create(self, *args, **kwargs):
        return self.create_metasploit_container(instance_id=kwargs.get("instance_id"))

    def get_all(self, *args, **kwargs):
        return self.get_all_containers(instance_id=kwargs.get("instance_id"))

    def get_one(self, *args, **kwargs):
        return self.get_container(instance_id=kwargs.get("instance_id"), container_id=kwargs.get("container_id"))

    def delete_one(self, *args, **kwargs):
        return self.delete_container(instance_id=kwargs.get("instance_id"), container_id=kwargs.get("container_id"))

    @update_containers_status
    def get_container(self, instance_id, container_id):
        """
        Gets a container from the DB.

        Args:
            instance_id (str): instance ID.
            container_id (str): container ID.

        Returns:
            ApiResponse: parsed ApiResponse obj with the container document in case of success.
        """
        try:
            return response.ApiResponse(
                response=self.database.get_docker_document(
                    amazon_resource_id=instance_id, docker_resource_id=container_id, type=self.type
                )
            ).make_response
        except (AmazonResourceNotFoundError, DockerResourceNotFoundError) as err:
            return response.ErrorResponse(
                error_msg=str(err), http_error_code=response.HttpCodes.NOT_FOUND
            ).make_response

    @update_containers_status
    def get_all_containers(self, instance_id):
        """
        Gets all containers from the DB.

        Args:
            instance_id (str): instance ID.

        Returns:
            ApiResponse: parsed ApiResponse obj with the container document(s) in case of success.
        """
        try:
            return response.ApiResponse(
                response=self.database.get_docker_documents(amazon_resource_id=instance_id, type=self.type)
            ).make_response
        except AmazonResourceNotFoundError as err:
            return response.ErrorResponse(
                error_msg=str(err), http_error_code=response.HttpCodes.NOT_FOUND
            ).make_response

    def create_metasploit_container(self, instance_id):
        """
        Creates a new metasploit container over a docker server instance.

        Args:
            instance_id (str): instance ID.

        Returns:
            ApiResponse: parsed ApiResponse obj without any content and 200 OK if success
        """
        all_containers_documents = self.database.get_docker_documents(amazon_resource_id=instance_id, type=self.type)

        try:
            new_container = ContainerOperations(
                docker_server_id=instance_id
            ).run_container_with_msfrpcd_metasploit(containers_documents=all_containers_documents)

            container_response = response.create_new_response(obj=new_container, response_type=self.type)

            self.database.add_docker_document(
                amazon_resource_id=instance_id, docker_document_type=self.type, new_docker_document=container_response
            )

            return response.ApiResponse(response=container_response).make_response

        except (ContainerCommandFailure, UpdateDatabaseError) as err:
            return response.ErrorResponse(
                error_msg=str(err), http_error_code=response.HttpCodes.INTERNAL_SERVER_ERROR
            ).make_response

    def delete_container(self, instance_id, container_id):
        """
        Deletes a container from the DB.

        Args:
            instance_id (str): instance ID.
            container_id (str): container ID.

        Returns:
            ApiResponse: parsed ApiResponse obj with the container document(s) in case of success.
        """
        try:
            ContainerOperations(
                docker_server_id=instance_id, docker_resource_id=container_id
            ).container.remove(force=True)

            self.database.delete_docker_document(
                amazon_resource_id=instance_id, docker_resource_id=container_id, docker_document_type=self.type
            )
            return response.ApiResponse(response='', http_status_code=response.HttpCodes.NO_CONTENT).make_response
        except UpdateDatabaseError as err:
            return response.ErrorResponse(
                error_msg=str(err), http_error_code=response.HttpCodes.INTERNAL_SERVER_ERROR
            ).make_response
