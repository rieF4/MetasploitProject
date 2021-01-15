from metasploit.api.interfaces.services import ContainerService
from metasploit.api.database import (
    DatabaseOperations,
    DatabaseCollections
)
from metasploit.docker.docker_operations import ContainerOperations

from metasploit.utils.decorators import (
    update_containers_status,
    response_decorator
)
from metasploit.api.response import (
    HttpCodes,
    create_new_response
)


class ContainerServiceImplementation(ContainerService):

    type = "Container"

    def __init__(self):
        self.database = DatabaseOperations(collection_type=DatabaseCollections.INSTANCES)

    def create(self, *args, **kwargs):
        return self.create_metasploit_container(**kwargs)

    def get_all(self, *args, **kwargs):
        return self.get_all_containers(**kwargs)

    def get_one(self, *args, **kwargs):
        return self.get_container(**kwargs)

    def delete_one(self, *args, **kwargs):
        return self.delete_container(**kwargs)

    @update_containers_status
    @response_decorator(HttpCodes.OK)
    def get_container(self, instance_id, container_id):
        """
        Gets a container from the DB.

        Args:
            instance_id (str): instance ID.
            container_id (str): container ID.

        Returns:
            dict: a container document in case found.
        """
        return self.database.get_docker_document(
            amazon_resource_id=instance_id, docker_resource_id=container_id, type=self.type
        )

    @update_containers_status
    @response_decorator(HttpCodes.OK)
    def get_all_containers(self, instance_id):
        """
        Gets all containers from the DB.

        Args:
            instance_id (str): instance ID.

        Returns:
            list(dict): a list of container documents in case there are, empty list otherwise.
        """
        return self.database.get_docker_documents(amazon_resource_id=instance_id, type=self.type)

    @response_decorator(HttpCodes.OK)
    def create_metasploit_container(self, instance_id):
        """
        Creates a new metasploit container over a docker server instance.

        Args:
            instance_id (str): instance ID.

        Returns:
            dict: a new container document.
        """
        all_containers_documents = self.database.get_docker_documents(amazon_resource_id=instance_id, type=self.type)

        new_container = ContainerOperations(
            docker_server_id=instance_id
        ).run_container_with_msfrpcd_metasploit(containers_documents=all_containers_documents)

        container_response = create_new_response(obj=new_container, response_type=self.type)

        self.database.add_docker_document(
            amazon_resource_id=instance_id, docker_document_type=self.type, new_docker_document=container_response
        )

        return container_response

    @response_decorator(HttpCodes.NO_CONTENT)
    def delete_container(self, instance_id, container_id):
        """
        Deletes a container from the DB.

        Args:
            instance_id (str): instance ID.
            container_id (str): container ID.

        """
        self.database.delete_docker_document(
            amazon_resource_id=instance_id, docker_resource_id=container_id, docker_document_type=self.type
        )
        ContainerOperations(docker_server_id=instance_id, docker_resource_id=container_id).container.remove(force=True)
        return ''
