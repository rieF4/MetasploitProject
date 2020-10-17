from metasploit.api.database import (
    DatabaseCollections,
    DatabaseOperations,
    DockerServerDatabaseManager,
    SecurityGroupDatabaseManager,
    ContainerDatabaseManager,
    ImageDatabaseManager
)

from metasploit import constants as global_constants
from metasploit.aws import utils as aws_utils
from metasploit.docker import utils as docker_utils

from metasploit.api.response import (
    PrepareResponse,
    ApiResponse,
    HttpCodes
)

from metasploit.utils.decorators import client_request_modifier


class ApiManager(object):
    """
    a class to manage all API operations such as Create, Get, Update and Delete.

    Attributes:
        client_request (dict): the full client request.
        resource_id (str): a resource ID, either a security group ID or instance ID.
        sub_resource_id (str): a sub resource ID, either container ID, image ID or network ID
        db_manager (DatabaseOperations): database manager with operations to mongo DB such as Insert, Delete, Update, Find
    """
    def __init__(self, collection_type, **kwargs):
        """
        Initializes the ApiManager class attributes.

        Args:
            collection_type (pymongo.Collection): the collection to use to access/modify DB documents.

        Keyword Arguments:
            client_request (dict): the client request.
            amazon_resource_id (str): the amazon resource ID that the DB operation should be performed on.
            docker_resource_id (str): the docker resource ID that the DB operation should be performed on.
            all_docker_documents (bool): indicate if all docker document type is needed, True if yes, False otherwise.
            docker_document_type (str): indicate which type is needed for docker e.g. Constants.Containers
            single_docker_document (bool): indicate if a specific docker document is required.
                                           True if yes, False otherwise
            collection_name (str): the collection name. e.g. SecurityGroups, Instances
            single_amazon_document (bool): indicate if the search should be on a single amazon document. True if yes,
                                           False to look for all documents available in the DB.
            amazon_resource_type (str): what type of amazon document it is. e.g. Instance, SecurityGroup.
            docker_resource_type (str): which type of docker document it is. e.g. Container, Image.
        """
        self._amazon_resource_id = kwargs.get('amazon_resource_id', '')
        self._docker_resource_id = kwargs.get('docker_resource_id', '')
        self._client_request = kwargs.pop('client_request', {})

        self._db_operations_manager = DatabaseOperations(collection_type=collection_type, **kwargs)

    @property
    def client_request(self):
        """
        Get client request attribute.
        """
        return self._client_request

    @property
    def amazon_resource_id(self):
        """
        Get amazon resource ID.
        """
        return self._amazon_resource_id

    @property
    def docker_resource_id(self):
        """
        Get docker resource ID.
        """
        return self._docker_resource_id

    @property
    def db_operations_manager(self):
        """
        Get DB operation manager object.
        """
        return self._db_operations_manager

    @property
    def create_amazon_resources(self):
        """
        Get CreateAmazonResources object that manages all create amazon resources API operations.
        """
        return CreateAmazonResources(self)

    @property
    def create_docker_resources(self):
        """
        Get CreateDockerResources object that manages all create Docker resources API operations
        """
        return CreateDockerResources(self)

    @property
    def get_resources(self):
        """
        Get GetResource object that manages all Get API operations.
        """
        return GetResource(self)

    @property
    def delete_resource(self):
        """
        Get DeleteResource object that manages all Delete API operations.
        """
        return DeleteResource(self)

    @property
    def update_resource(self):
        """
        Get UpdateResource object that manages all Update API operations.
        """
        return UpdateResource(self)

    def docker_server_database_manager(self, docker_server=None):
        """
        Get docker server database manager object.
        """
        return DockerServerDatabaseManager(self, docker_server=docker_server)

    def security_group_database_manager(self, security_group=None):
        """
        Get security group database manager object.
        """
        return SecurityGroupDatabaseManager(self, security_group=security_group)

    def container_database_manager(self, docker_server=None, container=None):
        """
        Get container database manager object.
        """
        return ContainerDatabaseManager(self, docker_server=docker_server, container=container)

    def image_database_manager(self, docker_server=None, image=None):
        """
        Get image database manager object.
        """
        return ImageDatabaseManager(self, docker_server=docker_server, image=image)


class ResourceOperation(object):
    """
    a base class for all operations in the API.

    Attributes:
        api_manager (ApiManager): api manager object.
    """
    def __init__(self, api_manager):
        self._api_manager = api_manager

    @property
    def api_manager(self):
        """
        Get ApiManager object.
        """
        return self._api_manager

    @property
    def amazon_document(self):
        return self.api_manager.db_operations_manager.amazon_document

    @property
    def docker_document(self):
        return self.api_manager.db_operations_manager.docker_document


class CreateAmazonResources(ResourceOperation):

    @property
    @client_request_modifier(code=HttpCodes.CREATED)
    def create_instance(self, req=None):
        """
        Creates an instance in AWS and inserts it to the DB.

        Args:
            req (dict): the request from the client.

        Returns:
            dict: an instance document.
        """
        return self.api_manager.docker_server_database_manager(
            docker_server=aws_utils.create_instance(kwargs=req)
        ).create_docker_server_instance_document

    @property
    @client_request_modifier(code=HttpCodes.CREATED)
    def create_security_group(self, req=None):
        """
        Creates a security group in AWS and inserts it in to the DB.

        Args:
            req (dict): the request from the client.

        Returns:
            dict: a security group document.
        """
        return self.api_manager.security_group_database_manager(
            security_group=aws_utils.create_security_group(kwargs=req)
        ).create_security_group_document


class CreateDockerResources(ResourceOperation):

    def __init__(self, api_manager):
        super(CreateDockerResources, self).__init__(api_manager=api_manager)
        self.docker_server = aws_utils.get_docker_server_instance(id=self.api_manager.amazon_resource_id)

    @property
    @client_request_modifier(code=HttpCodes.CREATED)
    def create_container(self, req=None):
        """
        Creates a container over a docker server instance in AWS and inserts it in to the DB.

        Args:
            req (dict): the request from the client.

        Returns:
            dict: a container document.
        """
        container = docker_utils.create_container(
            instance=self.docker_server,
            image=req.pop("Image"),
            command=req.pop("Command", None),
            kwargs=req
        )

        return self.api_manager.container_database_manager(
            docker_server=self.docker_server, container=container
        ).create_container_document()

    @property
    @client_request_modifier(code=HttpCodes.CREATED)
    def pull_image(self, req=None):
        """
        Pulls an image in a docker server instance in AWS and inserts it in to the DB.

        Args:
            req (dict): the request from the client.

        Returns:
            dict: an image document.
        """
        repository = req.pop("Repository")
        image = docker_utils.pull_image(
            instance=self.docker_server,
            repository=repository,
            tag=f"{repository}:latest",
            **req
        )

        return self.api_manager.image_database_manager(
            docker_server=self.docker_server, image=image
        ).create_image_document()

    @property
    def run_metasploit_container(self):
        """
        Creates a running container with msfrpc daemon that listens on a dynamic port.

        Returns:
            dict: a container document.
        """
        msfrpcd_container = docker_utils.run_container_with_msfrpcd_metasploit(
            instance=self.docker_server,
            containers_documents=self.amazon_document[global_constants.DOCKER][global_constants.CONTAINERS]
        )

        return self.api_manager.container_database_manager(
            docker_server=self.docker_server, container=msfrpcd_container
        ).create_container_document


class GetResource(ResourceOperation):

    @property
    def security_group_resource(self):
        """
        Get the security group(s) from the DB.

        Returns:
            ApiResponse: an api response object.
        """
        return ApiResponse(response=super().amazon_document, http_status_code=HttpCodes.OK)

    @property
    def docker_server_instance_resource(self):
        """
        Get the docker server(s) from the DB.

        Returns:
            ApiResponse: an api response object.
        """
        # need to init docker server constructor to update all the container documents in the DB because
        # their attributes change all the time
        return ApiResponse(
            response=self.api_manager.docker_server_database_manager(
                docker_server=aws_utils.get_docker_server_instance(id=self.api_manager.amazon_resource_id)
            ).amazon_document,
            http_status_code=HttpCodes.OK
        )

    @property
    def docker_resource(self):
        """
        Get all docker resource(s) from the DB of an instance such as containers, images or networks.

        Returns:
            ApiResponse: an api response object.
        """
        # need to init docker server constructor to update all the container documents in the DB because
        # their attributes change all the time
        return ApiResponse(
            response=self.api_manager.docker_server_database_manager(
                docker_server=aws_utils.get_docker_server_instance(id=self.api_manager.amazon_resource_id)
            ).amazon_document,
            http_status_code=HttpCodes.OK
        )


class DeleteResource(ResourceOperation):

    @property
    def delete_instance(self):
        """
        Deletes an instance from AWS and from the DB.

        Returns:
            ApiResponse: an api response object.
        """
        aws_utils.get_docker_server_instance(id=self.api_manager.amazon_resource_id).terminate()
        self.api_manager.db_manager.delete_amazon_document()
        return ApiResponse(http_status_code=HttpCodes.NO_CONTENT)

    @property
    def delete_security_group(self):
        """
        Deletes a security group from AWS and from the DB.

        Returns:
            ApiResponse: an api response object.
        """
        aws_utils.get_security_group_object(id=self.api_manager.amazon_resource_id)
        self.api_manager.db_manager.delete_amazon_document()
        return ApiResponse(http_status_code=HttpCodes.NO_CONTENT)

    @property
    def delete_container(self):
        """
        Deletes a container with docker sdk and remove it from the DB.

        Returns:
            ApiResponse: an api response object.
        """
        docker_utils.get_container(
            instance_id=self.api_manager.amazon_resource_id, container_id=self.api_manager.docker_resource_id
        ).remove()

        # update here all the container docker_documents [TO DO!!!]
        updated_containers_documents = None

        self.api_manager.db_manager.update_amazon_document(updated_document=updated_containers_documents)
        return ApiResponse(http_status_code=HttpCodes.NO_CONTENT)


class UpdateResource(ResourceOperation):

    @property
    @client_request_modifier(code=HttpCodes.OK)
    def modify_security_group_inbound_permissions(self, req=None):

        aws_utils.update_security_group_inbound_permissions(
            security_group_id=self.api_manager.amazon_resource_id,
            req=req
        )

        security_group_document = PrepareResponse.prepare_security_group_response(
            security_group_obj=aws_utils.get_security_group_object(id=self.api_manager.amazon_resource_id)
        )

        self.api_manager.db_manager.update_amazon_document(updated_document=security_group_document)

        return security_group_document

    @property
    def start_container(self):
        return