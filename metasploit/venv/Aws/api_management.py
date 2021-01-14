from metasploit.venv.Aws.Database import (
    DatabaseOperations,
    DockerServerDatabaseManager,
    SecurityGroupDatabaseManager,
    ContainerDatabaseManager,
    ImageDatabaseManager
)
from metasploit.venv.Aws import Constants
from metasploit.venv.Aws import Aws_Api_Functions
from metasploit.venv.Aws import Docker_Utils
from metasploit.venv.Aws.Response import (
    PrepareResponse,
    ApiResponse,
    HttpCodes
)
from metasploit.venv.Aws.utils import choose_port_for_msfrpcd
from metasploit.venv.Aws.ServerExceptions import choose_http_error_code


def client_request_modifier(code):
    """
    Decorator for all API requests that were made by the client that requires data from client.

    Args:
        code (HttpCodes): HTTP code to return in case of success.
    """
    def client_request_decorator(api_func):
        """
        a decorator for an API function.

        Args:
            api_func (Function): the api function that gets decorated.
        """
        def client_request_wrapper(self):
            """
            Executes the function that handles a client request

            Args:
                self (ResourceOperation): the obj reference as self. e.g. CreateAmazonResources, UpdateResource.
            """
            response = {}

            http_status_code = code
            is_valid = False
            is_error = False

            for key, req in self.api_manager.client_request.items():
                try:
                    print(self)
                    response[key] = api_func(self=self, req=req)
                    is_valid = True
                except Exception as err:
                    print(err.__str__())
                    http_status_code = choose_http_error_code(error=err)
                    response[key] = PrepareResponse.prepare_error_response(
                        msg=err.__str__(), http_error_code=http_status_code, req=req
                    )
                    is_error = True

            if is_valid and is_error:
                http_status_code = HttpCodes.MULTI_STATUS

            return ApiResponse(response=response, http_status_code=http_status_code)
        return client_request_wrapper
    return client_request_decorator


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
        Initializes the ApiManager class.

        Args:
            collection_type (DatabaseCollections): a database collection.

            Keyword Arguments:
                resource_id (str): resource ID.
                client_request (dict): client request from the server.
                sub_resource_id (str): sub resource ID.
                collection_name (str): collection name. eg. Constants.Instances, Constants.SecurityGroups
                single_document (bool): refers whether the DB manager should look for a single document.
                type (str): type of the collection. eg. Constants.Instance, Constants.SecurityGroup
                create_resource_flag (bool): indicate if a resource needs to be created. True if yes, False otherwise.
        """
        self._amazon_resource_id = kwargs.get('amazon_resource_id', '')
        self._docker_resource_id = kwargs.get('docker_resource_id', '')
        self._client_request = kwargs.get('client_request', {})

        self._db_operations_manager = DatabaseOperations(
            collection_type=collection_type,
            resource_id=self.amazon_resource_id,
            sub_resource_id=self.docker_resource_id,
            collection_name=kwargs.get("collection_name", Constants.INSTANCES),
            single_document=kwargs.get("single_document", True),
            type=kwargs.get("type", Constants.INSTANCE),
            create_resource_flag=kwargs.get("create_resource_flag")

        )

    @property
    def client_request(self):
        return self._client_request

    @property
    def amazon_resource_id(self):
        """
        Get resource ID.
        """
        return self._amazon_resource_id

    @property
    def docker_resource_id(self):
        """
        Get sub resource ID.
        """
        return self._docker_resource_id

    @property
    def db_operations_manager(self):
        """
        Get DB manager.
        """
        return self._db_operations_manager

    @property
    def create_resources(self):
        """
        Get CreateAmazonResources obj that manages all create API operations.
        """
        return CreateResource(self)

    @property
    def get_resources(self):
        """
        Get GetResource obj that manages all Get API operations.
        """
        return GetResource(self)

    @property
    def delete_resource(self):
        """
        Get DeleteResource obj that manages all Delete API operations.
        """
        return DeleteResource(self)

    @property
    def update_resource(self):
        """
        Get UpdateResource obj that manages all Update API operations.
        """
        return UpdateResource(self)

    def docker_server_database_manager(self, docker_server=None):
        """
        Get docker server database manager obj.
        """
        return DockerServerDatabaseManager(self, docker_server=docker_server)

    def security_group_database_manager(self, security_group=None):
        """
        Get security group database manager obj.
        """
        return SecurityGroupDatabaseManager(self, security_group=security_group)

    def container_database_manager(self, docker_server=None, container=None):
        """
        Get container database manager obj.
        """
        return ContainerDatabaseManager(self, docker_server=docker_server, container=container)

    def image_database_manager(self, docker_server=None, image=None):
        """
        Get image database manager obj.
        """
        return ImageDatabaseManager(self, docker_server=docker_server, image=image)


class ResourceOperation(object):
    """
    a base class for all operations in the API.

    Attributes:
        api_manager (ApiManager): api manager obj.
    """
    def __init__(self, api_manager):
        self._api_manager = api_manager

    @property
    def api_manager(self):
        """
        Get ApiManager obj.
        """
        return self._api_manager


class CreateResource(ResourceOperation):

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
            docker_server=Aws_Api_Functions.create_instance(kwargs=req)
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
            security_group=Aws_Api_Functions.create_security_group(kwargs=req)
        ).insert_security_group_document

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
        instance_id = self.api_manager.amazon_resource_id

        docker_server = Aws_Api_Functions.get_docker_server_instance(id=instance_id)

        container = Docker_Utils.create_container(
            instance=docker_server,
            image=req.pop("Image"),
            command=req.pop("Command", None),
            kwargs=req
        )

        return self.api_manager.container_database_manager(
            docker_server=docker_server, container=container
        ).insert_container_document()

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
        instance_id = self.api_manager.amazon_resource_id
        docker_server = Docker_Utils.get_docker_server_instance(id=instance_id)

        repository = req.pop("Repository")

        image = Docker_Utils.pull_image(
            instance=docker_server,
            repository=repository,
            tag=f"{repository}:latest",
            **req
        )

        return self.api_manager.image_database_manager(docker_server=docker_server, image=image).insert_image_document()

    @property
    def run_metasploit_container(self):
        """
        Creates a running container with msfrpc daemon that listens on a dynamic port.

        Returns:
            dict: a container document.
        """
        port = choose_port_for_msfrpcd(
            containers_document=self.api_manager.db_manager.document[Constants.DOCKER][Constants.CONTAINERS]
        )

        if port:
            instance_id = self.api_manager.amazon_resource_id
            instance = Aws_Api_Functions.get_docker_server_instance(id=instance_id)

            msfrpcd_container = Docker_Utils.run_container_with_msfrpcd_metasploit(instance=instance, port=port)

            return self.api_manager.database_operation(
                type=Constants.CONTAINER,
                amazon_object=instance,
                docker_object=msfrpcd_container
            )  # put here the DB required operation

            # container_document = PrepareResponse.prepare_container_response(container=msfrpcd_container)
            # updated_containers_documents = self.api.db_manager.document
            # updated_containers_documents[Constants.DOCKER][Constants.CONTAINERS].append(container_document)
            #
            # self.api.db_manager.update_amazon_document(updated_document=updated_containers_documents)
            #
            # return container_document


class GetResource(ResourceOperation):

    @property
    def get_resource(self):
        """
        Get a resource(s) from the DB.

        Returns:
            ApiResponse: an api response obj.
        """
        return ApiResponse(response=self.api_manager.db_manager.document, http_status_code=HttpCodes.OK)
        # need to think of a way how to update container document

    def get_all_sub_resource(self, document_type):
        """
        Get all sub resources from the DB of an instance such as containers, images or networks.

        Args:
            document_type (str): document type. eg. Constants.Containers/Constants.Images

        Returns:
            ApiResponse: an api response obj.
        """
        return ApiResponse(
            response=self.api_manager.db_manager.document[Constants.DOCKER][document_type],
            http_status_code=HttpCodes.OK
        )

    def get_specific_sub_resource(self, document_type):
        """
        Get a specific sub resource from the DB of an instance such as container, image or network.

        Returns:
            ApiResponse: an api response obj.
        """
        # documents = self.api_manager.db_manager.document[Constants.DOCKER][document_type]
        # return ApiResponse(
        #     response=_find_specific_document(documents=documents, sub_resource_id=self.api_manager.docker_resource_id),
        #     http_status_code=HttpCodes.OK
        # )


class DeleteResource(ResourceOperation):

    @property
    def delete_instance(self):
        """
        Deletes an instance from AWS and from the DB.

        Returns:
            ApiResponse: an api response obj.
        """
        Aws_Api_Functions.get_docker_server_instance(id=self.api_manager.amazon_resource_id).terminate()
        self.api_manager.db_manager.delete_amazon_document()
        return ApiResponse(http_status_code=HttpCodes.NO_CONTENT)

    @property
    def delete_security_group(self):
        """
        Deletes a security group from AWS and from the DB.

        Returns:
            ApiResponse: an api response obj.
        """
        Aws_Api_Functions.get_security_group_object(id=self.api_manager.amazon_resource_id)
        self.api_manager.db_manager.delete_amazon_document()
        return ApiResponse(http_status_code=HttpCodes.NO_CONTENT)

    @property
    def delete_container(self):
        """
        Deletes a container with docker sdk and remove it from the DB.

        Returns:
            ApiResponse: an api response obj.
        """
        Docker_Utils.get_container(
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

        Aws_Api_Functions.update_security_group_inbound_permissions(
            security_group_id=self.api_manager.amazon_resource_id,
            req=req
        )

        security_group_document = PrepareResponse.prepare_security_group_response(
            security_group_obj=Aws_Api_Functions.get_security_group_object(id=self.api_manager.amazon_resource_id)
        )

        self.api_manager.db_manager.update_amazon_document(updated_document=security_group_document)

        return security_group_document

    @property
    def start_container(self):
        return
