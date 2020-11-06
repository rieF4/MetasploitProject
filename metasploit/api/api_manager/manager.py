from metasploit.api.database import (
    DatabaseOperations,
    DockerServerDatabaseManager,
    SecurityGroupDatabaseManager,
    ContainerDatabaseManager,
    ImageDatabaseManager,
    DatabaseManager,
    NetworkDatabaseManager
)

from metasploit import constants as global_constants
from metasploit.aws import amazon_operations as aws_operations
from metasploit.docker import docker_operations

from metasploit.api.response import (
    ApiResponse,
    HttpCodes
)

from metasploit.utils.decorators import client_request_modifier

from metasploit.api.response import (
    SecurityGroupResponse,
    DockerInstanceResponse,
    ErrorResponse,
    ContainerResponse,
    ImageResponse,
    ResourceResponse,
    NetworkResponse
)


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

    def database_manager(self):
        """
        Get database manager object.
        """
        return DatabaseManager(self)

    def docker_server_database_manager(self, is_update_required=True):
        """
        Get docker server database manager object.
        """
        return DockerServerDatabaseManager(self, is_update_required)

    def security_group_database_manager(self):
        """
        Get security group database manager object.
        """
        return SecurityGroupDatabaseManager(self)

    def container_database_manager(self, is_update_required=True):
        """
        Get container database manager object.
        """
        return ContainerDatabaseManager(self, is_update_required)

    def image_database_manager(self, is_update_required=True):
        """
        Get image database manager object.
        """
        return ImageDatabaseManager(self, is_update_required)

    def network_database_manager(self, is_update_required=True):
        """
        Get network database manager object.
        """
        return NetworkDatabaseManager(self, is_update_required=is_update_required)

    def docker_server_response(self, http_status_code, docker_server=None, response=None):
        """
        Get docker instance response object.
        """
        return DockerInstanceResponse(
            self, response=response, http_status_code=http_status_code, docker_server=docker_server
        )

    def security_group_response(self, http_status_code, security_group=None, response=None):
        """
        Get security group response object.
        """
        return SecurityGroupResponse(
            self, response=response, http_status_code=http_status_code, security_group=security_group
        )

    def container_response(self, http_status_code=HttpCodes.OK, container=None, response=None):
        """
        Get container response object.
        """
        return ContainerResponse(self, http_status_code=http_status_code, container=container, response=response)

    def image_response(self, http_status_code, image=None, response=None):
        """
        Get image response object.
        """
        return ImageResponse(
            self, http_status_code=http_status_code, image=image, response=response
        )

    def network_response(self, http_status_code=HttpCodes.OK, network=None, response=None):
        """
        Get network response object.
        """
        return NetworkResponse(self, http_status_code=http_status_code, network=network, response=response)

    def error_response(self, error_msg, http_status_code, req=None, path=None):
        """
        Get error response object.
        """
        return ErrorResponse(self, error_msg=error_msg, http_error_code=http_status_code, req=req, path=path)

    def resource_response(self, response, http_status_code, docker_amazon_object=None):
        """
        Get general resource response object.
        """
        return ResourceResponse(
            self, response=response, http_status_code=http_status_code, docker_amazon_object=docker_amazon_object
        )


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

    @property
    def amazon_resource_id(self):
        return self._api_manager.amazon_resource_id

    @property
    def docker_resource_id(self):
        return self._api_manager.docker_resource_id


class CreateAmazonResources(ResourceOperation):

    @property
    @client_request_modifier(code=HttpCodes.CREATED)
    def create_instance(self, req=None):
        """
        Creates an instance in AWS and inserts it to the DB.

        Args:
            req (dict): the request from the client.

        Returns:
            dict: an docker server instance document.
        """
        docker_server_response = self.api_manager.docker_server_response(
            http_status_code=HttpCodes.CREATED,
            docker_server=aws_operations.create_instance(kwargs=req)
        ).response

        self.api_manager.docker_server_database_manager(is_update_required=False).insert_docker_server_document(
            new_docker_server_document=docker_server_response
        )

        return docker_server_response

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
        security_group_response = self.api_manager.security_group_response(
            http_status_code=HttpCodes.CREATED,
            security_group=aws_operations.create_security_group(kwargs=req)
        ).response

        self.api_manager.security_group_database_manage().insert_security_group_document(
            new_amazon_document=security_group_response
        )

        return security_group_response


class CreateDockerResources(ResourceOperation):

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
        container = docker_operations.ContainerOperations(docker_server_id=self.amazon_resource_id).create_container(
                image=req.pop("Image"),
                command=req.pop("Command", None),
                kwargs=req
            )

        container_response = self.api_manager.container_response(
            http_status_code=HttpCodes.CREATED,
            container=container
        ).response

        self.api_manager.container_database_manager().insert_container_document(
            new_container_document=container_response
        )

        return container_response

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
        image = docker_operations.ImageOperations(docker_server_id=self.amazon_resource_id).pull_image(
                repository=repository,
                tag="latest",
                **req
            )

        image_response = self.api_manager.image_response(http_status_code=HttpCodes.CREATED, image=image).response

        self.api_manager.image_database_manager().insert_image_document(new_image_document=image_response)

        return image_response

    @property
    def run_metasploit_container(self):
        """
        Creates a running container with msfrpc daemon that listens on a dynamic port.

        Returns:
            dict: a container document.
        """
        msfrpcd_container = docker_operations.ContainerOperations(
            docker_server_id=self.amazon_resource_id
        ).run_container_with_msfrpcd_metasploit(containers_documents=self.amazon_document[global_constants.CONTAINERS])

        msfrpcd_container_response = self.api_manager.container_response(
            http_status_code=HttpCodes.CREATED,
            container=msfrpcd_container
        )

        self.api_manager.container_database_manager().insert_container_document(
            new_container_document=msfrpcd_container_response.response
        )

        return msfrpcd_container_response.make_response

    @property
    @client_request_modifier(code=HttpCodes.CREATED)
    def create_docker_network(self, req=None):
        """
        Creates a docker network over the docker server instance.

        Args:
            req (dict): the client request.

        Returns:
            dict: a network document.
        """
        network_name = req.pop("name")

        network = docker_operations.NetworkOperations(docker_server_id=self.amazon_resource_id).create_network(
            network_name, req
        )

        network_response = self.api_manager.network_response(
            http_status_code=HttpCodes.CREATED, network=network
        ).response

        self.api_manager.network_database_manager().insert_network_document(network_response)

        return network_response


class GetResource(ResourceOperation):

    @property
    def amazon_resource(self):
        """
        Get amazon document(s) from the DB. note: except docker server instance.

        Returns:
            ApiResponse: an api response object.
        """
        return self.api_manager.resource_response(
            response=self.amazon_document, http_status_code=HttpCodes.OK
        ).make_response

    @property
    def docker_server_instance_resource(self):
        """
        Get the docker server instance(s) from the DB.

        Returns:
            ApiResponse: an api response object.
        """
        # need to init docker server constructor to update all the container documents in the DB because
        # their attributes change all the time
        docker_server_response = self.api_manager.docker_server_database_manager().get_docker_server_instance_document

        return self.api_manager.docker_server_response(
            response=docker_server_response,
            http_status_code=HttpCodes.OK
        ).make_response

    @property
    def docker_resource(self):
        """
        Get all docker resource(s) from the DB of an instance such as containers, images or networks.

        Returns:
            ApiResponse: an api response object.
        """
        # need to init docker server constructor to update all the container documents in the DB because
        # their attributes change all the time
        return self.api_manager.resource_response(
            response=self.api_manager.docker_server_database_manager().docker_document,
            http_status_code=HttpCodes.OK
        ).make_response


class DeleteResource(ResourceOperation):

    @property
    def delete_instance(self):
        """
        Deletes an instance from AWS and from the DB.

        Returns:
            ApiResponse: an api response object.
        """
        aws_operations.DockerServerInstanceOperations(instance_id=self.amazon_resource_id).docker_server.terminate()

        self.api_manager.docker_server_database_manager(
            is_update_required=False
        ).delete_docker_server_instance_document()

        return self.api_manager.docker_server_response(
            http_status_code=HttpCodes.NO_CONTENT, response=''
        ).make_response

    @property
    def delete_security_group(self):
        """
        Deletes a security group from AWS and from the DB.

        Returns:
            ApiResponse: an api response object.
        """
        aws_operations.SecurityGroupOperations(
            amazon_resource_id=self.amazon_resource_id
        ).security_group_object.delete()

        self.api_manager.security_group_database_manager.delete_security_group_document()

        return self.api_manager.security_group_response(
            http_status_code=HttpCodes.NO_CONTENT, response=''
        ).make_response

    @property
    def delete_container(self):
        """
        Deletes a container with docker sdk and remove it from the DB.

        Returns:
            ApiResponse: an api response object.
        """
        docker_operations.ContainerOperations(
            docker_server_id=self.amazon_resource_id, docker_resource_id=self.api_manager.docker_resource_id
        ).container.remove()

        self.api_manager.container_database_manager().delete_container_document()

        return self.api_manager.container_response(
            http_status_code=HttpCodes.NO_CONTENT, response=''
        ).make_response


class UpdateResource(ResourceOperation):

    @property
    @client_request_modifier(code=HttpCodes.OK)
    def update_security_group_inbound_permissions(self, req=None):
        """
        Updates security group inbound permissions.

        Args:
            req (dict): the api client request

        Returns:
            dict: an updated security group response.
        """
        new_ip_permissions = aws_operations.SecurityGroupOperations(
            amazon_resource_id=self.amazon_resource_id
        ).update_security_group_inbound_permissions(req=req)

        self.api_manager.security_group_database_manager().update_security_group_document(
            update={"IpPermissionsInbound": new_ip_permissions}
        )

        security_group_response = self.amazon_document
        return security_group_response

    @property
    def start_container(self):
        """
        Start a container that is in a "stopped" state
        """
        container = docker_operations.ContainerOperations(
            docker_server_id=self.amazon_resource_id, docker_resource_id=self.docker_resource_id
        ).container

        if container.status != "running":
            container.start()

        self.api_manager.container_database_manager()

        return self.api_manager.container_response(
            http_status_code=HttpCodes.OK, response=self.docker_document
        ).make_response

    @client_request_modifier(code=HttpCodes.OK)
    def run_exploit(
            self, target=None, module_name=None, payloads=None, options=None, connection=None, module_type=None
    ):
        """
        run exploits over a metasploit container with msfrpc daemon connected.

        Example of exploits running request where the key is the target host and the values are exploit's params:

        exploits_requests = {
            "10.10.10.10": {
                "ModuleType": 'exploit',
                "RpcPort": 50000,
                "ModuleName": "aix/local/ibstat_path",
                "Payloads": [
                    'cmd/unix/bind_perl',
                    'cmd/unix/bind_perl_ipv6',
                    'cmd/unix/reverse_perl',
                    'cmd/unix/reverse_perl_ssl'
                ],
                "Options": {
                    'SESSION': "value1",
                    'WritableDir': "value2"
                }
            },
            "9.9.9.9": {
                "ModuleType": 'exploit',
                "RpcPort": 50001,
                "ModuleName": "aix/rpc_cmsd_opcode21",
                "Payloads": [
                    'aix/ppc/shell_bind_tcp',
                    'aix/ppc/shell_reverse_tcp',
                    'generic/custom',
                    'generic/shell_bind_tcp',
                    'generic/shell_reverse_tcp'
                ],
                "Options": {
                    'RHOSTS': "value1",
                    'RPORT': "value2",
                    'SSLVERSION': "value3",
                    'ConnectTimeout': "value4",
                    'TIMEOUT': "value5"
                }
            }
        }
        """

