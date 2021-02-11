from flask_restful import request, Resource

from metasploit.api.logic.servicewrapper import ServiceWrapper
from metasploit.api.metasploit_manager.module_executor import (
    Exploit,
    Payload,
    PortScanning
)
from metasploit.api.utils.decorators import response_decorator
from metasploit.api.response import HttpCodes


class ControllerApi(Resource):
    """
    Base class for all the Controllers API classes
    """

    def post(self, *args, **kwargs):
        """
        Base method for all the post operations
        """
        pass

    def get(self, *args, **kwargs):
        """
        Base method for all the get operations
        """
        pass

    def delete(self, *args, **kwargs):
        """
        Base method for all the delete operations
        """
        pass

    def put(self, *args, **kwargs):
        """
        Base method for all the put operations
        """
        pass


class UserController(ControllerApi):
    """
    User service controller.

    Attributes:
        _user_service_implementation: a class which implements the service of the user service.
    """

    def __init__(self, user_service_implementation):
        self._user_service_implementation = user_service_implementation

    def post(self, *args, **kwargs):
        return self._create_user_endpoint()

    def get(self, username=None, password=None):
        if username and password:
            return self._get_specific_user_endpoint(username=username, password=password)
        else:
            return self._get_all_users_endpoint()

    def delete(self, username):
        return self._delete_user(username=username)

    @response_decorator(HttpCodes.OK)
    def _create_user_endpoint(self):
        """
        Creates a new user endpoint.

        Example of a body request:

        {
            "first_name": "Guy",
            "last_name": "Afik",
            "username": "Great",
            "password": "123456789", # must be more than 8 characters
            "email": "guyafik423468@gmail.com"
        }

        Returns:
            Response: a flask response.
        """
        return ServiceWrapper(class_type=self._user_service_implementation).create(**request.json)

    @response_decorator(HttpCodes.OK)
    def _get_specific_user_endpoint(self, username, password):
        """
        Gets a single user endpoint.

        Args:
            username (str): user name.
            password (str): user password.

        Returns:
            Response: a flask response.
        """
        return ServiceWrapper(
            class_type=self._user_service_implementation
        ).get_one(username=username, password=password)

    @response_decorator(HttpCodes.OK)
    def _get_all_users_endpoint(self):
        """
        Gets all the available users endpoint.

        Returns:
            Response: a flask response.
        """
        return ServiceWrapper(class_type=self._user_service_implementation).get_all()

    @response_decorator(HttpCodes.NO_CONTENT)
    def _delete_user(self, username):
        """
        Delete user endpoint.

        Returns:
            Response: a flask response.
        """
        return ServiceWrapper(class_type=self._user_service_implementation).delete_one(username=username)


class InstancesController(ControllerApi):
    """
    Docker server controller.

    Attributes:
        _docker_server_implementation: a class which implements the service of the docker server.
    """
    def __init__(self, docker_server_implementation):
        self._docker_server_implementation = docker_server_implementation

    def post(self):
        return self._create_instances_endpoint()

    def get(self, instance_id=None):
        if instance_id:
            return self._get_specific_instance_endpoint(instance_id=instance_id)
        else:
            return self._get_all_instances_endpoint()

    def delete(self, instance_id):
        return self._delete_instance_endpoint(instance_id=instance_id)

    @response_decorator(HttpCodes.OK)
    def _create_instances_endpoint(self):
        """
        Creates docker server instance endpoint.

        Example of a request:

        {
            "ImageId": "ami-016b213e65284e9c9",
            "InstanceType": "t2.micro"
        }

        Returns:
            Response: a flask response.
        """
        return ServiceWrapper(class_type=self._docker_server_implementation).create(docker_server_json=request.json)

    @response_decorator(HttpCodes.OK)
    def _get_all_instances_endpoint(self):
        """
        Gets all available the docker server instances endpoint.

        Returns:
            Response: a flask response.
        """
        return ServiceWrapper(class_type=self._docker_server_implementation).get_all()

    @response_decorator(HttpCodes.OK)
    def _get_specific_instance_endpoint(self, instance_id):
        """
        Gets a single docker server instance endpoint.

        Args:
            instance_id (str): instance id.

        Returns:
            Response: a flask response.
        """
        return ServiceWrapper(class_type=self._docker_server_implementation).get_one(instance_id=instance_id)

    @response_decorator(HttpCodes.NO_CONTENT)
    def _delete_instance_endpoint(self, instance_id):
        """
        Deletes a single docker server instance endpoint.

        Args:
            instance_id (str): instance id.

        Returns:
            Response: a flask response.
        """
        return ServiceWrapper(class_type=self._docker_server_implementation).delete_one(instance_id=instance_id)


class ContainersController(ControllerApi):
    """
    Containers controller.

    Attributes:
        _container_service_implementation: a class which implements the service of the containers.
    """
    def __init__(self, container_service_implementation):
        self._container_service_implementation = container_service_implementation

    def post(self, instance_id):
        return self._run_container_with_metasploit_daemon_endpoint(instance_id=instance_id)

    def get(self, instance_id, container_id=None):
        if container_id:
            return self._get_instance_container_endpoint(instance_id=instance_id, container_id=container_id)
        else:
            return self._get_all_instance_containers_endpoint(instance_id=instance_id)

    def delete(self, instance_id, container_id):
        return self._delete_container_endpoint(instance_id=instance_id, container_id=container_id)

    @response_decorator(HttpCodes.OK)
    def _get_all_instance_containers_endpoint(self, instance_id):
        """
        Gets all the containers of docker server instance endpoint.

        Args:
            instance_id (str): instance ID.

        Returns:
            Response: a flask response.
        """
        return ServiceWrapper(class_type=self._container_service_implementation).get_all(instance_id=instance_id)

    @response_decorator(HttpCodes.OK)
    def _get_instance_container_endpoint(self, instance_id, container_id):
        """
        Gets a single container of docker server instance endpoint.

        Args:
            instance_id (str): instance ID.
            container_id (str): container ID.

        Returns:
            Response: a flask response.
        """
        return ServiceWrapper(
            class_type=self._container_service_implementation
        ).get_one(instance_id=instance_id, container_id=container_id)

    @response_decorator(HttpCodes.NO_CONTENT)
    def _delete_container_endpoint(self, instance_id, container_id):
        """
        Deletes a single container of docker server instance endpoint.

        Args:
            instance_id (str): instance ID.
            container_id (str): container ID.

        Returns:
            Response: a flask response.
        """
        return ServiceWrapper(
            class_type=self._container_service_implementation
        ).delete_one(instance_id=instance_id, container_id=container_id)

    @response_decorator(HttpCodes.OK)
    def _run_container_with_metasploit_daemon_endpoint(self, instance_id):
        """
        Runs a container with metasploit daemon endpoint.

        Args:
             instance_id (str): instance ID.

        Returns:
            Response: a flask response.
        """
        return ServiceWrapper(class_type=self._container_service_implementation).create(instance_id=instance_id)


class MetasploitController(ControllerApi):
    """
    Containers controller.

    Attributes:
        _metasploit_service_implementation: a class which implements the service of the metasploit.
    """
    def __init__(self, metasploit_service_implementation):
        self._metasploit_service_implementation = metasploit_service_implementation

    def post(self, instance_id, target):
        return self._run_exploit(instance_id=instance_id, target=target)

    def get(self, instance_id, target=None, exploit_name=None, payload_name=None):
        if target:
            return self._scan_ports(instance_id=instance_id, target=target)
        elif exploit_name:
            return self._exploit_info(instance_id=instance_id, exploit_name=exploit_name)
        else:
            return self._payload_info(instance_id=instance_id, payload_name=payload_name)

    @response_decorator(HttpCodes.OK)
    def _run_exploit(self, instance_id, target):
        """
        Runs an exploit on a container that belongs to the instance on a target host endpoint.

        Args:
            instance_id (str): instance ID.
            target (str): target host to run the exploit (dns/IP).

        Returns:
            Response: a flask response.
        """
        return ServiceWrapper(
            class_type=self._metasploit_service_implementation,
            module=Exploit,
            instance_id=instance_id,
            target=target
        ).run(exploit_request=request.json)

    @response_decorator(HttpCodes.OK)
    def _scan_ports(self, instance_id, target):
        """
        Scans ports using a container that belongs to the instance on a target host endpoint.

        Args:
            instance_id (str): instance ID.
            target (str): target host to scan the ports (dns/IP).

        Returns:
            Response: a flask response.
        """
        return ServiceWrapper(
            class_type=self._metasploit_service_implementation,
            module=PortScanning,
            instance_id=instance_id,
            target=target
        ).info()

    @response_decorator(HttpCodes.OK)
    def _exploit_info(self, instance_id, exploit_name):
        """
        Gets exploit information endpoint.

        Args:
            instance_id (str): instance ID.
            exploit_name (str): exploit name to query.

        Returns:
            Response: a flask response.
        """
        return ServiceWrapper(
            class_type=self._metasploit_service_implementation,
            module=Exploit,
            instance_id=instance_id
        ).info(exploit_name=exploit_name)

    @response_decorator(HttpCodes.OK)
    def _payload_info(self, instance_id, payload_name):
        """
        Gets payload information endpoint.

        Args:
            instance_id (str): instance ID.
            payload_name (str): payload name to query.

        Returns:
            Response: a flask response.
        """
        return ServiceWrapper(
            class_type=self._metasploit_service_implementation,
            module=Payload,
            instance_id=instance_id
        ).info(payload_name=payload_name)

# class DockerImagesController(ControllerApi):
#
#     @staticmethod
#     @validate_json_request("Repository")
#     def pull_instance_images_endpoint(id):
#         """
#         Pull docker images to an instance.
#
#         Examples of a request:
#             {
#                 "1": {
#                     "Repository": "phocean/msf",
#                 },
#                 "2": {
#                     "Repository": "ubuntu",
#                 }
#             }
#
#         Args:
#             id (str): instance ID.
#
#         Returns:
#             ApiResponse: an api response obj.
#
#         Raises:
#             AmazonResourceNotFoundError: in case it's invalid instance ID.
#             ApiError: in case docker server returns an error.
#         """
#         # return ApiManager(
#         #     collection_type=InstancesController.instance_collection,
#         #     amazon_resource_id=id,
#         #     client_request=request.json,
#         #     single_amazon_document=True,
#         #     amazon_resource_type=global_constants.INSTANCE,
#         # ).create_docker_resources.pull_image



# class SecurityGroupsController(ControllerApi):
#
#     security_group_collection = DatabaseCollections.SECURITY_GROUPS
#
#     @staticmethod
#     def get_security_groups_endpoint():
#         """
#         Security group endpoint that gets all the security groups available in the DB.
#
#         Returns:
#             ApiResponse: an api response obj.
#
#          Raises:
#             SecurityGroupNotFoundError: in case there is not a security groups.
#         """
#         # return ApiManager(
#         #     collection_type=SecurityGroupsController.security_group_collection,
#         #     single_amazon_document=False,
#         #     collection_name=global_constants.SECURITY_GROUPS,
#         #     amazon_resource_type=global_constants.SECURITY_GROUPS
#         # ).get_resources.amazon_resource
#
#     @staticmethod
#     def get_specific_security_group_endpoint(id):
#         """
#         Security group endpoint to get a specific security group from the DB by its ID.
#
#         Args:
#             id (str): security group ID.
#
#         Returns:
#             ApiResponse: an api response obj.
#
#         Raises:
#             SecurityGroupNotFoundError: in case there is not a security group with the ID.
#         """
#         # return ApiManager(
#         #     collection_type=SecurityGroupsController.security_group_collection,
#         #     single_amazon_document=True,
#         #     amazon_resource_type=global_constants.SECURITY_GROUP,
#         #     amazon_resource_id=id
#         # ).get_resources.amazon_resource
#
#     @staticmethod
#     @validate_json_request("GroupName", "Description")
#     def create_security_groups_endpoint():
#         """
#         Create dynamic amount of security groups.
#
#         Example of a request:
#
#         {
#             "1": {
#                 "Description": "Metasploit project security group",
#                 "GroupName": "MetasploitSecurityGroup"
#             },
#             "2": {
#                 "Description": "Metasploit project security group1",
#                 "GroupName": "MetasploitSecurityGroup1"
#             }
#         }
#
#         Returns:
#             ApiResponse: an api response obj.
#
#         Raises:
#             ParamValidationError: in case the parameters by the client to create security groups are not valid.
#             ClientError: in case there is a duplicate security group that is already exist.
#         """
#         # return ApiManager(
#         #     collection_type=SecurityGroupsController.security_group_collection,
#         #     client_request=request.json
#         # ).create_amazon_resources.create_security_group
#
#     @staticmethod
#     def delete_specific_security_group_endpoint(id):
#         """
#         Security group endpoint in order to delete a specific security group from the API.
#
#         Args:
#             id (str): security group ID.
#
#         Returns:
#             ApiResponse: an api response obj.
#
#         Raises:
#             SecurityGroupNotFoundError: in case there is not a security group with the ID.
#         """
#         # return ApiManager(
#         #     collection_type=SecurityGroupsController.security_group_collection,
#         #     single_amazon_document=True,
#         #     amazon_resource_id=id,
#         #     amazon_resource_type=global_constants.SECURITY_GROUP
#         # ).delete_resource.delete_security_group
#
#     @staticmethod
#     @validate_json_request("IpProtocol", "FromPort", "ToPort", "CidrIp")
#     def modify_security_group_inbound_permissions_endpoint(id):
#         """
#         Modify a security group InboundPermissions.
#
#         Examples of a request:
#         {
#             "1": {
#                 "IpProtocol": "tcp",
#                 "FromPort": 2375,
#                 "ToPort": 2375,
#                 "CidrIp": "0.0.0.0/0"
#             },
#             "2": {
#                 "IpProtocol": "tcp",
#                 "FromPort": 22,
#                 "ToPort": 22,
#                 "CidrIp": "0.0.0.0/0"
#             }
#         }
#
#         Args:
#             id (str): security group ID.
#
#         Returns:
#             ApiResponse: an api response obj.
#
#         Raises:
#             SecurityGroupNotFoundError: in case there is not a security group with the ID.
#             ClientError: in case there is the requested inbound permissions already exist.
#         """
#         # return ApiManager(
#         #     collection_type=SecurityGroupsController.security_group_collection,
#         #     single_amazon_document=True,
#         #     client_request=request.json,
#         #     amazon_resource_id=id,
#         #     amazon_resource_type=global_constants.SECURITY_GROUP
#         # ).update_resource.modify_security_group_inbound_permissions