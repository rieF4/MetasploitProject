from flask_restful import request

from metasploit.api.database import (
    DatabaseCollections
)
from metasploit.utils.decorators import validate_json_request
from metasploit.api.service_implmentation.docker_server_service import DockerServerServiceImplementation
from metasploit.api.service_implmentation.container_service import ContainerServiceImplementation
from metasploit.api.service_implmentation.metasploit_service import MetasploitServiceImplementation
from metasploit.api.service_implmentation.service import Service


class ControllerApi(object):
    """
    Base class for all the collection API classes
    """
    pass


class SecurityGroupsController(ControllerApi):

    security_group_collection = DatabaseCollections.SECURITY_GROUPS

    @staticmethod
    def get_security_groups_endpoint():
        """
        Security group endpoint that gets all the security groups available in the DB.

        Returns:
            ApiResponse: an api response obj.

         Raises:
            SecurityGroupNotFoundError: in case there is not a security groups.
        """
        # return ApiManager(
        #     collection_type=SecurityGroupsController.security_group_collection,
        #     single_amazon_document=False,
        #     collection_name=global_constants.SECURITY_GROUPS,
        #     amazon_resource_type=global_constants.SECURITY_GROUPS
        # ).get_resources.amazon_resource

    @staticmethod
    def get_specific_security_group_endpoint(id):
        """
        Security group endpoint to get a specific security group from the DB by its ID.

        Args:
            id (str): security group ID.

        Returns:
            ApiResponse: an api response obj.

        Raises:
            SecurityGroupNotFoundError: in case there is not a security group with the ID.
        """
        # return ApiManager(
        #     collection_type=SecurityGroupsController.security_group_collection,
        #     single_amazon_document=True,
        #     amazon_resource_type=global_constants.SECURITY_GROUP,
        #     amazon_resource_id=id
        # ).get_resources.amazon_resource

    @staticmethod
    @validate_json_request("GroupName", "Description")
    def create_security_groups_endpoint():
        """
        Create dynamic amount of security groups.

        Example of a request:

        {
            "1": {
                "Description": "Metasploit project security group",
                "GroupName": "MetasploitSecurityGroup"
            },
            "2": {
                "Description": "Metasploit project security group1",
                "GroupName": "MetasploitSecurityGroup1"
            }
        }

        Returns:
            ApiResponse: an api response obj.

        Raises:
            ParamValidationError: in case the parameters by the client to create security groups are not valid.
            ClientError: in case there is a duplicate security group that is already exist.
        """
        # return ApiManager(
        #     collection_type=SecurityGroupsController.security_group_collection,
        #     client_request=request.json
        # ).create_amazon_resources.create_security_group

    @staticmethod
    def delete_specific_security_group_endpoint(id):
        """
        Security group endpoint in order to delete a specific security group from the API.

        Args:
            id (str): security group ID.

        Returns:
            ApiResponse: an api response obj.

        Raises:
            SecurityGroupNotFoundError: in case there is not a security group with the ID.
        """
        # return ApiManager(
        #     collection_type=SecurityGroupsController.security_group_collection,
        #     single_amazon_document=True,
        #     amazon_resource_id=id,
        #     amazon_resource_type=global_constants.SECURITY_GROUP
        # ).delete_resource.delete_security_group

    @staticmethod
    @validate_json_request("IpProtocol", "FromPort", "ToPort", "CidrIp")
    def modify_security_group_inbound_permissions_endpoint(id):
        """
        Modify a security group InboundPermissions.

        Examples of a request:
        {
            "1": {
                "IpProtocol": "tcp",
                "FromPort": 2375,
                "ToPort": 2375,
                "CidrIp": "0.0.0.0/0"
            },
            "2": {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "CidrIp": "0.0.0.0/0"
            }
        }

        Args:
            id (str): security group ID.

        Returns:
            ApiResponse: an api response obj.

        Raises:
            SecurityGroupNotFoundError: in case there is not a security group with the ID.
            ClientError: in case there is the requested inbound permissions already exist.
        """
        # return ApiManager(
        #     collection_type=SecurityGroupsController.security_group_collection,
        #     single_amazon_document=True,
        #     client_request=request.json,
        #     amazon_resource_id=id,
        #     amazon_resource_type=global_constants.SECURITY_GROUP
        # ).update_resource.modify_security_group_inbound_permissions


class InstancesController(ControllerApi):

    instance_collection = DatabaseCollections.INSTANCES

    @staticmethod
    @validate_json_request("ImageId", "InstanceType")
    def create_instances_endpoint():
        """
        Create a dynamic amount of instances over AWS.

        Example of a request:

        {
            "ImageId": "ami-016b213e65284e9c9",
            "InstanceType": "t2.micro"
        }

        Returns:
            ApiResponse: an api response obj.

        Raises:
            ParamValidationError: in case the parameters by the client to create instances are not valid.
        """
        return Service(class_type=DockerServerServiceImplementation).create(docker_server_json=request.json)

    @staticmethod
    def get_all_instances_endpoint():
        """
        Instance endpoint the get all the available instances from the DB.

        Returns:
            ApiResponse: an api response obj.

        Raises:
            AmazonResourceNotFoundError: in case there are not instances.
        """
        return Service(class_type=DockerServerServiceImplementation).get_all()


    @staticmethod
    def get_specific_instance_endpoint(id):
        """
        Instance endpoint to get a specific instance from the DB.

        Args:
            id (str): instance id.

        Returns:
            ApiResponse: an api response obj.

        Raises:
            AmazonResourceNotFoundError: in case there is not an instance with the ID.
        """
        return Service(class_type=DockerServerServiceImplementation).get_one(instance_id=id)

    @staticmethod
    def delete_instance_endpoint(id):
        """
        Instance endpoint to delete a specific instance from the API.

        Args:
            id (str): instance id.

        Returns:
            ApiResponse: an api response obj.

        Raises:
            AmazonResourceNotFoundError: in case there is not an instance with the ID.
        """
        return Service(class_type=DockerServerServiceImplementation).delete_one(instance_id=id)


class ContainersController(ControllerApi):

    @staticmethod
    def get_all_instance_containers_endpoint(id):
        """
        Container endpoint to get all the containers of a specific instance from the database.

        Args:
            id (str): instance ID.

        Returns:
            ApiResponse: an api response obj.

        Raises:
            AmazonResourceNotFoundError: in case the instance ID is not valid.
            DockerResourceNotFoundError: in case there aren't any available containers.
        """
        return Service(class_type=ContainerServiceImplementation).get_all(instance_id=id)

    @staticmethod
    def get_instance_container_endpoint(instance_id, container_id):
        """
        Container endpoint to get a container by instance and container IDs from the DB.

        Args:
            instance_id (str): instance ID.
            container_id (str): container ID.

        Returns:
            ApiResponse: an api response obj.

        Raises:
            AmazonResourceNotFoundError: in case the instance ID is not valid.
            DockerResourceNotFoundError: in case there aren't any available containers.
        """
        return Service(
            class_type=ContainerServiceImplementation
        ).get_one(instance_id=instance_id, container_id=container_id)

    @staticmethod
    def delete_container_endpoint(instance_id, container_id):
        """
        Container endpoint to deletes the container from an instance and remove it from DB.

        Args:
            instance_id (str): instance ID.
            container_id (str): container ID.

        Returns:
            ApiResponse: an api response obj.

        Raises:
            AmazonResourceNotFoundError: in case the instance ID is not valid.
            DockerResourceNotFoundError: in case there aren't any available containers.
            ApiError: in case the docker server returns an error.
        """
        return Service(
            class_type=ContainerServiceImplementation
        ).delete_one(instance_id=instance_id, container_id=container_id)

    @staticmethod
    def run_container_with_metasploit_daemon_endpoint(instance_id):
        """
        Runs a container with metasploit daemon endpoint

        Args:
             instance_id (str): instance ID.
        """
        return Service(class_type=ContainerServiceImplementation).create(instance_id=instance_id)


class DockerImagesController(ControllerApi):

    @staticmethod
    @validate_json_request("Repository")
    def pull_instance_images_endpoint(id):
        """
        Pull docker images to an instance.

        Examples of a request:
            {
                "1": {
                    "Repository": "phocean/msf",
                },
                "2": {
                    "Repository": "ubuntu",
                }
            }

        Args:
            id (str): instance ID.

        Returns:
            ApiResponse: an api response obj.

        Raises:
            AmazonResourceNotFoundError: in case it's invalid instance ID.
            ApiError: in case docker server returns an error.
        """
        # return ApiManager(
        #     collection_type=InstancesController.instance_collection,
        #     amazon_resource_id=id,
        #     client_request=request.json,
        #     single_amazon_document=True,
        #     amazon_resource_type=global_constants.INSTANCE,
        # ).create_docker_resources.pull_image


class MetasploitController(ControllerApi):

    @staticmethod
    @validate_json_request("target", "module_type", "exploit_name", "payloads")
    def run_exploit(instance_id):
        return Service(class_type=MetasploitServiceImplementation).run(
            instance_id=instance_id, exploit_request=request.json
        )

    @staticmethod
    def scan_ports(instance_id, target):
        return Service(class_type=MetasploitServiceImplementation).scan(
            instance_id=instance_id, target=target
        )
