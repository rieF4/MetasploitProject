from flask_restful import request

from metasploit.api.database import (
    DatabaseCollections
)
from metasploit import constants as global_constants
from metasploit.utils.decorators import validate_json_request

from .manager import ApiManager


class CollectionApi(object):
    """
    Base class for all the collection API classes
    """
    pass


class SecurityGroupsApi(CollectionApi):

    security_group_collection = DatabaseCollections.SECURITY_GROUPS

    @staticmethod
    def get_security_groups_endpoint():
        """
        Security group endpoint that gets all the security groups available in the DB.

        Returns:
            ApiResponse: an api response object.

         Raises:
            SecurityGroupNotFoundError: in case there is not a security groups.
        """
        return ApiManager(
            collection_type=SecurityGroupsApi.security_group_collection,
            single_amazon_document=False,
            collection_name=global_constants.SECURITY_GROUPS,
            amazon_resource_type=global_constants.SECURITY_GROUPS
        ).get_resources.amazon_resource

    @staticmethod
    def get_specific_security_group_endpoint(id):
        """
        Security group endpoint to get a specific security group from the DB by its ID.

        Args:
            id (str): security group ID.

        Returns:
            ApiResponse: an api response object.

        Raises:
            SecurityGroupNotFoundError: in case there is not a security group with the ID.
        """
        return ApiManager(
            collection_type=SecurityGroupsApi.security_group_collection,
            single_amazon_document=True,
            amazon_resource_type=global_constants.SECURITY_GROUP,
            amazon_resource_id=id
        ).get_resources.amazon_resource

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
            ApiResponse: an api response object.

        Raises:
            ParamValidationError: in case the parameters by the client to create security groups are not valid.
            ClientError: in case there is a duplicate security group that is already exist.
        """
        return ApiManager(
            collection_type=SecurityGroupsApi.security_group_collection,
            client_request=request.json
        ).create_amazon_resources.create_security_group

    @staticmethod
    def delete_specific_security_group_endpoint(id):
        """
        Security group endpoint in order to delete a specific security group from the API.

        Args:
            id (str): security group ID.

        Returns:
            ApiResponse: an api response object.

        Raises:
            SecurityGroupNotFoundError: in case there is not a security group with the ID.
        """
        return ApiManager(
            collection_type=SecurityGroupsApi.security_group_collection,
            single_amazon_document=True,
            amazon_resource_id=id,
            amazon_resource_type=global_constants.SECURITY_GROUP
        ).delete_resource.delete_security_group

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
            ApiResponse: an api response object.

        Raises:
            SecurityGroupNotFoundError: in case there is not a security group with the ID.
            ClientError: in case there is the requested inbound permissions already exist.
        """
        return ApiManager(
            collection_type=SecurityGroupsApi.security_group_collection,
            single_amazon_document=True,
            client_request=request.json,
            amazon_resource_id=id,
            amazon_resource_type=global_constants.SECURITY_GROUP
        ).update_resource.modify_security_group_inbound_permissions


class InstancesApi(CollectionApi):

    instance_collection = DatabaseCollections.INSTANCES

    @staticmethod
    @validate_json_request("ImageId", "InstanceType", "KeyName", "SecurityGroupIds", "MaxCount", "MinCount")
    def create_instances_endpoint():
        """
        Create a dynamic amount of instances over AWS.

        Example of a request:

        {
            "1": {
                "ImageId": "ami-016b213e65284e9c9",
                "InstanceType": "t2.micro",
                "KeyName": "default_key_pair_name",
                "SecurityGroupIds": ["sg-08604b8d820a35de6"],
                "MaxCount": 1,
                "MinCount": 1
            },
            "2": {
                "ImageId": "ami-016b213e65284e9c9",
                "InstanceType": "t2.micro",
                "KeyName": "default_key_pair_name",
                "SecurityGroupIds": ["sg-08604b8d820a35de6"],
                "MaxCount": 1,
                "MinCount": 1
            }
        }

        Returns:
            ApiResponse: an api response object.

        Raises:
            ParamValidationError: in case the parameters by the client to create instances are not valid.
        """
        return ApiManager(
            collection_type=InstancesApi.instance_collection,
            client_request=request.json
        ).create_amazon_resources.create_instance

    @staticmethod
    def get_all_instances_endpoint():
        """
        Instance endpoint the get all the available instances from the DB.

        Returns:
            ApiResponse: an api response object.

        Raises:
            AmazonResourceNotFoundError: in case there are not instances.
        """
        return ApiManager(
            collection_type=InstancesApi.instance_collection,
            amazon_resource_type=global_constants.INSTANCES,
            single_amazon_document=False,
            collection_name=global_constants.INSTANCES
        ).get_resources.docker_server_instance_resource

    @staticmethod
    def get_specific_instance_endpoint(id):
        """
        Instance endpoint to get a specific instance from the DB.

        Args:
            id (str): instance id.

        Returns:
            ApiResponse: an api response object.

        Raises:
            AmazonResourceNotFoundError: in case there is not an instance with the ID.
        """
        return ApiManager(
            collection_type=InstancesApi.instance_collection,
            amazon_resource_type=global_constants.INSTANCE,
            amazon_resource_id=id,
            single_amazon_document=True
        ).get_resources.docker_server_instance_resource

    @staticmethod
    def delete_instance_endpoint(id):
        """
        Instance endpoint to delete a specific instance from the API.

        Args:
            id (str): instance id.

        Returns:
            ApiResponse: an api response object.

        Raises:
            AmazonResourceNotFoundError: in case there is not an instance with the ID.
        """
        return ApiManager(
            collection_type=InstancesApi.instance_collection,
            amazon_resource_id=id,
            amazon_resource_type=global_constants.INSTANCE,
            single_amazon_document=True
        ).delete_resource.delete_instance


class ContainersApi(CollectionApi):

    @staticmethod
    @validate_json_request("Image")
    def create_containers_endpoint(id):
        """
        Create containers by instance ID. Containers will be created over the instance with the specified ID.

        Args:
            id (str): instance ID.

        Returns:
            ApiResponse: an api response object.

        Examples:
            {
                "1": {
                    "Image": "ubuntu",
                    "Command": "sleep 300"
                }
            }

        Raises:
            ImageNotFound: in case the image was not found on the docker server.
            ApiError: in case the docker server returns an error.
            TypeError: in case the request doesn't have the required arguments.
        """
        return ApiManager(
            collection_type=InstancesApi.instance_collection,
            amazon_resource_id=id,
            client_request=request.json,
            amazon_resource_type=global_constants.INSTANCE
        ).create_docker_resources.create_container

    @staticmethod
    def start_container_endpoint(instance_id, container_id):
        """
        Start a container in the instance.

        Args:
            instance_id (str): instance ID.
            container_id (str): container ID.

        Returns:
            ApiResponse: an api response object.

        Raises:
            AmazonResourceNotFoundError: in case the instance ID is not valid.
            DockerResourceNotFoundError: in case there aren't any available containers.
        """
        return ApiManager(
            collection_type=InstancesApi.instance_collection,
            amazon_resource_id=instance_id,
            docker_resource_id=container_id,
            single_docker_document=True,
            docker_resource_type=global_constants.CONTAINER,
            amazon_resource_type=global_constants.INSTANCE,
            docker_document_type=global_constants.CONTAINERS
        ).update_resource.start_container

    @staticmethod
    def get_all_instance_containers_endpoint(id):
        """
        Container endpoint to get all the containers of a specific instance from the database.

        Args:
            id (str): instance ID.

        Returns:
            ApiResponse: an api response object.

        Raises:
            AmazonResourceNotFoundError: in case the instance ID is not valid.
            DockerResourceNotFoundError: in case there aren't any available containers.
        """
        return ApiManager(
            collection_type=InstancesApi.instance_collection,
            amazon_resource_id=id,
            docker_resource_type=global_constants.CONTAINERS,
            docker_document_type=global_constants.CONTAINERS,
            amazon_resource_type=global_constants.INSTANCE,
            all_docker_documents=True
        ).get_resources.docker_resource

    @staticmethod
    def get_instance_container_endpoint(instance_id, container_id):
        """
        Container endpoint to get a container by instance and container IDs from the DB.

        Args:
            instance_id (str): instance ID.
            container_id (str): container ID.

        Returns:
            ApiResponse: an api response object.

        Raises:
            AmazonResourceNotFoundError: in case the instance ID is not valid.
            DockerResourceNotFoundError: in case there aren't any available containers.
        """
        return ApiManager(
            collection_type=InstancesApi.instance_collection,
            amazon_resource_id=instance_id,
            docker_resource_id=container_id,
            single_docker_document=True,
            docker_resource_type=global_constants.CONTAINER,
            amazon_resource_type=global_constants.INSTANCE,
            docker_document_type=global_constants.CONTAINERS
        ).get_resources.docker_resource

    @staticmethod
    def get_all_instances_containers_endpoint():
        """
        Container endpoint to get all the containers of all the instances from the DB.

        Returns:
            ApiResponse: an api response object.

        Raises:
            AmazonResourceNotFoundError: in case the instance ID is not valid.
            DockerResourceNotFoundError: in case there aren't any available containers.
        """
        # return get_all_instances_containers_from_database()

    @staticmethod
    def delete_container_endpoint(instance_id, container_id):
        """
        Container endpoint to deletes the container from an instance and remove it from DB.

        Args:
            instance_id (str): instance ID.
            container_id (str): container ID.

        Returns:
            ApiResponse: an api response object.

        Raises:
            AmazonResourceNotFoundError: in case the instance ID is not valid.
            DockerResourceNotFoundError: in case there aren't any available containers.
            ApiError: in case the docker server returns an error.
        """
        return ApiManager(
            collection_type=InstancesApi.instance_collection,
            amazon_resource_id=instance_id,
            docker_resource_id=container_id,
            single_docker_document=True,
            docker_resource_type=global_constants.CONTAINER,
            amazon_resource_type=global_constants.INSTANCE,
            docker_document_type=global_constants.CONTAINERS
        ).delete_resource.delete_container

    @staticmethod
    @validate_json_request("Command")
    def execute_command_endpoint(instance_id, container_id):
        """
        Executes a command in the container endpoint, similar to "Docker exec" command.

        Args:
            instance_id (str): instance ID.
            container_id (str): container ID.

        Returns:
            ApiResponse: an api response object.
        """
        # return create_update_resource(
        #     function=execute_command_in_container_through_api,
        #     code=HttpCodes.OK,
        #     instance_id=instance_id,
        #     container_id=container_id
        # )

    @staticmethod
    def run_container_with_metasploit_daemon_endpoint(instance_id):
        """
        Runs a container with metasploit daemon endpoint

        Args:
             instance_id (str): instance ID.
        """
        return ApiManager(
            collection_type=InstancesApi.instance_collection,
            amazon_resource_id=instance_id,
            amazon_resource_type=global_constants.INSTANCE,
        ).create_docker_resources.run_metasploit_container


class DockerImagesApi(CollectionApi):

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
            ApiResponse: an api response object.

        Raises:
            AmazonResourceNotFoundError: in case it's invalid instance ID.
            ApiError: in case docker server returns an error.
        """
        return ApiManager(
            collection_type=InstancesApi.instance_collection,
            amazon_resource_id=id,
            client_request=request.json,
            single_amazon_document=True,
            amazon_resource_type=global_constants.INSTANCE,
        ).create_docker_resources.pull_image

    @staticmethod
    def get_instance_images_endpoint(instance_id):
        """
        Get all instance docker images by instance ID.

        Args:
            instance_id (str): instance ID.

        Returns:
            ApiResponse: an api response object.

        Raises:
            ImageNotFoundError: in case there aren't any images available.
            AmazonResourceNotFoundError: in case the instance was not found.
        """
        # return get_all_instance_images_from_database(instance_id=instance_id)
