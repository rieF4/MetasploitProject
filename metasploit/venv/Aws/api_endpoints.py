from flask import Flask, jsonify
from flask_restful import Api, request

from metasploit.venv.Aws.utils import (
    HttpMethods,
    validate_json_request,
)
from metasploit.venv.Aws.Response import (
    HttpCodes
)

from metasploit.venv.Aws.api_management import ApiManager
from metasploit.venv.Aws.Database import DatabaseCollections
from metasploit.venv.Aws import Constants


class FlaskAppWrapper(object):
    """
    This is a class to wrap flask program and to create its endpoints to functions.

    Attributes:
        self._api (FlaskApi) - the api of flask.
    """
    app = Flask(__name__)

    def __init__(self):
        self._api = Api(app=FlaskAppWrapper.app)

    @app.errorhandler(HttpCodes.NOT_FOUND)
    def invalid_urls_error(self):
        """
        Catches a client request that is not a valid API URL.

        Returns:
            tuple (Json, int): an error response that shows all available URL's for the client to use.
        """
        url_error = {
            "Error": f"The given url {request.base_url} is invalid ",
            "AvailableUrls": "In progress"
        }

        return jsonify(url_error), 404

    @app.errorhandler(HttpCodes.BAD_REQUEST)
    def method_not_allowed(self):
        method_not_allowed_err = {
            "Error": f"Method {request.method} is not allowed in URL {request.base_url}",
            "AvailableMethods": "In progress"
        }

        return jsonify(method_not_allowed_err), 400

    def get_app(self):
        """
        Get flask app.
        """
        return self.app

    def get_api(self):
        """
        Get flask API.
        """
        return self._api

    def run(self):
        """
        Run flask app.
        """
        self.app.run(debug=True)

    def add_endpoints(self, *add_url_rules_params):
        """
        add url rules to class methods.

        Args:
             add_url_rules_params (list(tuple(str, str, Function, list(str)))):
             a list of 4-tuple to add_url_rule function.

        Examples:
             add_url_rules_params = [
            (
                '/SecurityGroupsController/Get',
                'SecurityGroup.get_security_groups_endpoint',
                SecurityGroup.get_security_groups_endpoint,
                [HttpMethods.GET]
            ),
            (
                '/Instances/Create',
                'Instances.create_instances_endpoint',
                Instances.create_instances_endpoint,
                [HttpMethods.POST]
            )
        ]
        """
        for url_rule, endpoint_name, func, http_methods in add_url_rules_params:
            try:
                self.app.add_url_rule(
                    rule=url_rule, endpoint=endpoint_name, view_func=EndpointAction(func), methods=http_methods
                )
            except Exception as e:
                print(e)


class EndpointAction(object):
    """
    Defines an Endpoint for a specific function for a client.

    Attributes:
        function (Function): the function that the endpoint will be forwarded to.
    """

    def __init__(self, function):
        """
        Create the endpoint by specifying which action we want the endpoint to perform, at each call.
        function (Function): The function to execute on endpoint call.
        """
        self.function = function

    def __call__(self, *args, **kwargs):
        """
        Standard method that effectively perform the stored function of its endpoint.

        Args:
            args (list): Arguments to give to the stored function.
            kwargs (dict): Keyword arguments to the stored functions.

        Returns:
           tuple (Json, int): an API response to the client.
        """
        # Perform the function
        try:
            return self.function(*args, **kwargs)
        except (ResourceNotFoundError, BadJsonInput) as err:
            http_error = choose_http_error_code(error=err)
            return make_error_response(
                msg=err.__str__(), http_error_code=http_error, req=request.json, path=request.base_url
            )


class CollectionApi(object):
    """
    Base class for all the collection API classes
    """
    pass


class SecurityGroupsApi(CollectionApi):

    security_group_collection = DatabaseCollections.SECURITY_GROUPS

    @staticmethod
    @validate_json_request(validate=False)
    def get_security_groups_endpoint():
        """
        Security group endpoint that gets all the security groups available in the DB.

        Returns:
            ApiResponse: an api response obj.

         Raises:
            SecurityGroupNotFoundError: in case there is not a security groups.
        """
        return ApiManager(
            collection_type=SecurityGroupsApi.security_group_collection,
            single_document=False,
            type=Constants.SECURITY_GROUPS,
            collection_name=Constants.SECURITY_GROUPS
        ).get_resources.amazon_resource

    @staticmethod
    @validate_json_request(validate=False)
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
        return ApiManager(
            collection_type=SecurityGroupsApi.security_group_collection,
            type=Constants.SECURITY_GROUP,
            resource_id=id
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
            ApiResponse: an api response obj.

        Raises:
            ParamValidationError: in case the parameters by the client to create security groups are not valid.
            ClientError: in case there is a duplicate security group that is already exist.
        """
        return ApiManager(
            collection_type=SecurityGroupsApi.security_group_collection,
            create_resource_flag=True,
            client_request=request.json
        ).create_resources.create_security_group

    @staticmethod
    @validate_json_request(validate=False)
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
        return ApiManager(
            collection_type=SecurityGroupsApi.security_group_collection,
            resource_id=id,
            type=Constants.SECURITY_GROUP
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
            ApiResponse: an api response obj.

        Raises:
            SecurityGroupNotFoundError: in case there is not a security group with the ID.
            ClientError: in case there is the requested inbound permissions already exist.
        """
        return ApiManager(
            collection_type=SecurityGroupsApi.security_group_collection,
            resource_id=id,
            type=Constants.SECURITY_GROUP
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
            ApiResponse: an api response obj.

        Raises:
            ParamValidationError: in case the parameters by the client to create instances are not valid.
        """
        return ApiManager(
            collection_type=InstancesApi.instance_collection,
            create_resource_flag=True,
            client_request=request.json
        ).create_resources.create_instance

    @staticmethod
    @validate_json_request(validate=False)
    def get_all_instances_endpoint():
        """
        Instance endpoint the get all the available instances from the DB.

        Returns:
            ApiResponse: an api response obj.

        Raises:
            AmazonResourceNotFoundError: in case there are not instances.
        """
        return ApiManager(
            collection_type=InstancesApi.instance_collection,
            type=Constants.INSTANCES,
            single_document=False
        ).get_resources.amazon_resource

    @staticmethod
    @validate_json_request(validate=False)
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
        return ApiManager(
            collection_type=InstancesApi.instance_collection,
            type=Constants.INSTANCE,
            resource_id=id,
        ).get_resources.amazon_resource

    @staticmethod
    @validate_json_request(validate=False)
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
        return ApiManager(
            collection_type=InstancesApi.instance_collection,
            resource_id=id,
            type=Constants.INSTANCE,
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
            ApiResponse: an api response obj.

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
            type=Constants.INSTANCE,
            resource_id=id,
            client_request=request.json,
        ).create_resources.create_container

    @staticmethod
    @validate_json_request(validate=False)
    def start_container_endpoint(instance_id, container_id):
        """
        Start a container in the instance.

        Args:
            instance_id (str): instance ID.
            container_id (str): container ID.

        Returns:
            ApiResponse: an api response obj.

        Raises:
            AmazonResourceNotFoundError: in case the instance ID is not valid.
            DockerResourceNotFoundError: in case there aren't any available containers.
        """
        # return start_container(instance_id=instance_id, container_id=container_id)

    @staticmethod
    @validate_json_request(validate=False)
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
        return ApiManager(
            collection_type=InstancesApi.instance_collection,
            resource_id=id,
            type=Constants.INSTANCE,
            collection_name=Constants.INSTANCES,
            single_document=False
        ).get_resources.get_docker_resource(document_type=Constants.CONTAINERS)

    @staticmethod
    @validate_json_request(validate=False)
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
        return ApiManager(
            collection_type=InstancesApi.instance_collection,
            type=Constants.INSTANCE,
            resource_id=instance_id,
            sub_resource_id=container_id,
        ).get_resources.get_specific_sub_resource(document_type=Constants.CONTAINERS)

    @staticmethod
    @validate_json_request(validate=False)
    def get_all_instances_containers_endpoint():
        """
        Container endpoint to get all the containers of all the instances from the DB.

        Returns:
            ApiResponse: an api response obj.

        Raises:
            AmazonResourceNotFoundError: in case the instance ID is not valid.
            DockerResourceNotFoundError: in case there aren't any available containers.
        """
        # return get_all_instances_containers_from_database()

    @staticmethod
    @validate_json_request(validate=False)
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
        # return delete_container(instance_id=instance_id, container_id=container_id)

    @staticmethod
    @validate_json_request("Command")
    def execute_command_endpoint(instance_id, container_id):
        """
        Executes a command in the container endpoint, similar to "Docker exec" command.

        Args:
            instance_id (str): instance ID.
            container_id (str): container ID.

        Returns:
            ApiResponse: an api response obj.
        """
        # return create_update_resource(
        #     function=execute_command_in_container_through_api,
        #     code=HttpCodes.OK,
        #     instance_id=instance_id,
        #     container_id=container_id
        # )

    @staticmethod
    @validate_json_request(validate=False)
    def run_container_with_metasploit_daemon_endpoint(instance_id):
        """
        Runs a container with metasploit daemon endpoint

        Args:
             instance_id (str): instance ID.
        """
        # return run_container_with_metasploit_daemon_through_api(instance_id=instance_id)


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
            ApiResponse: an api response obj.

        Raises:
            AmazonResourceNotFoundError: in case it's invalid instance ID.
            ApiError: in case docker server returns an error.
        """
        # return create_update_resource(function=pull_instance_image, instance_id=id)

    @staticmethod
    @validate_json_request(validate=False)
    def get_instance_images_endpoint(instance_id):
        """
        Get all instance docker images by instance ID.

        Args:
            instance_id (str): instance ID.

        Returns:
            ApiResponse: an api response obj.

        Raises:
            ImageNotFoundError: in case there aren't any images available.
            AmazonResourceNotFoundError: in case the instance was not found.
        """
        # return get_all_instance_images_from_database(instance_id=instance_id)


if __name__ == "__main__":
    flask_wrapper = FlaskAppWrapper()
    flask_wrapper.add_endpoints(
        (
            '/SecurityGroups/Get',
            'SecurityGroupsController.get_security_groups_endpoint',
            SecurityGroupsApi.get_security_groups_endpoint,
            [HttpMethods.GET]
        ),
        (
            '/SecurityGroups/Get/<id>',
            'SecurityGroupsController.get_specific_security_group_endpoint',
            SecurityGroupsApi.get_specific_security_group_endpoint,
            [HttpMethods.GET]
        ),
        (
            '/SecurityGroups/Create',
            'SecurityGroupsController.create_security_groups_endpoint',
            SecurityGroupsApi.create_security_groups_endpoint,
            [HttpMethods.POST]
        ),
        (
            '/SecurityGroups/Delete/<id>',
            'SecurityGroupsController.delete_specific_security_group_endpoint',
            SecurityGroupsApi.delete_specific_security_group_endpoint,
            [HttpMethods.DELETE]
        ),
        (
            '/SecurityGroups/<id>/UpdateInboundPermissions',
            'SecurityGroupsController.modify_security_group_inbound_permissions_endpoint',
            SecurityGroupsApi.modify_security_group_inbound_permissions_endpoint,
            [HttpMethods.PATCH]
        ),
        (
            '/DockerServerInstances/Create',
            'InstancesController.create_instances_endpoint',
            InstancesApi.create_instances_endpoint,
            [HttpMethods.POST]
        ),
        (
            '/DockerServerInstances/Get',
            'InstancesController.get_all_instances_endpoint',
            InstancesApi.get_all_instances_endpoint,
            [HttpMethods.GET]
        ),
        (
            '/DockerServerInstances/Get/<id>',
            'InstancesController.get_specific_instance_endpoint',
            InstancesApi.get_specific_instance_endpoint,
            [HttpMethods.GET]
        ),
        (
            '/DockerServerInstances/Delete/<id>',
            'InstancesController.delete_instance_endpoint',
            InstancesApi.delete_instance_endpoint,
            [HttpMethods.DELETE]
        ),
        (
            '/DockerServerInstances/<id>/CreateContainers',
            'ContainersController.create_containers_endpoint',
            ContainersApi.create_containers_endpoint,
            [HttpMethods.POST]
        ),
        (
            '/DockerServerInstances/<id>/Containers/Get',
            'ContainersController.get_all_instance_containers_endpoint',
            ContainersApi.get_all_instance_containers_endpoint,
            [HttpMethods.GET]
        ),
        (
            '/DockerServerInstances/<instance_id>/Containers/Get/<container_id>',
            'ContainersController.get_instance_container_endpoint',
            ContainersApi.get_instance_container_endpoint,
            [HttpMethods.GET]
        ),
        (
            '/DockerServerInstances/Containers/Get',
            'ContainersController.get_all_instances_containers_endpoint',
            ContainersApi.get_all_instances_containers_endpoint,
            [HttpMethods.GET]
        ),
        (
            '/DockerServerInstances/<instance_id>/Containers/Delete/<container_id>',
            'ContainersController.delete_container_endpoint',
            ContainersApi.delete_container_endpoint,
            [HttpMethods.DELETE]
        ),
        (
            '/DockerServerInstances/<instance_id>/Containers/Start/<container_id>',
            'ContainersController.start_container_endpoint',
            ContainersApi.start_container_endpoint,
            [HttpMethods.PATCH],
        ),
        (
            '/DockerServerInstances/<id>/Images/Pull',
            'DockerImagesController.pull_instance_images_endpoint',
            DockerImagesApi.pull_instance_images_endpoint,
            [HttpMethods.POST]
        ),
        (
            '/DockerServerInstances/<instance_id>/Images/Get',
            'DockerImagesController.get_instance_images_endpoint',
            DockerImagesApi.get_instance_images_endpoint,
            [HttpMethods.GET]
        ),
        (
            '/DockerServerInstances/<instance_id>/Containers/ExecuteCommand/<container_id>',
            'ContainersController.execute_command_endpoint',
            ContainersApi.execute_command_endpoint,
            [HttpMethods.PATCH]
        ),
        (
            '/DockerServerInstances/<instance_id>/Containers/CreateMetasploitContainer',
            'ContainersController.run_container_with_metasploit_daemon_endpoint',
            ContainersApi.run_container_with_metasploit_daemon_endpoint,
            [HttpMethods.POST]
        )
    )
    flask_wrapper.run()
