from flask import Flask
from flask_restful import Api, request
from botocore.exceptions import ClientError, ParamValidationError
from metasploit.venv.Aws.ServerExceptions import (
    SecurityGroupNotFoundError,
    InstanceNotFoundError,
    ContainerNotFoundError,
    ImageNotFoundError,
    DuplicateImageError
)
from docker.errors import (
    ImageNotFound,
    APIError
)
from metasploit.venv.Aws.Database import (
    DatabaseCollections,
    find_documents,
    update_document,
    delete_documents,
    insert_document,
    remove_specific_element_in_document
)
from metasploit.venv.Aws.Api_Utils import (
    prepare_error_response,
    prepare_container_response,
    prepare_instance_response,
    prepare_security_group_response,
    prepare_image_response,
    find_container_document,
    HttpMethods,
    HttpCodes,
    ApiResponse,
    request_error_validation,
    check_if_image_already_exists,
    update_container_document_attributes,
)
from metasploit.venv.Aws import Constants

from metasploit.venv.Aws.Aws_Api_Functions import (
    create_security_group,
    create_instance,
    get_docker_server_instance,
    get_aws_instance,
    get_security_group_object,
)

from metasploit.venv.Aws.Docker_Utils import (
    create_container,
    get_container,
    pull_image
)


class EndpointAction(object):
    """
    Defines an Endpoint for a specific function for any client.

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
            kwargs (dict): Keyword arguments.

        Returns:
           tuple (Json, int): an API response to the client.
        """
        # Perform the function
        return self.function(*args, **kwargs)


class FlaskAppWrapper(object):
    """
    This is a class to wrap flask program and to create its endpoints to functions.

    Attributes:
        self._api (FlaskApi) - the api of flask.
    """
    app = Flask(__name__)

    def __init__(self):
        self._api = Api(app=FlaskAppWrapper.app)

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
                '/SecurityGroupsApi/Get',
                'SecurityGroup.get_security_groups',
                SecurityGroup.get_security_groups,
                [HttpMethods.GET]
            ),
            (
                '/Instances/Create',
                'Instances.create_instances',
                Instances.create_instances,
                [HttpMethods.POST]
            )
        ]
        """
        for url_rule, endpoint_name, func, methods in add_url_rules_params:
            try:
                self.app.add_url_rule(
                    rule=url_rule, endpoint=endpoint_name, view_func=EndpointAction(func), methods=methods
                )
            except Exception as e:
                print(e)


class CollectionApi(object):
    """
    Base class for all the collection API classes
    """
    pass


class SecurityGroupsApi(CollectionApi):

    @staticmethod
    @request_error_validation
    def get_security_groups():
        """
        Get all the security groups available in the database.

        Returns:
            ApiResponse: an api response object.

         Raises:
            SecurityGroupNotFoundError: in case there is not a security groups.
        """
        security_groups = find_documents(
            document={},  # means bring everything in the collection
            collection_type=DatabaseCollections.SECURITY_GROUPS,
            collection_name=Constants.SECURITY_GROUPS,
            single_document=False
        )

        if security_groups:
            return ApiResponse(response=security_groups, http_status_code=HttpCodes.OK)
        else:
            raise SecurityGroupNotFoundError(type=Constants.SECURITY_GROUPS)

    @staticmethod
    @request_error_validation
    def get_specific_security_group(id):
        """
        Get specific security group by ID.

        Args:
            id (str): security group ID.

        Returns:
            ApiResponse: an api response object.

        Raises:
            SecurityGroupNotFoundError: in case there is not a security group with the ID.
        """
        security_group = find_documents(document={Constants.ID: id}, collection_type=DatabaseCollections.SECURITY_GROUPS)
        if security_group:
            return ApiResponse(response=security_group, http_status_code=HttpCodes.OK)
        else:
            raise SecurityGroupNotFoundError(type=Constants.SECURITY_GROUP, id=id)

    @staticmethod
    @request_error_validation
    def create_security_groups():
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

        security_groups_requests = request.json
        security_groups_response = {}

        is_valid = False
        is_error = False
        http_status_code = HttpCodes.CREATED

        for key, req in security_groups_requests.items():
            try:
                security_group_obj = create_security_group(kwargs=req)

                security_group_database = prepare_security_group_response(
                    security_group_obj=security_group_obj, path=request.base_url
                )
                DatabaseCollections.SECURITY_GROUPS.insert_one(document=security_group_database)
                security_groups_response[key] = security_group_database

                is_valid = True
            except (ParamValidationError, ClientError) as err:

                http_status_code = HttpCodes.DUPLICATE if isinstance(err, ClientError) else HttpCodes.BAD_REQUEST

                security_groups_response[key] = prepare_error_response(
                    msg=err.__str__(), http_error_code=http_status_code, req=req
                )

                is_error = True

        if is_valid and is_error:
            http_status_code = HttpCodes.MULTI_STATUS
        return ApiResponse(response=security_groups_response, http_status_code=http_status_code)

    @staticmethod
    @request_error_validation
    def delete_specific_security_group(id):
        """
        Deletes a security group by id.

        Args:
            id (str): security group id.

        Returns:
            ApiResponse: an api response object.

        Raises:
            SecurityGroupNotFoundError: in case there is not a security group with the ID.
        """
        security_group = find_documents(document={Constants.ID: id}, collection_type=DatabaseCollections.SECURITY_GROUPS)

        if security_group:
            get_security_group_object(id=id).delete()
            if delete_documents(collection_type=DatabaseCollections.SECURITY_GROUPS, document=security_group):
                return ApiResponse(http_status_code=HttpCodes.NO_CONTENT)
        else:
            raise SecurityGroupNotFoundError(type=Constants.SECURITY_GROUP, id=id)

    @staticmethod
    @request_error_validation
    def modify_security_group_inbound_permissions(id):
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
            id (str): the id of the security group.

        Returns:
            ApiResponse: an api response object.

        Raises:
            SecurityGroupNotFoundError: in case there is not a security group with the ID.
            ClientError: in case there is the requested inbound permissions already exist.
        """
        inbound_permissions_update_request = request.json
        inbound_permissions_update_response = {}
        document = {Constants.ID: id}

        security_group_response = find_documents(document=document, collection_type=DatabaseCollections.SECURITY_GROUPS)

        if security_group_response:
            security_group_obj = get_security_group_object(id=id)

            for key, req in inbound_permissions_update_request.items():
                try:
                    security_group_obj.authorize_ingress(**req)
                    security_group_obj.reload()
                    ip_permissions = security_group_obj.ip_permissions

                    if update_document(
                        fields={"IpPermissionsInbound": ip_permissions},
                        collection_type=DatabaseCollections.SECURITY_GROUPS,
                        operation=Constants.SET,
                        id=id
                    ):
                        security_group_response = find_documents(
                            document=document, collection_type=DatabaseCollections.SECURITY_GROUPS
                        )

                        inbound_permissions_update_response[key] = security_group_response
                except ClientError as err:
                    http_status_code = HttpCodes.DUPLICATE

                    inbound_permissions_update_response[key] = prepare_error_response(
                        msg=err.__str__(), http_error_code=http_status_code, req=req
                    )

            return ApiResponse(response=security_group_response, http_status_code=HttpCodes.OK)
        else:
            raise SecurityGroupNotFoundError(type=Constants.SECURITY_GROUP, id=id)


class InstancesApi(CollectionApi):

    @staticmethod
    @request_error_validation
    def create_instances():
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
        create_instances_requests = request.json
        create_instances_response = {}

        is_valid = False
        is_error = False
        http_status_code = HttpCodes.CREATED

        for key, req in create_instances_requests.items():
            try:
                instance_obj = create_instance(kwargs=req)

                instance_response = prepare_instance_response(instance_obj=instance_obj, path=request.base_url)
                DatabaseCollections.INSTANCES.insert_one(document=instance_response)
                create_instances_response[key] = instance_response

                is_valid = True
            except ParamValidationError as err:
                http_status_code = HttpCodes.BAD_REQUEST

                create_instances_response[key] = prepare_error_response(
                    msg=err.__str__(), http_error_code=http_status_code, req=req
                )

                is_error = True

        if is_valid and is_error:
            http_status_code = HttpCodes.MULTI_STATUS
        return ApiResponse(response=create_instances_response, http_status_code=http_status_code)

    @staticmethod
    @request_error_validation
    def get_all_instances():
        """
        Get all the instances available at the server.

        Returns:
            ApiResponse: an api response object.

        Raises:
            InstanceNotFoundError: in case there are not instances.
        """
        instances_response = find_documents(
            document={},  # means bring everything in the collection
            collection_type=DatabaseCollections.INSTANCES,
            collection_name=Constants.INSTANCES,
            single_document=False
        )

        for ins_res in instances_response[Constants.INSTANCES]:
            if ins_res[Constants.DOCKER][Constants.CONTAINERS]:
                ins_res[Constants.DOCKER][Constants.CONTAINERS] = update_container_document_attributes(
                    instance_id=ins_res[Constants.ID]
                )

        if instances_response:
            return ApiResponse(response=instances_response, http_status_code=HttpCodes.OK)
        else:
            raise InstanceNotFoundError(type=Constants.INSTANCES)

    @staticmethod
    @request_error_validation
    def get_specific_instance(id):
        """
        Get a specific instance by ID.

        Args:
            id (str): instance id.

        Returns:
            ApiResponse: an api response object.

        Raises:
            InstanceNotFoundError: in case there is not an instance with the ID.
        """
        instance_response = find_documents(document={Constants.ID: id}, collection_type=DatabaseCollections.INSTANCES)

        if instance_response[Constants.DOCKER][Constants.CONTAINERS]:
            instance_response[Constants.DOCKER][Constants.CONTAINERS] = update_container_document_attributes(
                instance_id=instance_response[Constants.ID]
            )

        if instance_response:
            return ApiResponse(response=instance_response, http_status_code=HttpCodes.OK)
        else:
            raise InstanceNotFoundError(type=Constants.INSTANCES, id=id)

    @staticmethod
    @request_error_validation
    def delete_instance(id):
        """
        Delete a specific instance by ID.

        Args:
            id (str): instance id.

        Returns:
            ApiResponse: an api response object.

        Raises:
            InstanceNotFoundError: in case there is not an instance with the ID.
        """
        instance_document = find_documents(document={Constants.ID: id}, collection_type=DatabaseCollections.INSTANCES)
        if instance_document:
            get_aws_instance(id=id).terminate()
            if delete_documents(collection_type=DatabaseCollections.INSTANCES, document=instance_document):
                return ApiResponse(http_status_code=HttpCodes.NO_CONTENT)
        else:
            raise InstanceNotFoundError(type=Constants.INSTANCE, id=id)


class ContainersApi(CollectionApi):

    @staticmethod
    @request_error_validation
    def create_containers(id):
        """
        Create containers by instance ID. Containers will be created over the instance with the specified ID.

        Args:
            id (str): instance ID.

        Returns:
            ApiResponse: an api response object.

        Raises:
            ImageNotFound: in case the image was not found on the docker server.
            ApiError: in case the docker server returns an error.
            TypeError: in case the request doesn't have the required arguments.
        """
        create_containers_requests = request.json
        create_containers_response = {}

        is_error = False
        is_valid = False
        http_status_code = HttpCodes.CREATED

        instance_document = find_documents(document={Constants.ID: id}, collection_type=DatabaseCollections.INSTANCES)

        if instance_document:
            docker_server_instance = get_docker_server_instance(id=id)

            for key, req in create_containers_requests.items():
                try:
                    image = req.pop('Image', None)
                    command = req.pop('Command', None)

                    container_obj = create_container(
                        instance=docker_server_instance, image=image, kwargs=req, command=command
                    )

                    container_response = prepare_container_response(container_obj=container_obj)

                    if delete_documents(collection_type=DatabaseCollections.INSTANCES, document=instance_document):

                        instance_document[Constants.DOCKER][Constants.CONTAINERS].append(container_response)

                        if insert_document(collection_type=DatabaseCollections.INSTANCES, document=instance_document):
                            create_containers_response[key] = container_response
                            is_valid = True

                except (APIError, ImageNotFound, TypeError) as err:

                    http_status_code = HttpCodes.NOT_FOUND
                    create_containers_response[key] = prepare_error_response(
                        msg=err.__str__(), http_error_code=http_status_code, req=req
                    )
                    is_error = True

            if is_error and is_valid:
                http_status_code = HttpCodes.MULTI_STATUS
            return ApiResponse(response=create_containers_response, http_status_code=http_status_code)
        else:
            raise InstanceNotFoundError(type=Constants.INSTANCE, id=id)

    @staticmethod
    @request_error_validation
    def start_container(instance_id, container_id):
        """
        Start a container in the instance.

        Args:
            instance_id (str): instance ID.
            container_id (str): container ID.

        Returns:
            ApiResponse: an api response object.

        Raises:
            InstanceNotFoundError: in case the instance ID is not valid.
            ContainerNotFoundError: in case there aren't any available containers.
        """
        instance_document = find_documents(
            document={Constants.ID: instance_id}, collection_type=DatabaseCollections.INSTANCES
        )

        if instance_document:
            container_document = find_container_document(
                containers_documents=instance_document[Constants.DOCKER][Constants.CONTAINERS],
                container_id=container_id
            )

            if container_document:
                container = get_container(instance_id=instance_id, container_id=container_id)
                container.start()

                updated_container_document = prepare_container_response(container_obj=container)

                if delete_documents(collection_type=DatabaseCollections.INSTANCES, document=instance_document):

                    instance_document[Constants.DOCKER][Constants.CONTAINERS] = remove_specific_element_in_document(
                        document=instance_document[Constants.DOCKER][Constants.CONTAINERS], resource_id=container_id
                    )

                    instance_document[Constants.DOCKER][Constants.CONTAINERS].append(updated_container_document)

                    if insert_document(collection_type=DatabaseCollections.INSTANCES, document=instance_document):
                        return ApiResponse(response=updated_container_document, http_status_code=HttpCodes.OK)
            else:
                raise ContainerNotFoundError(type=Constants.CONTAINER, id=container_id)
        else:
            raise InstanceNotFoundError(type=Constants.INSTANCE, id=instance_id)

    @staticmethod
    @request_error_validation
    def get_all_instance_containers(id):
        """
        Get all the containers of a specific instance.

        Args:
            id (str): instance ID.

        Returns:
            ApiResponse: an api response object.

        Raises:
            InstanceNotFoundError: in case the instance ID is not valid.
            ContainerNotFoundError: in case there aren't any available containers.
        """
        instance_document = find_documents(document={Constants.ID: id}, collection_type=DatabaseCollections.INSTANCES)

        if instance_document:
            containers = instance_document[Constants.DOCKER][Constants.CONTAINERS]

            if containers:
                containers = update_container_document_attributes(instance_id=id)

                return ApiResponse(
                    response={
                        Constants.CONTAINERS: containers
                    },
                    http_status_code=HttpCodes.OK
                )
            else:
                raise ContainerNotFoundError(type=Constants.CONTAINERS)
        else:
            raise InstanceNotFoundError(type=Constants.INSTANCES, id=id)

    @staticmethod
    @request_error_validation
    def get_instance_container(instance_id, container_id):
        """
        Get a container by instance and container IDs

        Args:
            instance_id (str): instance ID.
            container_id (str): container ID.

        Returns:
            ApiResponse: an api response object.

        Raises:
            InstanceNotFoundError: in case the instance ID is not valid.
            ContainerNotFoundError: in case there aren't any available containers.
        """

        instance_document = find_documents(
            document={Constants.ID: instance_id}, collection_type=DatabaseCollections.INSTANCES
        )

        if instance_document:
            container = find_container_document(
                containers_documents=instance_document[Constants.DOCKER][Constants.CONTAINERS],
                container_id=container_id
            )
            if container:

                if instance_document[Constants.DOCKER][Constants.CONTAINERS]:
                    instance_document[Constants.DOCKER][Constants.CONTAINERS] = update_container_document_attributes(
                        instance_id=instance_id
                    )
                    return ApiResponse(response=container, http_status_code=HttpCodes.OK)
            else:
                raise ContainerNotFoundError(type=Constants.CONTAINER, id=container_id)
        else:
            raise InstanceNotFoundError(type=Constants.INSTANCE, id=instance_id)

    @staticmethod
    @request_error_validation
    def get_all_instances_containers():
        """
        Get all the containers of all the instances

        Returns:
            ApiResponse: an api response object.

        Raises:
            InstanceNotFoundError: in case the instance ID is not valid.
            ContainerNotFoundError: in case there aren't any available containers.
        """
        instances_documents = find_documents(
            document={},
            collection_type=DatabaseCollections.INSTANCES,
            collection_name=Constants.INSTANCES,
            single_document=False
        )

        if instances_documents:
            found_containers = False
            all_containers_response = {Constants.INSTANCES: {}}

            for instance in instances_documents[Constants.INSTANCES]:

                if instance[Constants.DOCKER][Constants.CONTAINERS]:
                    instance[Constants.DOCKER][Constants.CONTAINERS] = update_container_document_attributes(
                        instance_id=instance[Constants.ID]
                    )

                instance_id = instance[Constants.ID]
                all_containers_response[Constants.INSTANCES][instance_id] = []
                containers = instance[Constants.DOCKER][Constants.CONTAINERS]

                for container in containers:
                    all_containers_response[Constants.INSTANCES][instance_id].append(container)

                if all_containers_response[Constants.INSTANCES][instance_id]:
                    found_containers = True

            if found_containers:
                return ApiResponse(response=all_containers_response, http_status_code=HttpCodes.OK)
            else:
                raise ContainerNotFoundError(type=Constants.CONTAINERS)
        else:
            raise InstanceNotFoundError(type=Constants.INSTANCES)

    @staticmethod
    @request_error_validation
    def delete_container(instance_id, container_id):
        """
        Deletes the container over an instance.

        Returns:
            ApiResponse: an api response object.

        Raises:
            InstanceNotFoundError: in case the instance ID is not valid.
            ContainerNotFoundError: in case there aren't any available containers.
            ApiError: in case the docker server returns an error.
        """
        instance_document = find_documents(
            document={Constants.ID: instance_id}, collection_type=DatabaseCollections.INSTANCES
        )

        if instance_document:
            containers = instance_document[Constants.DOCKER][Constants.CONTAINER]
            container_document = find_container_document(containers_documents=containers, container_id=container_id)

            if container_document:
                try:
                    get_container(instance_id=instance_id, container_id=container_id).remove()

                    if delete_documents(collection_type=DatabaseCollections.INSTANCES, document=instance_document):
                        instance_document[Constants.DOCKER][Constants.CONTAINERS] = remove_specific_element_in_document(
                            document=instance_document[Constants.DOCKER][Constants.CONTAINERS], resource_id=container_id
                        )
                        if insert_document(collection_type=DatabaseCollections.INSTANCES, document=instance_document):
                            return ApiResponse(http_status_code=HttpCodes.NO_CONTENT)

                except APIError as err:
                    return ApiResponse(
                        response=prepare_error_response(
                            msg=err.__str__(), http_error_code=HttpCodes.INTERNAL_SERVER_ERROR
                        ),
                        http_status_code=HttpCodes.INTERNAL_SERVER_ERROR
                    )
            else:
                raise ContainerNotFoundError(type=Constants.CONTAINER, id=container_id)
        else:
            raise InstanceNotFoundError(type=Constants.INSTANCE, id=instance_id)


class DockerImagesApi(CollectionApi):

    @staticmethod
    @request_error_validation
    def pull_instance_images(id):
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
            InstanceNotFoundError: in case it's invalid instance ID.
            ApiError: in case docker server returns an error.
        """
        images_request = request.json
        pull_images_response = {}

        instance_document = find_documents(document={Constants.ID: id}, collection_type=DatabaseCollections.INSTANCES)

        http_status_code = HttpCodes.CREATED
        is_valid = False
        is_error = False

        if instance_document:
            instance_docker_server = get_docker_server_instance(id=id)

            for key, req in images_request.items():
                try:
                    repository = req.pop("Repository", None)
                    tag = "latest"
                    tag_to_check = f"{repository}:{tag}"

                    if check_if_image_already_exists(
                        image_document=instance_document[Constants.DOCKER][Constants.IMAGES],
                        tag_to_check=tag_to_check
                    ):
                        raise DuplicateImageError(resource=tag_to_check)

                    image = pull_image(instance=instance_docker_server, repository=repository, tag=tag, **req)

                    image_response = prepare_image_response(image_obj=image)

                    if delete_documents(collection_type=DatabaseCollections.INSTANCES, document=instance_document):
                        instance_document[Constants.DOCKER][Constants.IMAGES].append(image_response)

                        if DatabaseCollections.INSTANCES.insert_one(document=instance_document):
                            pull_images_response[key] = image_response
                            is_valid = True

                except (APIError, TypeError, AttributeError) as err:
                    http_status_code = HttpCodes.BAD_REQUEST
                    pull_images_response[key] = prepare_error_response(
                        msg=err.__str__(), http_error_code=http_status_code, req=req
                    )
                    is_error = True

            if is_error and is_valid:
                http_status_code = HttpCodes.MULTI_STATUS

            return ApiResponse(response=pull_images_response, http_status_code=http_status_code)
        else:
            raise InstanceNotFoundError(type=Constants.INSTANCES, id=id)

    @staticmethod
    @request_error_validation
    def get_instance_images(id):
        """
        Get all instance docker images by its ID

        Args:
            id (str): instance ID.

        Returns:
            ApiResponse: an api response object.

        Raises:
            ImageNotFoundError: in case there aren't any images available.
            InstanceNotFoundError: in case the instance was not found.
        """
        instance_document = find_documents(document={Constants.ID: id}, collection_type=DatabaseCollections.INSTANCES)

        if instance_document:
            images = instance_document[Constants.DOCKER][Constants.IMAGES]
            if images:
                return ApiResponse(response=images, http_status_code=HttpCodes.OK)
            else:
                raise ImageNotFoundError(type=Constants.IMAGES)
        else:
            return InstanceNotFoundError(type=Constants.INSTANCE, id=id)


if __name__ == "__main__":
    flask_wrapper = FlaskAppWrapper()
    flask_wrapper.add_endpoints(
        (
            '/SecurityGroups/Get',
            'SecurityGroupsApi.get_security_groups',
            SecurityGroupsApi.get_security_groups,
            [HttpMethods.GET]
        ),
        (
            '/SecurityGroups/Get/<id>',
            'SecurityGroupsApi.get_specific_security_group',
            SecurityGroupsApi.get_specific_security_group,
            [HttpMethods.GET]
        ),
        (
            '/SecurityGroups/Create',
            'SecurityGroupsApi.create_security_groups',
            SecurityGroupsApi.create_security_groups,
            [HttpMethods.POST]
        ),
        (
            '/SecurityGroups/Delete/<id>',
            'SecurityGroupsApi.delete_specific_security_group',
            SecurityGroupsApi.delete_specific_security_group,
            [HttpMethods.DELETE]
        ),
        (
            '/SecurityGroups/<id>/UpdateInboundPermissions',
            'SecurityGroupsApi.modify_security_group_inbound_permissions',
            SecurityGroupsApi.modify_security_group_inbound_permissions,
            [HttpMethods.PATCH]
        ),
        (
            '/Instances/Create',
            'InstancesApi.create_instances',
            InstancesApi.create_instances,
            [HttpMethods.POST]
        ),
        (
            '/Instances/Get',
            'InstancesApi.get_all_instances',
            InstancesApi.get_all_instances,
            [HttpMethods.GET]
        ),
        (
            '/Instances/Get/<id>',
            'InstancesApi.get_specific_instance',
            InstancesApi.get_specific_instance,
            [HttpMethods.GET]
        ),
        (
            '/Instances/Delete/<id>',
            'InstancesApi.delete_instance',
            InstancesApi.delete_instance,
            [HttpMethods.DELETE]
        ),
        (
            '/DockerServerInstance/<id>/CreateContainers',
            'ContainersApi.create_containers',
            ContainersApi.create_containers,
            [HttpMethods.POST]
        ),
        (
            '/DockerServerInstance/<id>/Get/Containers',
            'ContainersApi.get_all_instance_containers',
            ContainersApi.get_all_instance_containers,
            [HttpMethods.GET]
        ),
        (
            '/DockerServerInstance/<instance_id>/Get/Container/<container_id>',
            'ContainersApi.get_instance_container',
            ContainersApi.get_instance_container,
            [HttpMethods.GET]
        ),
        (
            '/DockerServerInstances/Get/Containers',
            'ContainersApi.get_all_instances_containers',
            ContainersApi.get_all_instances_containers,
            [HttpMethods.GET]
        ),
        (
            '/DockerServerInstances/<instance_id>/Delete/Container/<container_id>',
            'ContainersApi.delete_container',
            ContainersApi.delete_container,
            [HttpMethods.DELETE]
        ),
        (
            '/DockerServerInstances/<instance_id>/Start/Container/<container_id>',
            'ContainersApi.start_container',
            ContainersApi.start_container,
            [HttpMethods.PATCH],
        ),
        (
            '/DockerServerInstances/<id>/Image/Pull',
            'DockerImagesApi.pull_instance_images',
            DockerImagesApi.pull_instance_images,
            [HttpMethods.POST]
        )
    )
    flask_wrapper.run()
