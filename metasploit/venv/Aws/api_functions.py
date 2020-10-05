from flask import request
from metasploit.venv.Aws.Database import (
    DatabaseCollections,
    delete_documents,
    find_documents,
    insert_document,
    remove_specific_element_in_document,
    update_document
)

from metasploit.venv.Aws import Constants
from metasploit.venv.Aws.Api_Utils import (
    check_if_image_already_exists,
    prepare_image_response,
    prepare_instance_response,
    prepare_security_group_response,
    prepare_container_response,
    HttpCodes,
    choose_http_error_code,
    prepare_error_response,
    ApiResponse,
    update_container_document_attributes,
    find_container_document,
)
from metasploit.venv.Aws.Docker_Utils import (
    pull_image,
    create_container,
    get_container
)
from metasploit.venv.Aws.Aws_Api_Functions import (
    create_instance,
    create_security_group,
    get_security_group_object,
    get_aws_instance,
    update_security_group_inbound_permissions
)
from metasploit.venv.Aws.ServerExceptions import (
    DuplicateImageError,
    InstanceNotFoundError,
    SecurityGroupNotFoundError,
    ContainerNotFoundError,
    ImageNotFoundError,
    ResourceNotFoundError
)
from docker.errors import (
    APIError
)


def create_update_resource(function, collection_type=None, type="", **create_func_kwargs):
    """
    Creates a resource in the api.

    Args:
        function (Function): api function that should be executed.
        collection_type (pymongo.Collection): the collection that the request should be searched on.
        type (str): the resource type. etc: SecurityGroup(s), Instance(s), Container(s)

        Keyword arguments:
            resource_id (str): resource ID.

    Returns:
        ApiResponse: api response object.

    """
    create_request = request.json
    response = {}

    resource_id = create_func_kwargs.get("resource_id", "")

    if resource_id:
        found_document = find_documents(document={Constants.ID: resource_id}, collection_type=collection_type)
        if not found_document:
            raise ResourceNotFoundError(type=type, id=resource_id)
        create_func_kwargs["document"] = found_document

    http_status_code = HttpCodes.CREATED
    is_valid = False
    is_error = False

    for key, req in create_request.items():
        try:
            response[key] = function(req=req, **create_func_kwargs)
            is_valid = True
        except Exception as err:
            http_status_code = choose_http_error_code(error=err)
            response[key] = prepare_error_response(
                msg=err.__str__(), http_error_code=http_status_code, req=req
            )
            is_error = True

    if is_valid and is_error:
        http_status_code = HttpCodes.MULTI_STATUS

    return ApiResponse(response=response, http_status_code=http_status_code)


def pull_instance_image(req, **pull_image_req_kwargs):
    """
    Creates a new image over the docker server and adds a new image document to the DB.

    Args:
        req (dict): the client request.

        Keyword arguments:
            instance_document (dict): instance document from the DB.
            instance_id (str): instance ID.

    Returns:
        dict: image response if success.

    """
    instance_document = pull_image_req_kwargs.get("document")
    instance_id = pull_image_req_kwargs.get("resource_id")
    repository = req.pop("Repository")
    tag = "latest"
    tag_to_check = f"{repository}:{tag}"

    if check_if_image_already_exists(
            image_document=instance_document[Constants.DOCKER][Constants.IMAGES],
            tag_to_check=tag_to_check
    ):
        raise DuplicateImageError(resource=tag_to_check)

    image = pull_image(instance_id=instance_id, repository=repository, tag=tag, **req)

    image_response = prepare_image_response(image_obj=image)

    if delete_documents(collection_type=DatabaseCollections.INSTANCES, document=instance_document):
        instance_document[Constants.DOCKER][Constants.IMAGES].append(image_response)

        if DatabaseCollections.INSTANCES.insert_one(document=instance_document):
            return image_response


def create_instance_in_api(req):
    """
    Creates an instance in AWS and adds a new instance document to the DB.

    Args:
        req (dict): client request.

    Returns:
        dict: a new instance response if success.
    """
    instance_obj = create_instance(kwargs=req)
    instance_response = prepare_instance_response(instance_obj=instance_obj, path=request.base_url)
    DatabaseCollections.INSTANCES.insert_one(document=instance_response)
    return instance_response


def create_security_group_in_api(req):
    """
    Creates new security group in AWS and adds a new security group document to the DB.

    Args:
        req (dict): client request.

    Returns:
        dict: a new security group response if success.
    """
    security_group_obj = create_security_group(kwargs=req)

    security_group_database = prepare_security_group_response(
        security_group_obj=security_group_obj, path=request.base_url
    )
    DatabaseCollections.SECURITY_GROUPS.insert_one(document=security_group_database)
    return security_group_database


def create_container_in_api(req, **create_container_kwargs):
    """
    Creates a new container in Docker server and adds new container document to the DB.

    Args:
        req (dict): the client request.

        Keyword arguments:
            instance_document (dict): instance document from the DB.
            instance_id (str): instance ID.

    Returns:
        dict: container response if success.

    """
    instance_document = create_container_kwargs.get("document")
    instance_id = create_container_kwargs.get("resource_id")
    image = req.pop('Image')
    command = req.pop('Command', None)

    container_obj = create_container(
        instance_id=instance_id, image=image, kwargs=req, command=command
    )

    container_response = prepare_container_response(container_obj=container_obj)

    if delete_documents(collection_type=DatabaseCollections.INSTANCES, document=instance_document):

        instance_document[Constants.DOCKER][Constants.CONTAINERS].append(container_response)

        if insert_document(collection_type=DatabaseCollections.INSTANCES, document=instance_document):
            return container_response


def get_security_groups_from_database():
    """
    Get all the security groups documents available in the database.

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


def get_specific_security_group_from_database(security_group_id):
    """
    Get specific security group document by ID from the DB.

    Args:
        security_group_id (str): security group ID.

    Returns:
        ApiResponse: an api response object.

    Raises:
        SecurityGroupNotFoundError: in case there is not a security group with the ID.
    """
    security_group = find_documents(
        document={Constants.ID: security_group_id}, collection_type=DatabaseCollections.SECURITY_GROUPS
    )

    if security_group:
        return ApiResponse(response=security_group, http_status_code=HttpCodes.OK)
    else:
        raise SecurityGroupNotFoundError(type=Constants.SECURITY_GROUP, id=security_group_id)


def delete_security_group(security_group_id):
    """
    Deletes a security group from AWS and removes it from the DB by its ID.

    Args:
        security_group_id (str): security group ID.

    Returns:
        ApiResponse: an api response object.

    Raises:
        SecurityGroupNotFoundError: in case there is not a security group with the ID.
    """
    security_group = find_documents(
        document={Constants.ID: security_group_id}, collection_type=DatabaseCollections.SECURITY_GROUPS
    )

    if security_group:
        get_security_group_object(id=security_group_id).delete()
        if delete_documents(collection_type=DatabaseCollections.SECURITY_GROUPS, document=security_group):
            return ApiResponse(http_status_code=HttpCodes.NO_CONTENT)
    else:
        raise SecurityGroupNotFoundError(type=Constants.SECURITY_GROUP, id=security_group_id)


def get_all_instances_from_database():
    """
    Get all the instances documents available from the database.

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

    if instances_response:
        for ins_res in instances_response[Constants.INSTANCES]:
            if ins_res[Constants.DOCKER][Constants.CONTAINERS]:
                ins_res[Constants.DOCKER][Constants.CONTAINERS] = update_container_document_attributes(
                    instance_id=ins_res[Constants.ID]
                )

    if instances_response:
        return ApiResponse(response=instances_response, http_status_code=HttpCodes.OK)
    else:
        raise InstanceNotFoundError(type=Constants.INSTANCES)


def get_specific_instance_from_database(instance_id):
    """
    Get a specific instance document from the database by its ID.

    Args:
        instance_id (str): instance id.

    Returns:
        ApiResponse: an api response object.

    Raises:
        InstanceNotFoundError: in case there is not an instance with the ID.
    """
    instance_response = find_documents(
        document={Constants.ID: instance_id}, collection_type=DatabaseCollections.INSTANCES
    )

    if instance_response:
        if instance_response[Constants.DOCKER][Constants.CONTAINERS]:
            instance_response[Constants.DOCKER][Constants.CONTAINERS] = update_container_document_attributes(
                instance_id=instance_response[Constants.ID]
            )
        return ApiResponse(response=instance_response, http_status_code=HttpCodes.OK)
    else:
        raise InstanceNotFoundError(type=Constants.INSTANCE, id=instance_id)


def delete_instance(instance_id):
    """
    Deletes a specific instance from AWS and removes it from the DB by its ID.

    Args:
        instance_id (str): instance ID.

    Returns:
        ApiResponse: an api response object.

    Raises:
        InstanceNotFoundError: in case there is not an instance with the ID.
    """
    instance_document = find_documents(
        document={Constants.ID: instance_id}, collection_type=DatabaseCollections.INSTANCES
    )

    if instance_document:
        get_aws_instance(id=instance_id).terminate()
        if delete_documents(collection_type=DatabaseCollections.INSTANCES, document=instance_document):
            return ApiResponse(http_status_code=HttpCodes.NO_CONTENT)
    else:
        raise InstanceNotFoundError(type=Constants.INSTANCE, id=instance_id)


def get_all_instance_containers_from_database(instance_id):
    """
    Get all the containers documents of a specific instance from the database.

    Args:
        instance_id (str): instance ID.

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
        containers = instance_document[Constants.DOCKER][Constants.CONTAINERS]

        if containers:
            containers = update_container_document_attributes(instance_id=instance_id)

            return ApiResponse(
                response={
                    Constants.CONTAINERS: containers
                },
                http_status_code=HttpCodes.OK
            )
        else:
            raise ContainerNotFoundError(type=Constants.CONTAINERS)
    else:
        raise InstanceNotFoundError(type=Constants.INSTANCE, id=instance_id)


def get_instance_container_from_database(instance_id, container_id):
    """
    Gets a container document by instance and container IDs from the database.

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

                return ApiResponse(
                    response=instance_document[Constants.DOCKER][Constants.CONTAINERS],
                    http_status_code=HttpCodes.OK
                )
        else:
            raise ContainerNotFoundError(type=Constants.CONTAINER, id=container_id)
    else:
        raise InstanceNotFoundError(type=Constants.INSTANCE, id=instance_id)


def get_all_instances_containers_from_database():
    """
    Get all the the documents of all the containers of all available instances from the DB.

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


def delete_container(instance_id, container_id):
    """
    Deletes the container over an instance and removes it from the DB.

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
        containers = instance_document[Constants.DOCKER][Constants.CONTAINERS]
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


def get_all_instance_images_from_database(instance_id):
    """
    Get all instance docker images from the DB by its ID.

    Args:
        instance_id (str): instance ID.

    Returns:
        ApiResponse: an api response object.

    Raises:
        ImageNotFoundError: in case there aren't any images available.
        InstanceNotFoundError: in case the instance was not found.
    """
    instance_document = find_documents(
        document={Constants.ID: instance_id}, collection_type=DatabaseCollections.INSTANCES
    )

    if instance_document:
        images = instance_document[Constants.DOCKER][Constants.IMAGES]
        if images:
            return ApiResponse(response=images, http_status_code=HttpCodes.OK)
        else:
            raise ImageNotFoundError(type=Constants.IMAGES)
    else:
        raise InstanceNotFoundError(type=Constants.INSTANCE, id=instance_id)


def update_security_group_inbound_permissions_in_api(req, **update_sc_permissions_kwargs):
    """
    Updates the security group inbound permissions in AWS and update security group document in DB.

    Args:
        req (dict): client api request.

        Keyword Arguments:
            resource_id (str): security group ID.
    """
    security_group_id = update_sc_permissions_kwargs.get("resource_id")
    ip_permissions = update_security_group_inbound_permissions(req=req, security_group_id=security_group_id)

    if update_document(
            fields={"IpPermissionsInbound": ip_permissions},
            collection_type=DatabaseCollections.SECURITY_GROUPS,
            operation=Constants.SET,
            id=security_group_id
    ):
        security_group_response = find_documents(
            document={Constants.ID: security_group_id}, collection_type=DatabaseCollections.SECURITY_GROUPS
        )

        return security_group_response
