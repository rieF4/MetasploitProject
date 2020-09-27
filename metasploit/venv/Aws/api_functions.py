from flask import request
from metasploit.venv.Aws.Database import (
    DatabaseCollections,
    delete_documents,
    find_documents,
    insert_document,
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
    ApiResponse
)
from metasploit.venv.Aws.Docker_Utils import (
    pull_image,
    create_container
)
from metasploit.venv.Aws.Aws_Api_Functions import (
    create_instance,
    create_security_group,
)
from metasploit.venv.Aws.ServerExceptions import (
    DuplicateImageError,
    InstanceNotFoundError
)


def create_resource(create_function, type="", **create_func_kwargs):
    create_request = request.json
    response = {}

    instance_id = create_func_kwargs.get("instance_id", "")

    if instance_id:
        instance_document = find_documents(
            document={Constants.ID: instance_id}, collection_type=DatabaseCollections.INSTANCES
        )
        if not instance_document:
            raise InstanceNotFoundError(type=type, id=instance_id)
        create_func_kwargs["instance_document"] = instance_document

    http_status_code = HttpCodes.CREATED
    is_valid = False
    is_error = False

    for key, req in create_request.items():
        try:
            response[key] = create_function(req=req, **create_func_kwargs)
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
    instance_document = pull_image_req_kwargs.get("instance_document")
    instance_id = pull_image_req_kwargs.get("instance_id")
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
    return {}


def create_instance_in_api(req):

    instance_obj = create_instance(kwargs=req)
    instance_response = prepare_instance_response(instance_obj=instance_obj, path=request.base_url)
    DatabaseCollections.INSTANCES.insert_one(document=instance_response)
    return instance_response


def create_security_group_in_api(req):
    security_group_obj = create_security_group(kwargs=req)

    security_group_database = prepare_security_group_response(
        security_group_obj=security_group_obj, path=request.base_url
    )
    DatabaseCollections.SECURITY_GROUPS.insert_one(document=security_group_database)
    return security_group_database


def create_container_in_api(req, **create_container_kwargs):
    instance_document = create_container_kwargs.get("instance_document")
    instance_id = create_container_kwargs.get("instance_id")
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
