from flask import jsonify
from flask_restful import request
from metasploit.venv.Aws import Constants
from werkzeug.exceptions import BadRequest
from metasploit.venv.Aws.custom_exceptions import (
    ResourceNotFoundError
)


def check_if_image_already_exists(image_document, tag_to_check):
    """
    Check if the image with the specified tag already exists.

    Args:
        image_document (dict): image document.
        tag_to_check (str): tag that should be checked.

    Returns:
        bool: True if the tag was found, False otherwise
    """
    for image in image_document:
        for tag in image['tags']:
            if tag == tag_to_check:
                return True
    return False


def find_container_document(containers_documents, container_id):
    """
    Find a container document with the specified ID.

    Args:
        containers_documents (dict): a container documents form.
        container_id (str): container ID.

    Returns:
        tuple (dict, int): container response matching to container ID and it's index in the list,
        empty dict and -1 otherwise.
    """
    for index, container in enumerate(containers_documents):
        if container[Constants.ID] == container_id:
            return container[Constants.ID], index
    return {}, -1


def prepare_error_response(msg, http_error_code, req=None, path=None):
    """
    Prepare an error response for a resource.

    Args:
        msg (str): error message to send.
        http_error_code (int): the http error code.
        req (dict): the request by the client.
        path (str): The path in the api the error occurred.

    Returns:
        dict: parsed error response for the client.
    """
    return {
        "Error":
            {
                "Message": msg,
                "Code": http_error_code,
                "Request": req,
                "Url": path
            }
    }


def prepare_security_group_response(security_group_obj, path):
    """
    Create a security group parsed response for the client.

    Args:
        security_group_obj (SecurityGroup): security group object.
        path (str): the api path to the newly created security group

    Returns:
        dict: a parsed security group response.
    """
    return {
        "_id": security_group_obj.group_id,
        "Description": security_group_obj.description,
        "Name": security_group_obj.group_name,
        "Url": path.replace("Create", security_group_obj.group_id),
        "IpPermissionsInbound": security_group_obj.ip_permissions,  # means permissions to connect to the instance
        "IpPermissionsOutbound": security_group_obj.ip_permissions_egress
    }


def prepare_instance_response(instance_obj, path):
    """
    Prepare a create instance parsed response for the client.

    Args:
        instance_obj (DockerServerInstance): an instance object that was created.
        path (str): the api path to the newly created instance.

    Returns:
        dict: a parsed instance response.
    """
    return {
        "_id": instance_obj.get_instance_id(),
        "IpParameters": {
            "PublicIpAddress": instance_obj.get_public_ip_address(),
            "PublicDNSName": instance_obj.get_public_dns_name(),
            "PrivateIpAddress": instance_obj.get_private_ip_address(),
            "PrivateDNSName": instance_obj.get_private_dns_name()
        },
        "SecurityGroups": instance_obj.get_security_groups(),
        "State": instance_obj.get_state(),
        "KeyName": instance_obj.get_key_name(),
        "Docker": {
            "Containers": [],
            "Images": [],
            "Networks": []
        },
        "Url": path.replace("Create", instance_obj.get_instance_id())
    }


def prepare_image_response(image_obj):
    """
    Prepare an image parsed response for the client.

    Args:
        image_obj (Image): an image object.

    Returns:
        dict: a parsed instance response.
    """
    return {
        "_id": image_obj.id,
        "tags": image_obj.tags
    }


def prepare_container_response(container_obj):
    """
    Prepare a create container parsed response for the client.

    Args:
        container_obj (Container): a container object.

    Returns:
        dict: a parsed instance response.
    """
    return {
        "_id": container_obj.id,
        "image": container_obj.image,
        "name": container_obj.name,
        "status": container_obj.status
    }


def validate_request_type():
    """
    Validate the client request type (dict).

    Returns:
        tuple(bool, str): a tuple that indicates if the request type is ok. (True, 'Success') for a valid request type,
        otherwise, (False, err)

    Raises:
         BadRequest:
         TypeError:
         AttributeError:
    """
    try:
        req = request.json
        if not isinstance(req, dict):
            return False, "Request type is not a dictionary form."
        return True, 'Success'
    except (BadRequest, TypeError, AttributeError) as err:
        return False, err.__str__()


def request_error_validation(api_function):
    def wrapper(*args, **kwargs):

        if request.method not in [HttpMethods.GET, HttpMethods.DELETE]:
            type_validation, msg = validate_request_type()

            if not type_validation:
                return make_error_response(msg=msg, http_error_code=HttpCodes.BAD_REQUEST)
        try:
            api_response = api_function(*args, **kwargs)
        except ResourceNotFoundError as err:
            return make_error_response(
                msg=err.__str__(), http_error_code=HttpCodes.NOT_FOUND, req=request.json, path=request.base_url
            )

        return make_response(api_response=api_response)

    return wrapper


def make_error_response(msg, http_error_code, req=None, path=None):
    """
    Make error response for the client.

    Args:
        msg (str): error message to send.
        http_error_code (int): the http error code.
        req (dict): the request by the client.
        path (str): The path in the api the error occurred.

    Returns:
        tuple (Json, int): (error, error_status_code) for the client.
    """
    return jsonify(
        prepare_error_response(
            msg=msg, http_error_code=http_error_code, req=req, path=path
        )
    ), http_error_code


def make_response(api_response):
    """
    Returns a json and http status code to the client.

    Args:
        (ApiResponse): api response object.

    Returns:
        tuple (Json, int): a (response, status_code) for the client.
    """
    resp = api_response.get_response()
    http_status_code = api_response.get_http_status_code()

    if resp:
        return jsonify(resp), http_status_code
    return jsonify(''), http_status_code


class ApiResponse(object):
    """
    This is a class to represent an API response.

    Attributes:
        response (dict): a response from the database.
        http_status_code (int): the http status code of the response.
    """
    def __init__(self, response={}, http_status_code=200):
        self._response = response
        self._http_status_code = http_status_code

    def get_response(self):
        return self._response

    def get_http_status_code(self):
        return self._http_status_code


class HttpCodes:
    OK = 200
    CREATED = 201
    ACCEPTED = 202
    NO_CONTENT = 204
    MULTI_STATUS = 207
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    METHOD_NOT_ALLOWED = 405
    DUPLICATE = 409
    INTERNAL_SERVER_ERROR = 500


class HttpMethods:
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    DELETE = 'DELETE'
    PATCH = 'PATCH'
