import functools
from flask import jsonify
from flask_restful import request
from metasploit.venv.Aws import Constants
from werkzeug.exceptions import (
    BadRequest
)
from botocore.exceptions import ClientError, ParamValidationError
from metasploit.venv.Aws.ServerExceptions import (
    ResourceNotFoundError,
    DuplicateDockerResourceError,
    DuplicateImageError,
    BadJsonInput
)
from docker.errors import (
    ImageNotFound,
    APIError,
)
from metasploit.venv.Aws.Aws_Api_Functions import (
    get_docker_server_instance,
)
from metasploit.venv.Aws.Response import HttpCodes


def choose_port_for_msfrpcd(containers_document):
    """
    Choose dynamically the port that msfrpcd would listen to.

    Args:
        containers_document (dict): all of the instance container documents

    Returns:
        int: port to be used, 0 if there is not such a port.
    """
    used_ports = get_all_used_port_in_instance(containers_document=containers_document)
    for port in Constants.PORTS:
        if port not in used_ports:
            return port
    return 0


def get_all_used_port_in_instance(containers_document):
    all_containers_ports = [container_document["ports"] for container_document in containers_document]
    used_ports = []
    for container_port_details in all_containers_ports:
        for port in container_port_details.keys():
            used_ports.append(port)
    return used_ports


def update_container_document_attributes(instance_id):
    """
    Updates the container(s) documents that belongs to the instance.

    Args:
        instance_id (str): instance ID.

    Returns:
        list(dict): a list of dictionaries that composes the container updated documents.
    """

    container_documents = []

    docker_server_instance = get_docker_server_instance(id=instance_id)
    containers = docker_server_instance.docker().get_container_collection().list(all=True)

    for container in containers:
        container_documents.append(prepare_container_response(container_obj=container))

    return container_documents


def choose_http_error_code(error):
    """
    Returns the HTTP error code according to the error exception type.

    Args:
        error (Exception): an exception object.

    Returns:
        int: a http error code. (400's, 500's)
    """
    if isinstance(error, (ResourceNotFoundError, ImageNotFound)):
        return HttpCodes.NOT_FOUND
    elif isinstance(error, (ClientError, DuplicateDockerResourceError, DuplicateImageError)):
        return HttpCodes.DUPLICATE
    elif isinstance(error, (BadRequest, TypeError, AttributeError, ParamValidationError, BadJsonInput)):
        return HttpCodes.BAD_REQUEST
    elif isinstance(error, APIError):
        return HttpCodes.INTERNAL_SERVER_ERROR


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
    Finds a container document with the specified ID.

    Args:
        containers_documents (dict): a container documents form.
        container_id (str): container ID.

    Returns:
        dict: a container document if found, empty dict otherwise.
    """
    for container in containers_documents:
        if container[Constants.ID] == container_id:
            return container
    return {}


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
    container_obj.reload()

    return {
        "_id": container_obj.id,
        "image": container_obj.image.tags,
        "name": container_obj.name,
        "status": container_obj.status,
        "ports": container_obj.ports
    }


def prepare_network_response(network_obj):
    """
    Prepare a network parsed response for the client
    """
    network_obj.reload()

    return {
        "_id": network_obj.id,
        "name": network_obj.name,
        "containers": [container.id for container in network_obj.containers]
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


def validate_json_request(*expected_args, validate=True):
    """
    Validates the json request for an api function that needs a request as input.

    Args:
        validate (bool): is json validation required, True if it is, False otherwise.
        expected_args (list): list of arguments that should be checked if there are in the json request.
    """
    def decorator_validate_json(api_func):
        """
        decorator for an api function.

        Args:
            api_func (Function) an api function.
        """
        @functools.wraps(api_func)
        def wrapper_validate_json(*args, **kwargs):
            """
            Wrapper decorator to validate json input to the api.

            Args:
                args (list): function arguments.
                kwargs (dict): function arguments.

            Returns:
                ApiResponse: an api response object.

            Raises:
                BadJsonInput: in case the parameters for the json request are not valid.
                ResourceNotFoundError: in case the requested resource was not found.
            """
            if validate:
                type_validation, msg = validate_request_type()
                if not type_validation:
                    return make_error_response(msg=msg, http_error_code=HttpCodes.BAD_REQUEST, req=request.json)

                api_requests = request.json
                bad_inputs, is_valid_argument = validate_api_request_arguments(
                    api_requests=api_requests, expected_args=expected_args
                )

                if not is_valid_argument:
                    raise BadJsonInput(bad_inputs=bad_inputs)

            api_response = api_func(*args, **kwargs)
            return make_response(api_response=api_response)

        return wrapper_validate_json
    return decorator_validate_json


def validate_api_request_arguments(api_requests, expected_args):
    """
    Validates that the api request from the client has valid arguments for the api function that was used.

    Args:
        api_requests (dict): a dictionary that composes the api requests from the client.
        expected_args (list(str)): a list containing all the arguments that should be checked.

    Returns:
        tuple (dict, bool): a dictionary with arguments that aren't valid if exists and False,
        otherwise, otherwise dict with empty lists as values and True.
    """
    bad_inputs = {}
    is_valid_argument = True

    for key, api_req in api_requests.items():
        bad_inputs[key] = []
        for expected_arg in expected_args:
            if expected_arg not in api_req:
                is_valid_argument = False
                bad_inputs[key].append(expected_arg)

    return bad_inputs, is_valid_argument


def make_response_decorator(api_function):
    def wrapper(*args, **kwargs):

        api_response = api_function(*args, **kwargs)
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
        api_response (ApiResponse): api response object.

    Returns:
        tuple (Json, int): a (response, status_code) for the client.
    """
    resp = api_response.response
    http_status_code = api_response.http_status_code

    if resp:
        return jsonify(resp), http_status_code
    return jsonify(''), http_status_code


# class ApiResponse(object):
#     """
#     This is a class to represent an API response.
#
#     Attributes:
#         response (dict): a response from the database.
#         http_status_code (int): the http status code of the response.
#     """
#     def __init__(self, response={}, http_status_code=200):
#         self._response = response
#         self._http_status_code = http_status_code
#
#     def get_response(self):
#         return self._response
#
#     def get_http_status_code(self):
#         return self._http_status_code
#
#
# class HttpCodes:
#     OK = 200
#     CREATED = 201
#     ACCEPTED = 202
#     NO_CONTENT = 204
#     MULTI_STATUS = 207
#     BAD_REQUEST = 400
#     UNAUTHORIZED = 401
#     FORBIDDEN = 403
#     NOT_FOUND = 404
#     METHOD_NOT_ALLOWED = 405
#     DUPLICATE = 409
#     INTERNAL_SERVER_ERROR = 500


class HttpMethods:
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    DELETE = 'DELETE'
    PATCH = 'PATCH'


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
