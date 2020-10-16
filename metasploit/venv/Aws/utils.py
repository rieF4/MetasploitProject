import functools
from flask_restful import request
from metasploit.venv.Aws import Constants
from werkzeug.exceptions import (
    BadRequest
)
from metasploit.venv.Aws.ServerExceptions import (
    ResourceNotFoundError,
    BadJsonInput
)
from metasploit.venv.Aws.Response import HttpCodes


def choose_port_for_msfrpcd(containers_document):
    """
    Choose dynamically the port that msfrpcd would listen to.

    Args:
        containers_document (dict): all of the instance container docker_documents

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


class HttpMethods:
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    DELETE = 'DELETE'
    PATCH = 'PATCH'
