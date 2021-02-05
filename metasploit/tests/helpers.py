import json
import logging
from metasploit.api.response import HttpCodes


logger = logging.getLogger("GlobalHelpers")


def to_utf8(response_as_bytes):
    """
    Converts bytes into a utf-8 string.

    Args:
        response_as_bytes (bytes): the bytes to convert to utf-8

    Returns:
        str: a utf-8 string.
    """
    return response_as_bytes.decode('utf-8')


def load_json(string):
    """
    Converts a string to a valid data type e.g.: dict, list.

    Args:
        string (str): a string representing a rest api response

    Returns:
        a valid data type. e.g.: list, dict.
    """
    return json.loads(string)


def convert(response_as_bytes):
    """
    converts the response from the API into a valid data type.

    Args:
        response_as_bytes (bytes): the bytes to convert into a valid data type.

    Returns:
        a valid data type. e.g.: list, dict.
    """
    return load_json(to_utf8(response_as_bytes=response_as_bytes))


def is_expected_code(actual_code, expected_code=HttpCodes.OK):
    """
    Checks whether the status code is what's expected.

    Args:
        actual_code (int): actual code from the API.
        expected_code (int): expected code from the API.
    """
    return expected_code == actual_code


def is_error_response_valid(error_response, **expected):
    """
    Validates that an error response is as expected.

    Args:
        error_response (dict): the error response body.

    Keyword arguments:
         code (int): expected status code.
         message (str): expected message
         request (str): expected request
         url (str): expected URL.

    Returns:
        bool: True if error response is valid, False otherwise.
    """
    if "Error" not in error_response:
        logger.error(f"The response {error_response} is not error response!")
        return False

    error_response_body = error_response["Error"]

    if "Code" not in error_response_body:
        logger.error(f"There is no Code key in the error response body {error_response_body}")
        return False

    if "Message" not in error_response_body:
        logger.error(f"There is no Message key in the error response body {error_response_body}")
        return False

    if "Request" not in error_response_body:
        logger.error(f"There is no Request key in the error response body {error_response_body}")
        return False

    if "Url" not in error_response_body:
        logger.error(f"There is no Url key in the error response body {error_response_body}")
        return False

    return is_error_response_body_expected(error_response_body=error_response_body, **expected)


def is_error_response_body_expected(error_response_body, **expected):
    """
    Validates that an error response is as expected.

    Args:
        error_response_body (dict): the error response body.

    Keyword arguments:
        code (int): expected status code.
        message (str): expected message
        request (str): expected request
        url (str): expected URL.

    Returns:
        bool: True if the response is as expected, False otherwise.
    """
    actual_status_code = error_response_body.get("Code")
    expected_status_code = expected.get("code")

    if expected_status_code is not None and actual_status_code != expected_status_code:
        logger.error(f"actual status code: {actual_status_code}, expected status code: {expected_status_code}")
        return False

    actual_message = error_response_body.get("Message")
    expected_message = expected.get("message")

    if expected_message is not None and actual_message != expected_message:
        logger.error(f"actual message: {actual_message}, expected message: {expected_message}")
        return False

    actual_request = error_response_body.get("Request")
    expected_request = expected.get("request")

    if expected_request is not None and actual_request != expected_request:
        logger.error(f"actual request: {actual_request}, expected request: {expected_request}")
        return False

    actual_url = error_response_body.get("Url")
    expected_url = expected.get("url")

    if expected_url is not None and actual_url != expected_url:
        logger.error(f"actual url: {actual_url}, expected url: {expected_url}")
        return False

    return True


def execute_rest_api_func(url, api_func, convert_func=convert, request_body=None):
    """
    Execute the REST-API Http request to the server [POST, GET, DELETE]

    Args:
        url (str): URL for the request.
        api_func (function): API function type e.g.: (POST, GET, DELETE)
        convert_func (function): a convert function (to-utf-8, convert)
        request_body (dict): a request body in case exists.

    Returns:
        tuple[dict/list[dict]/str, int]: a tuple containing the body response and status code.
    """
    if request_body:
        full_response = api_func(url, json=request_body)
    else:
        full_response = api_func(url)

    response_body = convert_func(response_as_bytes=full_response.data)
    status_code = full_response.status_code

    return response_body, status_code
