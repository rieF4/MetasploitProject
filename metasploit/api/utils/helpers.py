import time
from metasploit.api import constants as global_constants

from metasploit.api.errors import (
    BadRequest,
    PortNotFoundError,
    DuplicateImageError,
    TimeoutExpiredError,
    InvalidInputTypeError
)


def choose_port_for_msfrpcd(containers_document):
    """
    Choose dynamically the port that msfrpcd would listen to.

    Args:
        containers_document (dict): all of the instance container docker_documents

    Returns:
        int: port to be used, 0 if there is not such a port.
    """
    used_ports = get_all_used_port_in_instance(containers_document=containers_document)
    for port in global_constants.PORTS:
        if port not in used_ports:
            return port
    raise PortNotFoundError('No port available to run msfrpc daemon in a container - internal server error')


def get_all_used_port_in_instance(containers_document):
    if containers_document:
        all_containers_ports = [container_document["ports"] for container_document in containers_document]
        used_ports = []
        for container_port_details in all_containers_ports:
            for port in container_port_details.keys():
                used_ports.append(port)
        return used_ports
    else:
        return []


def check_if_image_already_exists(image_document, tag_to_check):
    """
    Check if the image with the specified tag already exists.

    Args:
        image_document (dict): image document.
        tag_to_check (str): tag that should be checked.

    Returns:
        bool: False if the tag was not found.

    Raises
    """
    for image in image_document:
        for tag in image['tags']:
            if tag == tag_to_check:
                raise DuplicateImageError(resource=tag)
    return False


def validate_request_type(client_request):
    """
    Validate the client request type (dict).

    Returns:
        tuple(bool, str): a tuple that indicates if the request type is ok. (True, 'Success') for a valid request type,
        otherwise, (False, err)
    """
    try:
        if not isinstance(client_request, dict):
            return False
        return True
    except (BadRequest, TypeError, AttributeError):
        raise InvalidInputTypeError()


def validate_api_request_arguments(api_request, expected_args):
    """
    Validates that the api request from the client has valid arguments for the api function that was used.

    Args:
        api_request (dict): a dictionary that composes the api request from the client.
        expected_args (list(str)): a list containing all the arguments that should be checked.

    Returns:
        list: a list with arguments that aren't valid if exists, empty list otherwise
    """
    bad_inputs = []

    for expected_arg in expected_args:
        if expected_arg not in api_request:
            bad_inputs.append(expected_arg)
    return bad_inputs


class HttpMethods:
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    DELETE = 'DELETE'
    PATCH = 'PATCH'


class TimeoutSampler(object):

    def __init__(self, timeout, sleep, func, *func_args, **func_kwargs):
        self.timeout = timeout
        ''' Timeout in seconds. '''
        self.sleep = sleep
        ''' Sleep interval seconds. '''

        self.func = func
        ''' A function to sample. '''
        self.func_args = func_args
        ''' Args for func. '''
        self.func_kwargs = func_kwargs
        ''' Kwargs for func. '''

        self.start_time = None
        ''' Time of starting the sampling. '''
        self.last_sample_time = None
        ''' Time of last sample. '''

    def __iter__(self):
        """
        Iterator that generates the function output every 'sleep' seconds.

        Yields:
            any function output.

        Raises:
            TimeoutExpiredError: in case the function sampling reached to the timeout provided
        """
        if self.start_time is None:
            self.start_time = time.time()

        while True:
            self.last_sample_time = time.time()
            yield self.func(*self.func_args, **self.func_kwargs)

            if self.timeout < (time.time() - self.start_time):
                raise TimeoutExpiredError(error_msg=f"Timeout occurred sampling {self.func.__name__}")
            time.sleep(self.sleep)

    def iterate_over_func_results(self, result):
        """
        Samples the function and in case the function gets the desired result (True or False).

        Args:
            result (bool): expected result from the function.

        Returns:
            bool: in case function output is what's expected, false otherwise.
        """
        try:
            for res in self:
                if result == res:
                    return True
        except TimeoutExpiredError:
            return False


def remove_trailing_spaces(string):
    """
    Removes trailing spaces from a string

    Args:
        string (str): a string to remove spaces from.

    Returns:
        str: a string without trailing spaces
    """
    if isinstance(string, str):
        string.replace("\n", "")
        return "".join(string.split())
    return ""
