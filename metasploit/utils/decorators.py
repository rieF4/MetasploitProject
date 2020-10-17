import functools
from flask_restful import request

from metasploit.api.utils import (
    validate_request_type,
    validate_api_request_arguments
)
from metasploit.api.response import (
    HttpCodes,
    ErrorResponse,
    ApiResponse
)
from metasploit.api.errors import (
    BadJsonInput,
    choose_http_error_code
)


def singleton(cls):
    """
    Make a class a Singleton class (only one instance)
    """
    @functools.wraps(cls)
    def wrapper_singleton(*args, **kwargs):
        if not wrapper_singleton.instance:
            wrapper_singleton.instance = cls(*args, **kwargs)
        return wrapper_singleton.instance
    wrapper_singleton.instance = None
    return wrapper_singleton


def validate_json_request(*expected_args):
    """
    Validates the json request for an api function that needs a request as input.

    Args:
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

            type_validation, msg = validate_request_type(client_request=request.json)
            if not type_validation:
                return ErrorResponse(
                    error_msg=msg, http_error_code=HttpCodes.BAD_REQUEST, req=request.json
                ).make_response

            bad_inputs, is_valid_argument = validate_api_request_arguments(
                api_requests=request.json, expected_args=expected_args
            )

            if not is_valid_argument:
                raise BadJsonInput(bad_inputs=bad_inputs)

            return api_func(*args, **kwargs)

        return wrapper_validate_json
    return decorator_validate_json


def client_request_modifier(code):
    """
    Decorator for all API requests that were made by the client that requires data from client.

    Args:
        code (HttpCodes): HTTP code to return in case of success.
    """
    def client_request_decorator(api_func):
        """
        a decorator for an API function.

        Args:
            api_func (Function): the api function that gets decorated.
        """
        def client_request_wrapper(self):
            """
            Executes the function that handles a client request

            Args:
                self (ResourceOperation): the object reference as self. e.g. CreateAmazonResources, UpdateResource.
            """
            response = {}

            http_status_code = code
            is_valid = False
            is_error = False

            for key, req in self.api_manager.client_request.items():
                try:
                    response[key] = api_func(self=self, req=req)
                    is_valid = True
                except Exception as err:
                    print(err.__str__())
                    http_status_code = choose_http_error_code(error=err)
                    response[key] = ErrorResponse(
                        error_msg=err.__str__(), http_error_code=http_status_code, req=req
                    ).response
                    is_error = True

            if is_valid and is_error:
                http_status_code = HttpCodes.MULTI_STATUS

            return ApiResponse(response=response, http_status_code=http_status_code).make_response

        return client_request_wrapper
    return client_request_decorator
