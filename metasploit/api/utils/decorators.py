import functools
from flask_restful import request

from metasploit.api.utils.helpers import (
    validate_request_type,
    validate_api_request_arguments
)
from metasploit.api.response import (
    ErrorResponse,
    ApiResponse,
    HttpCodes
)
from metasploit.api.errors import (
    BadJsonInput,
    InvalidInputTypeError,
    choose_http_error_code
)
from boto3.exceptions import Boto3Error
from docker.errors import DockerException
from metasploit.api.aws.amazon_operations import DockerServerInstanceOperations
from metasploit.api import constants as global_const
from metasploit.api.errors import (
    ApiException,
    AmazonResourceNotFoundError,
    MetasploitActionError
)


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
                ApiResponse: an api response obj.

            Raises:
                BadJsonInput: in case the parameters for the json request are not valid.
                ResourceNotFoundError: in case the requested resource was not found.
            """

            type_validation = validate_request_type(client_request=request.json)
            if not type_validation:
                raise InvalidInputTypeError()

            bad_inputs = validate_api_request_arguments(
                api_request=request.json, expected_args=expected_args
            )
            if bad_inputs:
                raise BadJsonInput(bad_inputs=bad_inputs)

            return api_func(*args, **kwargs)

        return wrapper_validate_json
    return decorator_validate_json


def update_containers_status(func):
    """
    Updates containers status in case there is any change with them ( running state ---> stopped state for example)
    """
    def wrapper(self, **kwargs):
        database = self.database

        instance_documents = database.get_all_documents()

        for document in instance_documents:
            docker_server_instance = DockerServerInstanceOperations(instance_id=document[global_const.ID]).docker_server
            containers = docker_server_instance.docker.container_collection.list(all=True)

            for container in containers:
                container.reload()
                for container_document in document["Containers"]:

                    if container.id == container_document[global_const.ID]:
                        if container.status != container_document["status"]:

                            database.update_docker_document(
                                docker_document_type="Container",
                                docker_document_id=container.id,
                                update={"Containers.$.status": container.status},
                                docker_server_id=document[global_const.ID]
                            )
        return func(self, **kwargs)
    return wrapper


def response_decorator(code):
    """
    Decorator to execute all the API services implementations and parse a valid response to them.

    Args:
        code (int): http code that should indicate about success.
    """
    def first_wrapper(func):
        """
        wrapper to get the service function.

        Args:
            func (Function): a function object representing the API service function.
        """
        def second_wrapper(*args, **kwargs):
            """
            Args:
                args: function args
                kwargs: function kwargs

            Returns:
                Response: flask api response.
            """
            try:
                return ApiResponse(response=func(*args, **kwargs), http_status_code=code).make_response
            except ApiException as exc:
                return ErrorResponse(
                    error_msg=str(exc), http_error_code=exc.error_code, req=request.json, path=request.base_url
                ).make_response
            except (Boto3Error, DockerException) as exc:
                error_code = choose_http_error_code(error=exc)
                return ErrorResponse(
                    error_msg=str(exc), http_error_code=error_code, req=request.json, path=request.base_url
                ).make_response

        return second_wrapper
    return first_wrapper


def metasploit_action_verification(func):
    """
    Verifies that the metasploit actions that are performed are valid.

    Args:
        func (Function): metasploit function.
    """

    def wrapper(self, *args, **kwargs):
        """
        Catches error of metasploit actions in case there are any.
        """
        try:
            return func(self, *args, **kwargs)
        except Exception as exc:
            raise MetasploitActionError(error_msg=str(exc), error_code=HttpCodes.BAD_REQUEST)

    return wrapper
