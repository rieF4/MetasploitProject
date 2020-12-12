

from werkzeug.exceptions import (
    BadRequest
)
from botocore.exceptions import ClientError, ParamValidationError
from docker.errors import (
    ImageNotFound,
    APIError,
)

from .response import HttpCodes


class ApiException(Exception):
    """
    A base class for all api exceptions.
    """
    pass


class PortNotFoundError(ApiException):
    def __init__(self, msg):
        super().__init__(msg)


class CommandFailureError(ApiException):
    """
    This class represents an error exception for executing a command over an aws instance

    Attributes:
         cmd (str) - the command that was executed over the instance
         instance_id (str) - the instance id that this command was executed on
    """
    def __init__(self, cmd, instance_id):
        msg = f"The following command {cmd} has failed over the instance {instance_id}!"
        super().__init__(msg)


class ContainerCommandFailure(ApiException):
    def __init__(self, error_code, output, cmd, container_id):
        output = output.decode('utf-8')
        msg = f"the following {cmd} failed on container {container_id}, error code:{error_code}, output: {output}"
        super().__init__(msg)


class ResourceNotFoundError(ApiException):
    """
    This class represents an exception for a resource that was not found in the DB.
    """
    def __init__(self, type, id=None):
        if id:
            msg = f"{type} with ID {id} was not found"
        else:
            msg = f"{type} were not found."
        super().__init__(msg)


class AmazonResourceNotFoundError(ResourceNotFoundError):
    def __init__(self, type, id=None):
        super().__init__(type=type, id=id)


class DockerResourceNotFoundError(ResourceNotFoundError):
    def __init__(self, type, id=None):
        super().__init__(type=type, id=id)


class DuplicateDockerResourceError(ApiException):
    """
    This class represents an exception for a resource that already exists in the DB.
    """
    def __init__(self, resource):
        msg = f"{resource} already exists"
        super().__init__(msg)


class DuplicateImageError(DuplicateDockerResourceError):

    def __init__(self, resource):
        super().__init__(resource=resource)


class ModuleNotSupportedError(ApiException):
    def __init__(self, module_type, module_name=None):
        if module_name:
            msg = f"module {module_name} is not supported under module type {module_type}"
        else:
            msg = f"module type {module_type} is not a valid type"
        super().__init__(msg)


class PayloadNotSupportedError(ApiException):
    def __init__(self, unsupported_payloads):
        msg = ""
        for payload in unsupported_payloads:
            msg += f"Payload {payload} is not supported. "
        super().__init__(msg)


class BadJsonInput(ApiException):
    def __init__(self, bad_inputs):
        d = {}
        for key, inputs in bad_inputs.items():
            if inputs:
                d[key] = ""
                for input in inputs:
                    d[key] += f"Missing required parameter: {input}. "
        super().__init__(d)


class DatabaseOperationError(ApiException):
    def __init__(self, document, error_msg):
        msg = f"{error_msg}, document: {document}"
        super().__init__(msg)


class DeleteDatabaseError(DatabaseOperationError):
    def __init__(self, document, error_msg):
        super().__init__(document=document, error_msg=error_msg)


class InsertDatabaseError(DatabaseOperationError):
    def __init__(self, document, error_msg):
        super().__init__(document=document, error_msg=error_msg)


class UpdateDatabaseError(DatabaseOperationError):
    def __init__(self, document, error_msg):
        super().__init__(document=document, error_msg=error_msg)


class ModuleOptionsError(ApiException):

    def __init__(self, options, module_name):
        str_options = ""
        for o in options:
            str_options += o
        msg = f'The following {str_options} are missing options for {module_name}'
        super().__init__(msg)


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
