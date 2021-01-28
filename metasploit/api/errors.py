

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
    def __init__(self, error_msg, error_code):

        self.error_msg = error_msg
        self.error_code = error_code

        super().__init__(error_msg)

    def __str__(self):

        if self._is_client_error():
            return f"{self.error_code} Client error: {self.error_msg}"
        elif self._is_server_error():
            return f"{self.error_code} Server error: {self.error_msg}"

    def _is_client_error(self):
        return 400 <= self.error_code < 500

    def _is_server_error(self):
        return 500 <= self.error_code < 600


class InvalidHostName(ApiException):

    def __init__(self, invalid_host, error_code=HttpCodes.BAD_REQUEST):
        msg = f"the host {invalid_host} is invalid and does not exist!"
        super().__init__(error_msg=msg, error_code=error_code)


class GeneralConnectionError(ApiException):

    def __init__(self, error_msg, error_code=HttpCodes.SERVICE_UNAVAILABLE):
        super().__init__(error_msg=error_msg, error_code=error_code)


class MsfrpcdConnectionError(GeneralConnectionError):

    def __init__(self, host, port, error_code=HttpCodes.SERVICE_UNAVAILABLE):
        error_msg = f"Failed to setup connection to msfrpc daemon at {host} using port {port}"
        super().__init__(error_msg=error_msg, error_code=error_code)


class SSHConnectionError(GeneralConnectionError):
    def __init__(self, host, error_code=HttpCodes.SERVICE_UNAVAILABLE):
        error_msg = f"Failed to connect with SSH to {host}"
        super().__init__(error_msg=error_msg, error_code=error_code)


class DockerServerConnectionError(GeneralConnectionError):

    def __init__(self, url, error_code=HttpCodes.SERVICE_UNAVAILABLE):
        error_msg = f"Failed to connect to {url}"
        super().__init__(error_msg=error_msg, error_code=error_code)


class PortNotFoundError(ApiException):

    def __init__(self, error_code=HttpCodes.INTERNAL_SERVER_ERROR):
        error_msg = "Unable to find available port to start a metasploit based container"
        super().__init__(error_msg=error_msg, error_code=error_code)


class CommandFailureError(ApiException):
    """
    This class represents an error exception for executing a command over an aws instance

    Attributes:
         cmd (str) - the command that was executed over the instance
         instance_id (str) - the instance id that this command was executed on
    """
    def __init__(self, cmd, instance_id, error_code=HttpCodes.INTERNAL_SERVER_ERROR):
        msg = f"The following command {cmd} has failed over the instance {instance_id}!"
        super().__init__(error_msg=msg, error_code=error_code)


class ContainerCommandFailure(ApiException):

    def __init__(self, error_code, output, cmd, container_id):
        output = output.decode('utf-8')
        msg = f"the following {cmd} failed on container {container_id}, output: {output}"
        super().__init__(error_msg=msg, error_code=error_code)


class ResourceNotFoundError(ApiException):
    """
    This class represents an exception for a resource that was not found in the DB.
    """
    def __init__(self, type, id, error_code=HttpCodes.NOT_FOUND):
        msg = f"{type} with ID {id} was not found"
        super().__init__(error_msg=msg, error_code=error_code)


class AmazonResourceNotFoundError(ResourceNotFoundError):
    pass


class DockerResourceNotFoundError(ResourceNotFoundError):
    pass


class DuplicateDockerResourceError(ApiException):
    """
    This class represents an exception for a resource that already exists in the DB.
    """
    def __init__(self, resource, error_code=HttpCodes.DUPLICATE):
        msg = f"{resource} already exists"
        super().__init__(error_msg=msg, error_code=error_code)


class DuplicateImageError(DuplicateDockerResourceError):
    pass


class ModuleNotSupportedError(ApiException):

    def __init__(self, module_type, module_name=None, error_code=HttpCodes.BAD_REQUEST):
        if module_name:
            msg = f"module name {module_name} is not supported under module type {module_type}"
        else:
            msg = f"module type {module_type} is not a valid type"
        super().__init__(error_msg=msg, error_code=error_code)


class PayloadNotSupportedError(ApiException):

    def __init__(self, unsupported_payloads, error_code=HttpCodes.BAD_REQUEST):
        msg = ""
        for payload in unsupported_payloads:
            msg += f"Payload {payload} is not supported. "
        super().__init__(error_msg=msg, error_code=error_code)


class MetasploitActionError(ApiException):
    pass


class InvalidInputTypeError(ApiException):

    def __init__(self, error_code=HttpCodes.BAD_REQUEST):
        msg = "The input type is invalid!"
        super().__init__(error_msg=msg, error_code=error_code)


class BadJsonInput(ApiException):

    def __init__(self, bad_inputs, error_code=HttpCodes.BAD_REQUEST):
        msg = ""
        for input in bad_inputs:
            msg += f"Missing required parameter: {input}  "
        super().__init__(error_msg=msg, error_code=error_code)


class DatabaseOperationError(ApiException):

    def __init__(self, document, error_msg, error_code=HttpCodes.INTERNAL_SERVER_ERROR):
        msg = f"{error_msg}, document: {document}"
        super().__init__(error_msg=msg, error_code=error_code)


class DeleteDatabaseError(DatabaseOperationError):
    pass


class InsertDatabaseError(DatabaseOperationError):
    pass


class UpdateDatabaseError(DatabaseOperationError):
    pass


class ModuleOptionsError(ApiException):

    def __init__(self, options, module_name, error_code=HttpCodes.BAD_REQUEST):

        str_options = ""

        for o in options:
            str_options += f"{o} "
        msg = f'The following required options {str_options} are missing options for {module_name}'
        super().__init__(error_msg=msg, error_code=error_code)


def choose_http_error_code(error):
    """
    Returns the HTTP error code according to the error exception type.

    Args:
        error (Exception): an exception obj.

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


class TimeoutExpiredError(ApiException):

    def __init__(self, error_msg):
        self.msg = error_msg

    def __str__(self):
        return self.msg
