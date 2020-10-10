

class ApiException(Exception):
    """
    A base class for all api exceptions.
    """
    pass


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


class SecurityGroupNotFoundError(ResourceNotFoundError):

    def __init__(self, type, id=None):
        super().__init__(type=type, id=id)


class InstanceNotFoundError(ResourceNotFoundError):
    def __init__(self, type, id=None):
        super().__init__(type=type, id=id)


class ContainerNotFoundError(ResourceNotFoundError):
    def __init__(self, type, id=None):
        super().__init__(type=type, id=id)


class ImageNotFoundError(ResourceNotFoundError):
    def __init__(self, type, id=None):
        super().__init__(type=type, id=id)


class VulnerabilityNotSupported(ApiException):
    def __init__(self, vulnerability_type):
        msg = f"Vulnerability {vulnerability_type} is not supported."
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