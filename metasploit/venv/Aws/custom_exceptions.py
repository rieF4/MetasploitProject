from botocore.exceptions import ClientError


class CommandFailureException(Exception):
    """
    This class represents an error exception for executing a command over an aws instance

    Attributes:
         cmd (str) - the command that was executed over the instance
         instance_id (str) - the instance id that this command was executed on
    """
    def __init__(self, cmd, instance_id):
        msg = f"The following command {cmd} has failed over the instance {instance_id}!"
        super().__init__(self.msg)


class InitializeNewInstanceUsingConstructorException(Exception):
    """
    This class represents an error exception for creating a new instance over aws
    """

    def __init__(self):
        msg = "Cannot init the instance using constructor, please use AwsAccess.get_aws_access_instance() method"
        super().__init__(msg)


class ResourceNotFoundError(Exception):
    """
    This class represents an exception for a resource that was not found in the DB.
    """

    def __init__(self, type, id=None):
        msg = ""
        if id:
            msg = f"{type} with ID {id} was not found"
        else:
            msg = f"{type} were not found."
        super().__init__(msg)


class SecurityGroupNotFoundError(ResourceNotFoundError):

    def __init__(self, type, id=None):
        super().__init__(type=type, id=id)


class InstanceNotFoundError(ResourceNotFoundError):
    def __init__(self, type, id=None):
        super().__init__(type=type, id=id)


class DuplicateResourceError(ClientError):
    def __init__(self, error_response={}, operation_name=""):
        super().__init__(error_response=error_response, operation_name=operation_name)
