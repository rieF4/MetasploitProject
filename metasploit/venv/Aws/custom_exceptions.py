

class CommandFailureException(Exception):
    """
    This class represents an error exception for executing a command over an aws instance

    Attributes:
         cmd (str) - the command that was executed over the instance
         instance_id (str) - the instance id that this command was executed on
    """
    def __init__(self, cmd, instance_id):
        self.msg = f"The following command {cmd} has failed over the instance {instance_id}!"
        super().__init__(self.msg)


class InitializeNewInstanceUsingConstructorException(Exception):
    """
    This class represents an error exception for creating a new instance over aws
    """

    def __init__(self):
        self.msg = "Cannot init the instance using constructor, please use AwsAccess.get_aws_access_instance() method"
        super().__init__(self.msg)
