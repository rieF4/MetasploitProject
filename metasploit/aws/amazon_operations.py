

from .amazon_docker_server import (
    DockerServerInstance
)
from .aws_access import (
    aws_api
)


class AmazonObjectOperations(object):
    def __init__(self, amazon_resource_id):
        self._amazon_resource_id = amazon_resource_id

    @property
    def amazon_resource_id(self):
        return self._amazon_resource_id


class SecurityGroupOperations(AmazonObjectOperations):

    @property
    def security_group_object(self):
        """
        Returns the security group object by the security group ID.

        Returns:
            SecurityGroup: a security group object if found.
        """
        return aws_api.resource.SecurityGroup(self.amazon_resource_id)

    def update_security_group_inbound_permissions(self, req):
        """
        Updates the security group inbound in AWS.

        Args:
            req (dict): the client api request.

        Returns:
            dict: updated security group permissions.
        """
        security_group_obj = self.security_group_object
        security_group_obj.authorize_ingress(**req)
        security_group_obj.reload()
        return security_group_obj.ip_permissions


class DockerServerInstanceOperations(AmazonObjectOperations):

    @property
    def aws_instance_object(self):
        """
        Get the AWS instance object by its ID.

        Returns:
            Aws.Instance: an AWS instance object if found

        Raises:
            ClientError: in case there isn't an instance with the ID.
        """
        return aws_api.resource.Instance(self.amazon_resource_id)

    def get_docker_server_instance(self, ssh_flag=False):
        """
        Get the docker server instance object.

        Args:
            ssh_flag (bool): True if ssh connection needs to be deployed, False otherwise.

        Returns:
            DockerServerInstance: a docker server instance object if exits, None otherwise.
        """
        return DockerServerInstance(instance_obj=self.aws_instance_object, ssh_flag=ssh_flag)


def create_security_group(kwargs):
    """
    Creates a new security group in ec2 AWS.

        Args:
            kwargs(dict) - This is the API post request to create a security group in AWS.

        Examples:
            kwargs =
                Description='string',
                GroupName='string',
                VpcId='string',
                TagSpecifications=[
                {
                    'ResourceType': '_client-vpn-endpoint'|'customer-gateway'
                    'Tags': [
                        {
                            'Key': 'string',
                            'Value': 'string'
                        },
                    ]
                },
            ],
                DryRun=True|False

        Returns:
            SecurityGroup: a security group object if created.

        Raises:
            ParamValidationError: in case kwargs params are not valid to create a new security group.
            ClientError: in case there is a duplicate security group that exits with the same name.
    """
    return SecurityGroupOperations(
        amazon_resource_id=aws_api.client.create_security_group(**kwargs)['GroupId']
    ).security_group_object


def create_instance(kwargs):
    """
    Args:
        kwargs (dict) - The API post request to create the instance.

        Examples:
            kwargs =
            ImageId='ami-0bdcc6c05dec346bf',
            InstanceType='t2.micro',
            MaxCount=1,
            MinCount=1,
            KeyName='MyFirstInstance'
            SecurityGroupIds=['group_id']

        instance = self._resource.create_instances(**kwargs)
        The get API call is an instance object

    Returns:
        DockerServerInstance: docker server instance object if successful
    Raises:
        ParamValidationError: in case kwargs params are not valid to create a new instance.
    """
    aws_instance = aws_api.resource.create_instances(**kwargs)[0]
    aws_instance.wait_until_running()
    aws_instance.reload()
    return DockerServerInstance(instance_obj=aws_instance, ssh_flag=True, init_docker_server_flag=True)
