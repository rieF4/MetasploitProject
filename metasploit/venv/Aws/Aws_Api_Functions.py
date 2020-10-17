from metasploit.venv.Aws.Aws import (
    DockerServerInstance,
    aws_api
)


def get_security_group_object(id):
    """
    Returns the security group object by the ID.

    Args:
        id (str): security group ID.

    Returns:
        SecurityGroup: a security group object if found.
    """
    return aws_api.get_amazon_resource().SecurityGroup(id)


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
    return get_security_group_object(aws_api.get_client().create_security_group(**kwargs)['GroupId'])


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
    aws_instance = aws_api.get_amazon_resource().create_instances(**kwargs)[0]
    aws_instance.wait_until_running()
    aws_instance.reload()
    return DockerServerInstance(instance_obj=aws_instance, ssh_flag=True, init_docker_server_flag=True)


def get_docker_server_instance(id, ssh_flag=False):
    """
    Get the docker server instance object.

    Args:
        id (str): instance id.
        ssh_flag (bool): True if ssh connection needs to be deployed, False otherwise.

    Returns:
        DockerServerInstance: a docker server instance object if exits, None otherwise.
    """
    return DockerServerInstance(instance_obj=get_aws_instance(id=id), ssh_flag=ssh_flag)


def get_aws_instance(id):
    """
    Get the AWS instance object by its ID.

    Args:
        id (str): instance ID.

    Returns:
        Aws.Instance: an AWS instance object if found

    Raises:
        ClientError: in case there isn't an instance with the ID.
    """
    return aws_api.get_amazon_resource().Instance(id)


def update_security_group_inbound_permissions(security_group_id, req):
    """
    Updates the security group inbound in AWS.

    Args:
        security_group_id (id): security group ID.
        req (dict): the client api request.

    Returns:
        dict: updated security group permissions.
    """
    security_group_obj = get_security_group_object(id=security_group_id)
    security_group_obj.authorize_ingress(**req)
    security_group_obj.reload()
    return security_group_obj.ip_permissions
