import boto3
import docker
from metasploit.venv.Aws import custom_exceptions


EC2 = 'ec2'


class AwsAccess:
    """
    This is a class for API calls to the AWS ec2 service per one user

    Attributes:
        client(put here the type of variable) - client for api calls to ec2
        resource(put here the type of variable) - resource for api calls to ec2

    Documentation:
        https://boto3.amazonaws.com/v1/documentation/api/latest/index.html
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#service-resource
    """

    aws_access_instance = None

    def __init__(self):
        if AwsAccess.aws_access_instance is not None:
            raise custom_exceptions.InitializeNewInstanceUsingConstructorException()
        self.client = boto3.client(EC2)
        self.resource = boto3.resource(EC2)
        self.session = boto3.Session()
        AwsAccess.aws_access_instance = self

    @staticmethod
    def get_aws_access_instance():
        if AwsAccess.aws_access_instance is None:
            AwsAccess()
        return AwsAccess.aws_access_instance

    # def get_credentials(self):
    #     """
    #     Get the aws access key and aws secret key for the user's session
    # 
    #     Returns:
    #         tuple(str, str) - The first argument is access key, the second one is secret key
    #     """
    #     credentials = self.session.get_credentials().get_frozen_credentials()
    #     
    #     return credentials.access_key, credentials.secret_key
    # 
    # def create_new_pair_key(self, kwargs):
    #     """
    #     Create new pair key for the user's session
    # 
    #     Args:
    #         kwargs(dict) - This is the API post request to AWS
    # 
    #     Examples:
    #         kwargs =
    #             KeyName='string',
    #             DryRun=True|False,
    #             TagSpecifications=[
    #             {
    #                 'ResourceType': 'client-vpn-endpoint'|'customer-gateway'
    #                 'Tags': [
    #                     {
    #                         'Key': 'string',
    #                         'Value': 'string'
    #                     },
    #                 ]
    #             },
    #         ]
    #     )
    #         response = client.create_key_pair(**kwargs)
    # 
    #     Returns:
    #         bool - True if successful, False otherwise
    #     """
    #     return True if self.client.create_key_pair(**kwargs) else False
    # 
    # def delete_key_pairs(self, kwargs):
    #     """
    #     Deletes the specified key pairs
    # 
    #     Args:
    #         kwargs(dict) - This is the API post request to AwsAccess
    # 
    #     Examples:
    #         kwargs =
    #                 KeyName='string',KeyPairId='string',DryRun=True|False
    # 
    #         response = client.delete_key_pair(**kwargs)
    # 
    #     Returns:
    #         True if successful, False otherwise
    #     """
    #     keys_pairs_names = self.get_pair_keys_names()
    #     for value in kwargs.values():
    #         if value not in keys_pairs_names:
    #             return False
    #     self.client.delete_key_pair(**kwargs)
    #     return True
    # 
    # def get_pair_keys_names(self):
    #     """
    #     Get all the available key pairs names available in aws
    # 
    #     Returns:
    #         list(str) - all the pair keys available for the user to authenticate the instance
    #     """
    #     keys_list = []
    #     for key in self.client.describe_key_pairs()['KeyPairs']:
    #         keys_list.append(key['KeyName'])
    #     return keys_list
    # 
    # def get_all_available_instances(self):
    #     """
    #     Get all available instances
    # 
    #     Returns:
    #         list(str) - a list of all instances ids
    #     """
    #     instances_ids = []
    #     response = self.client.describe_instances()
    #     for reservation in response["Reservations"]:
    #         for instance in reservation["Instances"]:
    #             instances_ids.append(instance["InstanceId"])
    #     return instances_ids
    # 
    # def get_chosen_state_of_instances(self, state="running"):
    #     """
    #     Get all the instances ids according to the requested state
    # 
    #     Args: state(str) - default is running state, state could be : "stopped", "pending", "terminated", "running"
    # 
    #     Returns:
    #         list(strings) - all instances ids according to requested state
    # 
    #     raises:
    #         AttributeError in case the requested state is not supported
    #     """
    # 
    #     available_states = ["stopped", "pending", "terminated", "running"]
    #     if state not in available_states:
    #         raise AttributeError(
    #             "AwsAccess Class - get_chosen_state_of_instances method - the wanted state is not part of available states"
    #         )
    #     instances_ids = []
    #     response = self.client.describe_instances()
    #     for reservation in response["Reservations"]:
    #         for instance in reservation["Instances"]:
    #             if instance["State"]["Name"] == state:
    #                 instances_ids.append(instance["InstanceId"])
    #     return instances_ids


class Image:
    """
    This class represents an image in the AWS ec2

    Attributes:
        image_obj (Image) - The object of the image
    """
    aws = AwsAccess.get_aws_access_instance()

    def __init__(self, image_id):
        """
        Creates a new Image object

        Args:
            image_id  (str) - The image id will be used to define the image object
        """
        self.image_obj = Image.aws.resource.Image(image_id)

    def get_id(self):
        return self.image_obj.image_id

    def get_type(self):
        return self.image_obj.image_type

    def get_state(self):
        return self.image_obj.state

    def reload(self):
        self.image_obj.reload()


class KeyPair:
    """
    This class represents a Key pair in AWS ec2

    Attributes:
        key_pair_obj (KeyPair) - The object of the key pair
    """
    aws = AwsAccess.get_aws_access_instance()

    def __init__(self, key_name):
        """
        Creates a new keyPair object

        Args:
            key_name (str) - The key pair will be created with the provided given name
        """
        self.key_pair_obj = KeyPair.aws.resource.KeyPair(key_name)

    def get_name(self):
        return self.key_pair_obj.key_name

    def get_id(self):
        return self.key_pair_obj.key_id

    def delete(self, kwargs):
        """
        Deletes the specified key pair, by removing the public key from Amazon EC2.

        Args:
            kwargs =
                KeyPairId='string',
                DryRun=True|False
        """
        self.key_pair_obj.delete(**kwargs)


class SecurityGroup:
    """
    This class represents a security group in AWS ec2

    Attributes:
        security_group_obj (SecurityGroup) - Object of the security group
    """
    aws = AwsAccess.get_aws_access_instance()

    def __init__(self, kwargs):
        """
            Creates a new security group in the user's session in ec2 AWS

            Args:
                kwargs(dict) - This is the API post request to create a security group in AWS

            Examples:
                kwargs =
                    Description='string',
                    GroupName='string',
                    VpcId='string',
                    TagSpecifications=[
                    {
                        'ResourceType': 'client-vpn-endpoint'|'customer-gateway'
                        'Tags': [
                            {
                                'Key': 'string',
                                'Value': 'string'
                            },
                        ]
                    },
                ],
                    DryRun=True|False
        """
        self.security_group_obj = SecurityGroup.aws.client.create_security_group(**kwargs)

    def get_group_id(self):
        return self.security_group_obj.group_id

    def get_group_name(self):
        return self.security_group_obj.group_name

    def reload(self):
        self.security_group_obj.reload()

    def modify(self, kwargs):
        """
        Modify the security group configuration

        Args:
            kwargs(dict) - This is the API post request to modify a security group in AWS

        Examples:
            kwargs =
                     DryRun=True|False,
                     IpPermissions=[
                {
                    'FromPort': 123,
                    'IpProtocol': 'string',
                    'IpRanges': [
                        {
                            'CidrIp': 'string',
                            'Description': 'string'
                        },
                    ],
                    'Ipv6Ranges': [
                        {
                            'CidrIpv6': 'string',
                            'Description': 'string'
                        },
                    ],
                    'PrefixListIds': [
                    {
                        'Description': 'string',
                        'PrefixListId': 'string'
                    },
                 ],
                'ToPort': 123,
                'UserIdGroupPairs': [
                    {
                        'Description': 'string',
                        'GroupId': 'string',
                        'GroupName': 'string',
                        'PeeringStatus': 'string',
                        'UserId': 'string',
                        'VpcId': 'string',
                        'VpcPeeringConnectionId': 'string'
                    },
                ]
            },
        ],
                    CidrIp='string',
                    FromPort=123,
                    IpProtocol='string',
                    ToPort=123,
                    SourceSecurityGroupName='string',
                    SourceSecurityGroupOwnerId='string'
        """
        self.security_group_obj.authorize_ingress(**kwargs)

    def delete(self, kwargs):
        """
        Deletes a security group in ec2 AWS

        Args:
            kwargs =
                GroupId='string',
                GroupName='string',
                DryRun=True|False
        """
        self.security_group_obj.delete(**kwargs)



dockerClient = docker.from_env()
client1 = docker.APIClient(base_url='tcp://3.131.82.175:2375')
client2 = docker.DockerClient(base_url='tcp://3.131.82.175:2375')
print()



