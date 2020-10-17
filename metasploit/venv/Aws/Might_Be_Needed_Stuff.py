


    # def get_credentials(self):
    #     """
    #     Get the aws access key and aws secret key for the user's _session
    #
    #     Returns:
    #         tuple(str, str) - The first argument is access key, the second one is secret key
    #     """
    #     credentials = self._session.get_credentials().get_frozen_credentials()
    #
    #     return credentials.access_key, credentials.secret_key
    #
    # def create_new_pair_key(self, kwargs):
    #     """
    #     Create new pair key for the user's _session
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
    #                 'ResourceType': '_client-vpn-endpoint'|'customer-gateway'
    #                 'Tags': [
    #                     {
    #                         'Key': 'string',
    #                         'Value': 'string'
    #                     },
    #                 ]
    #             },
    #         ]
    #     )
    #         response = _client.create_key_pair(**kwargs)
    #
    #     Returns:
    #         bool - True if successful, False otherwise
    #     """
    #     return True if self._client.create_key_pair(**kwargs) else False
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
    #         response = _client.delete_key_pair(**kwargs)
    #
    #     Returns:
    #         True if successful, False otherwise
    #     """
    #     keys_pairs_names = self.get_pair_keys_names()
    #     for value in kwargs.values1():
    #         if value not in keys_pairs_names:
    #             return False
    #     self._client.delete_key_pair(**kwargs)
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
    #     for key in self._client.describe_key_pairs()['KeyPairs']:
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
    #     response = self._client.describe_instances()
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
    #     response = self._client.describe_instances()
    #     for reservation in response["Reservations"]:
    #         for instance in reservation["Instances"]:
    #             if instance["State"]["Name"] == state:
    #                 instances_ids.append(instance["InstanceId"])
    #     return instances_ids



# class KeyPair:
#     """
#     This class represents a Key pair in AWS ec2
#
#     Attributes:
#         key_pair_obj (KeyPair) - The object of the key pair
#     """
#     aws = AwsAccess.get_aws_access_instance()
#
#     def __init__(self, key_name):
#         """
#         Creates a new keyPair object
#
#         Args:
#             key_name (str) - The key pair will be created with the provided given name
#         """
#         self.key_pair_obj = KeyPair.aws.resource.KeyPair(key_name)
#
#     def get_name(self):
#         return self.key_pair_obj.key_name
#
#     def get_id(self):
#         return self.key_pair_obj.key_id
#
#     def delete(self, kwargs):
#         """
#         Deletes the specified key pair, by removing the public key from Amazon EC2.
#
#         Args:
#             kwargs =
#                 KeyPairId='string',
#                 DryRun=True|False
#         """
#         self.key_pair_obj.delete(**kwargs)


# def create_new_key_pair(key_name):
#     """
#     Creates a new keyPair object.
#
#     Args:
#         key_name (str) - The key pair will be created with the provided given name.
#
#     Returns:
#         KeyPair: a key pair object in AWS.
#     """
#     try:
#         return aws_api.get_amazon_resource().KeyPair(key_name)
#     except Exception:
#         return None