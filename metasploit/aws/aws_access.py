import boto3
import functools

EC2 = 'ec2'


def singleton(cls):
    """
    Make a class a Singleton class (only one instance)
    """
    @functools.wraps(cls)
    def wrapper_singleton(*args, **kwargs):
        if not wrapper_singleton.instance:
            wrapper_singleton.instance = cls(*args, **kwargs)
        return wrapper_singleton.instance
    wrapper_singleton.instance = None
    return wrapper_singleton


@singleton
class AwsAccess(object):
    """
    This is a class for API calls to the AWS ec2 service.

    Attributes:
        _client(put here the type of variable) - client for api calls to ec2
        _resource(put here the type of variable) - resource for api calls to ec2

    Documentation:
        https://boto3.amazonaws.com/v1/documentation/api/latest/index.html
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#service-resource
    """

    def __init__(self):
        self._client = boto3.client(EC2)
        self._resource = boto3.resource(EC2)
        self._session = boto3.Session()

    @property
    def client(self):
        return self._client

    @property
    def resource(self):
        return self._resource

    @property
    def session(self):
        return self._session


aws_api = AwsAccess()
