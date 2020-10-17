from flask import jsonify
from flask import make_response


class HttpCodes(object):
    OK = 200
    CREATED = 201
    ACCEPTED = 202
    NO_CONTENT = 204
    MULTI_STATUS = 207
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    METHOD_NOT_ALLOWED = 405
    DUPLICATE = 409
    INTERNAL_SERVER_ERROR = 500


class ApiResponse(object):
    """
    This is a class to represent an API response.

    Attributes:
        response (dict): a response from the database.
        http_status_code (int): the http status code of the response.
    """
    def __init__(self, api_manager=None, response=None, http_status_code=HttpCodes.OK):

        self._api_manager = api_manager
        self._response = response
        self._http_status_code = http_status_code

    @property
    def make_response(self):
        return make_response(jsonify(self.response), self.http_status_code)

    @property
    def api_manager(self):
        return self._api_manager

    @property
    def response(self):
        return self._response

    @property
    def http_status_code(self):
        return self._http_status_code


class ResourceResponse(ApiResponse):

    def __init__(self, api_manager, response, http_status_code, docker_amazon_object=None):
        super(ResourceResponse, self).__init__(
            api_manager=api_manager, response=response, http_status_code=http_status_code
        )
        self._docker_amazon_object = docker_amazon_object

    @property
    def docker_amazon_object(self):
        return self._docker_amazon_object


class SecurityGroupResponse(ResourceResponse):

    def __init__(self, api_manager, http_status_code, security_group, response):
        super(SecurityGroupResponse, self).__init__(
            api_manager=api_manager,
            response=self._prepare_security_group_response if security_group else response,
            http_status_code=http_status_code,
            docker_amazon_object=security_group
        )

    @property
    def _prepare_security_group_response(self):
        """
        Create a security group parsed response for the client.

        Returns:
            dict: a parsed security group response.
        """
        return {
            "_id": self.docker_amazon_object.group_id,
            "Description": self.docker_amazon_object.description,
            "Name": self.docker_amazon_object.group_name,
            "IpPermissionsInbound": self.docker_amazon_object.ip_permissions,
            "IpPermissionsOutbound": self.docker_amazon_object.ip_permissions_egress
        }


class DockerInstanceResponse(ResourceResponse):

    def __init__(self, api_manager, http_status_code, docker_server, response):
        super(DockerInstanceResponse, self).__init__(
            api_manager=api_manager,
            response=self._prepare_instance_response if docker_server else response,
            http_status_code=http_status_code,
            docker_amazon_object=docker_server
        )

    @property
    def _prepare_instance_response(self):
        """
        Prepare a create instance parsed response for the client.

        Returns:
            dict: a parsed instance response.
        """
        return {
            "_id": self.docker_amazon_object.instance_id,
            "IpParameters": {
                "PublicIpAddress": self.docker_amazon_object.public_ip_address,
                "PublicDNSName": self.docker_amazon_object.public_dns_name,
                "PrivateIpAddress": self.docker_amazon_object.private_ip_address,
                "PrivateDNSName": self.docker_amazon_object.private_dns_name
            },
            "SecurityGroups": self.docker_amazon_object.security_groups,
            "State": self.docker_amazon_object.state,
            "KeyName": self.docker_amazon_object.key_name,
            "Docker": {
                "Containers": [],
                "Images": [],
                "Networks": []
            },
        }


class ContainerResponse(ResourceResponse):

    def __init__(self, api_manager, http_status_code, container, response):
        super(ContainerResponse, self).__init__(
            api_manager=api_manager,
            response=self._prepare_container_response if container else response,
            http_status_code=http_status_code,
            docker_amazon_object=container
        )

    @property
    def _prepare_container_response(self):
        """
        Prepare a create container parsed response for the client.

        Returns:
            dict: a parsed instance response.
        """
        self.docker_amazon_object.reload()

        return {
            "_id": self.docker_amazon_object.id,
            "image": self.docker_amazon_object.image.tags,
            "name": self.docker_amazon_object.name,
            "status": self.docker_amazon_object.status,
            "ports": self.docker_amazon_object.ports
        }


class ImageResponse(ResourceResponse):

    def __init__(self, api_manager, http_status_code, image, response):
        super(ImageResponse, self).__init__(
            api_manager=api_manager,
            response=self._prepare_image_response if image else response,
            http_status_code=http_status_code,
            docker_amazon_object=image
        )

    @property
    def _prepare_image_response(self):
        """
        Prepare an image parsed response for the client.

        Returns:
            dict: a parsed instance response.
        """
        return {
            "_id": self.docker_amazon_object.id,
            "tags": self.docker_amazon_object.tags
        }


class NetworkResponse(ResourceResponse):

    def __init__(self, api_manager, http_status_code, network, response):
        super(NetworkResponse, self).__init__(
            api_manager=api_manager,
            response=self._prepare_network_response if network else response,
            http_status_code=http_status_code,
            docker_amazon_object=network
        )

    def _prepare_network_response(self):
        """
        Prepare a network parsed response for the client
        """
        self.docker_amazon_object.reload()

        return {
            "_id": self.docker_amazon_object.id,
            "name": self.docker_amazon_object.name,
            "containers": [container.id for container in self.docker_amazon_object.containers]
        }


class ErrorResponse(ApiResponse):

    def __init__(self, api_manager, error_msg, http_error_code, req=None, path=None):
        """
        Prepare an error response for a resource.
        Args:
            error_msg (str): error message to send.
            http_error_code (int): the http error code.
            req (dict): the request by the client.
            path (str): The path in the api the error occurred.
            api_manager (ApiManager): api manager object.

        Returns:
            dict: parsed error response for the client.
        """
        response = {
            "Error":
                {
                    "Message": error_msg,
                    "Code": http_error_code,
                    "Request": req,
                    "Url": path
                }
        }
        super(ErrorResponse, self).__init__(
            api_manager=api_manager, response=response, http_status_code=http_error_code
        )
