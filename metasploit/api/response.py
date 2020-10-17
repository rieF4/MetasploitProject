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
    def __init__(self, response={}, http_status_code=HttpCodes.OK):
        self._response = response if response else ''
        self._http_status_code = http_status_code

    @property
    def make_response(self):
        return make_response(jsonify(self.response), self.http_status_code)

    @property
    def response(self):
        return self._response

    @property
    def http_status_code(self):
        return self._http_status_code


class ResourceResponse(ApiResponse):

    def __init__(self, response, http_status_code, docker_amazon_object):
        super(ResourceResponse, self).__init__(response=response, http_status_code=http_status_code)
        self._docker_amazon_object = docker_amazon_object

    @property
    def docker_amazon_object(self):
        return self._docker_amazon_object


class SecurityGroupResponse(ResourceResponse):

    @property
    def prepare_security_group_response(self):
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

    @property
    def prepare_instance_response(self):
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

    @property
    def prepare_container_response(self):
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

    @property
    def prepare_image_response(self):
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

    def prepare_network_response(self):
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

    def __init__(self, error_msg, http_error_code, req=None, path=None):
        """
        Prepare an error response for a resource.
        Args:
            msg (str): error message to send.
            http_error_code (int): the http error code.
            req (dict): the request by the client.
            path (str): The path in the api the error occurred.

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
        super(ErrorResponse, self).__init__(response=response, http_status_code=http_error_code)


# class PrepareResponse(object):
#
#     @staticmethod
#     def prepare_container_response(container):
#         """
#         Prepare a create container parsed response for the client.
#
#         Args:
#
#         Returns:
#             dict: a parsed instance response.
#         """
#         container.reload()
#
#         return {
#             "_id": container.id,
#             "image": container.image.tags,
#             "name": container.name,
#             "status": container.status,
#             "ports": container.ports
#         }
#
#     @staticmethod
#     def prepare_instance_response(docker_server):
#         """
#         Prepare a create instance parsed response for the client.
#
#         Returns:
#             dict: a parsed instance response.
#         """
#         return {
#             "_id": docker_server.get_instance_id(),
#             "IpParameters": {
#                 "PublicIpAddress": docker_server.get_public_ip_address(),
#                 "PublicDNSName": docker_server.get_public_dns_name(),
#                 "PrivateIpAddress": docker_server.get_private_ip_address(),
#                 "PrivateDNSName": docker_server.get_private_dns_name()
#             },
#             "SecurityGroups": docker_server.get_security_groups(),
#             "State": docker_server.get_state(),
#             "KeyName": docker_server.get_key_name(),
#             "Docker": {
#                 "Containers": [],
#                 "Images": [],
#                 "Networks": []
#             },
#         }
#
#     @staticmethod
#     def prepare_security_group_response(security_group_obj):
#         """
#         Create a security group parsed response for the client.
#
#         Args:
#             security_group_obj (SecurityGroup): security group object.
#             path (str): the api path to the newly created security group
#
#         Returns:
#             dict: a parsed security group response.
#         """
#         return {
#             "_id": security_group_obj.group_id,
#             "Description": security_group_obj.description,
#             "Name": security_group_obj.group_name,
#             "IpPermissionsInbound": security_group_obj.ip_permissions,  # means permissions to connect to the instance
#             "IpPermissionsOutbound": security_group_obj.ip_permissions_egress
#         }
#
#     @staticmethod
#     def prepare_error_response(msg, http_error_code, req=None, path=None):
#         """
#         Prepare an error response for a resource.
#
#         Args:
#             msg (str): error message to send.
#             http_error_code (int): the http error code.
#             req (dict): the request by the client.
#             path (str): The path in the api the error occurred.
#
#         Returns:
#             dict: parsed error response for the client.
#         """
#         return {
#             "Error":
#                 {
#                     "Message": msg,
#                     "Code": http_error_code,
#                     "Request": req,
#                     "Url": path
#                 }
#         }
#
#     @staticmethod
#     def prepare_image_response(image):
#         """
#         Prepare an image parsed response for the client.
#
#         Args:
#             image (Image): an image object.
#
#         Returns:
#             dict: a parsed instance response.
#         """
#         return {
#             "_id": image.id,
#             "tags": image.tags
#         }
#
#     @staticmethod
#     def prepare_network_response(network_obj):
#         """
#         Prepare a network parsed response for the client
#         """
#         network_obj.reload()
#
#         return {
#             "_id": network_obj.id,
#             "name": network_obj.name,
#             "containers": [container.id for container in network_obj.containers]
#         }
#
#
# def make_error_response(msg, http_error_code, req=None, path=None):
#     """
#     Make error response for the client.
#
#     Args:
#         msg (str): error message to send.
#         http_error_code (int): the http error code.
#         req (dict): the request by the client.
#         path (str): The path in the api the error occurred.
#
#     Returns:
#         tuple (Json, int): (error, error_status_code) for the client.
#     """
#     return jsonify(
#         PrepareResponse.prepare_error_response(
#             msg=msg, http_error_code=http_error_code, req=req, path=path
#         )
#     ), http_error_code