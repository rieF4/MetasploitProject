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
    SERVICE_UNAVAILABLE = 503


class ApiResponse(object):
    """
    This is a class to represent an API response.

    Attributes:
        response (dict/list/serializable object): a response from the database.
        http_status_code (int): the http status code of the response.
    """
    def __init__(self, response=None, http_status_code=HttpCodes.OK):

        self._response = response
        self._http_status_code = http_status_code

    @property
    def make_response(self):
        """
        Returns an API response for the client.

        Returns:
            Response: a flask response.
        """
        return make_response(jsonify(self.response), self.http_status_code)

    @property
    def response(self):
        return self._response

    @response.setter
    def response(self, res):
        self._response = res

    @property
    def http_status_code(self):
        return self._http_status_code


class ErrorResponse(ApiResponse):

    def __init__(self, error_msg, http_error_code, req=None, path=None):
        """
        Prepare an error response for a resource.

        Args:
            error_msg (str): error message to send.
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


def create_new_response(obj, response_type='Instance'):

    if response_type == 'Instance':
        return {
            "_id": obj.instance_id,
            "IpParameters": {
                "PublicIpAddress": obj.public_ip_address,
                "PublicDNSName": obj.public_dns_name,
                "PrivateIpAddress": obj.private_ip_address,
                "PrivateDNSName": obj.private_dns_name
            },
            "SecurityGroups": obj.security_groups,
            "State": obj.state,
            "Containers": [],
            "Images": [],
            "Metasploit": []
        }
    elif response_type == 'Container':
        obj.reload()
        return {
            "_id": obj.id,
            "image": obj.image.tags,
            "name": obj.name,
            "status": obj.status,
            "ports": obj.ports
        }
    elif response_type == 'Image':
        return {
            "_id": obj.id,
            "tags": obj.tags
        }
    elif response_type == 'User':
        return {
            "_id": obj.id,
            "firstName": obj.first_name,
            "lastName": obj.last_name,
            "email": obj.email
        }


def fill_user_document(user):

    return {
        "_id": user.id,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "username": user.username,
        "password": user.hashed_password,
    }
