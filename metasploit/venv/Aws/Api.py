from metasploit.venv.Aws import Aws
from flask import Flask
from flask import jsonify
from pymongo import MongoClient
from flask_restful import Api, abort, request
from botocore.exceptions import ClientError, ParamValidationError
from werkzeug.exceptions import BadRequest
from metasploit.venv.Aws.custom_exceptions import (
    ResourceNotFoundError,
    SecurityGroupNotFoundError,
    InstanceNotFoundError
)


db_client = MongoClient(
    'mongodb+srv://Metasploit:FVDxbg312@metasploit.gdvxn.mongodb.net/metasploit?retryWrites=true&w=majority'
)
metasploit_db = db_client['Metasploit']

ID = "_id"
CONTAINERS = "Containers"
DOCKER = "Docker"
PUSH = "$push"
SET = "$set"
INSTANCES = "Instances"
INSTANCE = "Instance"
SECURITY_GROUPS = "SecurityGroups"
SECURITY_GROUP = "SecurityGroup"


class DatabaseCollections:
    INSTANCES = metasploit_db['instances']
    INSTANCES_OBJECTS = metasploit_db['instancesObjects']
    SECURITY_GROUPS = metasploit_db['securityGroups']
    KEY_PAIRS = metasploit_db['keyPairs']


class HttpCodes:
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


class HttpMethods:
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    DELETE = 'DELETE'
    PATCH = 'PATCH'


class EndpointAction(object):
    """
    Defines an Endpoint for a specific function for any client.

    Attributes:
        function (Function): the function that the endpoint will be forwarded to.
    """

    def __init__(self, function):
        """
        Create the endpoint by specifying which action we want the endpoint to perform, at each call.
        function (Function): The function to execute on endpoint call.
        """
        self.function = function

    def __call__(self, *args, **kwargs):
        """
        Standard method that effectively perform the stored function of its endpoint.

        Args:
            args (list): Arguments to give to the stored function.
            kwargs (dict): Keyword arguments.

        Returns:
           tuple (Json, int): an API response to the client.
        """
        # Perform the function
        return self.function(*args, **kwargs)


class FlaskAppWrapper(object):
    """
    This is a class to wrap flask program and to create its endpoints to functions.

    Attributes:
        self._api (FlaskApi) - the api of flask.
    """
    app = Flask(__name__)

    def __init__(self):
        self._api = Api(app=FlaskAppWrapper.app)

    def get_app(self):
        """
        Get flask app.
        """
        return self.app

    def get_api(self):
        """
        Get flask API.
        """
        return self._api

    def run(self):
        """
        Run flask app.
        """
        self.app.run(debug=True)

    def add_endpoints(self, *add_url_rules_params):
        """
        add url rules to class methods.

        Args:
             add_url_rules_params (list(tuple(str, str, Function, list(str)))):
             a list of 4-tuple to add_url_rule function.

        Examples:
             add_url_rules_params = [
            (
                '/SecurityGroupsApi/Get',
                'SecurityGroup.get_security_groups',
                SecurityGroup.get_security_groups,
                [HttpMethods.GET]
            ),
            (
                '/Instances/Create',
                'Instances.create_instances',
                Instances.create_instances,
                [HttpMethods.POST]
            )
        ]
        """
        for url_rule, endpoint_name, func, methods in add_url_rules_params:
            try:
                self.app.add_url_rule(
                    rule=url_rule, endpoint=endpoint_name, view_func=EndpointAction(func), methods=methods
                )
            except Exception as e:
                print(e)


def validate_request_type():
    """
    Validate the client request type (dict).

    Returns:
        tuple(bool, str): a tuple that indicates if the request type is ok. (True, 'Success') for a valid request type,
        otherwise, (False, err)

    Raises:
         BadRequest:
         TypeError:
         AttributeError:
    """
    try:
        req = request.json
        if not isinstance(req, dict):
            return False, "Request type is not a dictionary form."
        return True, 'Success'
    except (BadRequest, TypeError, AttributeError) as err:
        return False, err.__str__()


def request_error_validation(api_function):
    def wrapper(*args, **kwargs):

        if request.method not in [HttpMethods.GET, HttpMethods.DELETE]:
            type_validation, msg = validate_request_type()

            if not type_validation:
                return make_error_response(msg=msg, http_error_code=HttpCodes.BAD_REQUEST)
        try:
            api_response = api_function(*args, **kwargs)
        except ResourceNotFoundError as err:
            return make_error_response(
                msg=err.__str__(), http_error_code=HttpCodes.NOT_FOUND, req=request.json, path=request.base_url
            )

        return make_response(api_response=api_response)

    return wrapper


def make_error_response(msg, http_error_code, req=None, path=None):
    """
    Make error response for the client.

    Args:
        msg (str): error message to send.
        http_error_code (int): the http error code.
        req (dict): the request by the client.
        path (str): The path in the api the error occurred.

    Returns:
        tuple (Json, int): (error, error_status_code) for the client.
    """
    return jsonify(
        prepare_error_response(
            msg=msg.__str__(), http_error_code=http_error_code, req=req, path=path
        )
    ), http_error_code


def make_response(api_response):
    """
    Returns a json and http status code to the client.

    Args:
        (ApiResponse): api response object.

    Returns:
        tuple (Json, int): a (response, status_code) for the client.
    """
    resp = api_response.get_response()
    http_status_code = api_response.get_http_status_code()

    if resp:
        return jsonify(resp), http_status_code
    return jsonify(''), http_status_code


class ApiResponse(object):
    """
    This is a class to represent an API response.

    Attributes:
        response (dict): a response from the database.
        http_status_code (int): the http status code of the response.
        error (dict): error response if needed.
    """
    def __init__(self, response={}, http_status_code=200, error={}):
        self._response = response
        self._http_status_code = http_status_code
        self._error = error

    def get_response(self):
        return self._response

    def get_http_status_code(self):
        return self._http_status_code

    def get_error(self):
        return self._error


class CollectionApi(object):
    """
    Base class for all the collection API classes
    """
    pass


class SecurityGroupsApi(CollectionApi):

    @staticmethod
    @request_error_validation
    def get_security_groups():
        """
        Get all the security groups available in the database.

        Returns:
            ApiResponse: an api response object.

         Raises:
            SecurityGroupNotFoundError: in case there is not a security groups.
        """
        security_groups = find_documents(
            document={},  # means bring everything in the collection
            collection_type=DatabaseCollections.SECURITY_GROUPS,
            collection_name=SECURITY_GROUPS,
            single_document=False
        )

        if security_groups:
            return ApiResponse(response=security_groups, http_status_code=HttpCodes.OK)
        else:
            raise SecurityGroupNotFoundError(type=SECURITY_GROUPS)

    @staticmethod
    @request_error_validation
    def get_specific_security_group(id):
        """
        Get specific security group by ID.

        Args:
            id (str): security group ID.

        Returns:
            ApiResponse: an api response object.

        Raises:
            SecurityGroupNotFoundError: in case there is not a security group with the ID.
        """
        security_group = find_documents(document={ID: id}, collection_type=DatabaseCollections.SECURITY_GROUPS)
        if security_group:
            return ApiResponse(response=security_group, http_status_code=HttpCodes.OK)
        else:
            raise SecurityGroupNotFoundError(type=SECURITY_GROUP, id=id)

    @staticmethod
    @request_error_validation
    def create_security_groups():
        """
        Create dynamic amount of security groups.

        Example of a request:

        {
            "1": {
                "Description": "Metasploit project security group",
                "GroupName": "MetasploitSecurityGroup"
            },
            "2": {
                "Description": "Metasploit project security group1",
                "GroupName": "MetasploitSecurityGroup1"
            }
        }

        Returns:
            ApiResponse: an api response object.

        Raises:
            ParamValidationError: in case the parameters by the client to create security groups are not valid.
            ClientError: in case there is a duplicate resource that is already exits.
        """

        security_groups_requests = request.json
        security_groups_response = {}

        is_valid = False
        is_error = False
        http_status_code = HttpCodes.CREATED

        for key, req in security_groups_requests.items():
            try:
                security_group_obj = Aws.create_security_group(kwargs=req)

                security_group_database = prepare_security_group_response(
                    security_group_obj=security_group_obj, path=request.base_url
                )
                DatabaseCollections.SECURITY_GROUPS.insert_one(document=security_group_database)
                security_groups_response[key] = security_group_database

                is_valid = True
            except (ParamValidationError, ClientError) as err:

                http_status_code = HttpCodes.DUPLICATE if isinstance(err, ClientError) else HttpCodes.BAD_REQUEST

                security_groups_response[key] = prepare_error_response(
                    msg=err.__str__(), http_error_code=http_status_code, req=req
                )

                is_error = True

        if is_valid and is_error:
            http_status_code = HttpCodes.MULTI_STATUS
        return ApiResponse(response=security_groups_response, http_status_code=http_status_code)

    @staticmethod
    @request_error_validation
    def delete_specific_security_group(id):
        """
        Deletes a security group by id.

        Args:
            id (str): security group id.

        Returns:
            ApiResponse: an api response object.

        Raises:
            SecurityGroupNotFoundError: in case there is not a security group with the ID.
        """
        security_group = find_documents(document={ID: id}, collection_type=DatabaseCollections.SECURITY_GROUPS)

        if security_group:
            Aws.get_security_group_object(id=id).delete()
            if delete_documents(collection_type=DatabaseCollections.SECURITY_GROUPS, document=security_group):
                return ApiResponse(http_status_code=HttpCodes.NO_CONTENT)
        else:
            raise SecurityGroupNotFoundError(type=SECURITY_GROUP, id=id)

    @staticmethod
    @request_error_validation
    def modify_security_group_inbound_permissions(id):
        """
        Modify a security group InboundPermissions.

        Examples of a request:
        {
            "1": {
                "IpProtocol": "tcp",
                "FromPort": 2375,
                "ToPort": 2375,
                "CidrIp": "0.0.0.0/0"
            },
            "2": {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "CidrIp": "0.0.0.0/0"
            }
        }

        Args:
            id (str): the id of the security group.

        Returns:
            ApiResponse: an api response object.

        Raises:
            SecurityGroupNotFoundError: in case there is not a security group with the ID.
        """
        inbound_permissions_update_request = request.json
        inbound_permissions_update_response = {}
        document = {ID: id}

        security_group_response = find_documents(document=document, collection_type=DatabaseCollections.SECURITY_GROUPS)

        if security_group_response:
            security_group_obj = Aws.get_security_group_object(id=id)

            for key, req in inbound_permissions_update_request.items():
                try:
                    security_group_obj.authorize_ingress(**req)
                    security_group_obj.reload()
                    ip_permissions = security_group_obj.ip_permissions

                    if update_document(
                        fields={"IpPermissionsInbound": ip_permissions},
                        collection_type=DatabaseCollections.SECURITY_GROUPS,
                        operation=SET,
                        id=id
                    ):
                        security_group_response = find_documents(
                            document=document, collection_type=DatabaseCollections.SECURITY_GROUPS
                        )

                        inbound_permissions_update_response[key] = security_group_response
                except ClientError as err:
                    http_status_code = HttpCodes.DUPLICATE

                    inbound_permissions_update_response[key] = prepare_error_response(
                        msg=err.__str__(), http_error_code=http_status_code, req=req
                    )

            return ApiResponse(response=security_group_response, http_status_code=HttpCodes.OK)
        else:
            raise SecurityGroupNotFoundError(type=SECURITY_GROUP, id=id)


class InstancesApi(CollectionApi):

    @staticmethod
    @request_error_validation
    def create_instances():
        """
        Create a dynamic amount of instances over AWS.

        Example of a request:

        {
            "1": {
            "ImageId": "ami-016b213e65284e9c9",
            "InstanceType": "t2.micro",
            "KeyName": "default_key_pair_name",
            "SecurityGroupIds": ["sg-08604b8d820a35de6"],
            "MaxCount": 1,
            "MinCount": 1
            },
            "2": {
            "ImageId": "ami-016b213e65284e9c9",
            "InstanceType": "t2.micro",
            "KeyName": "default_key_pair_name",
            "SecurityGroupIds": ["sg-08604b8d820a35de6"],
            "MaxCount": 1,
            "MinCount": 1
            }
        }

        Returns:
            ApiResponse: an api response object.

        Raises:
            ParamValidationError: in case the parameters by the client to create instances are not valid.
        """
        create_instances_requests = request.json
        create_instances_response = {}

        is_valid = False
        is_error = False
        http_status_code = HttpCodes.OK

        for key, req in create_instances_requests.items():
            try:
                instance_obj = Aws.create_instance(kwargs=req)

                instance_response = prepare_instance_response(instance_obj=instance_obj, path=request.base_url)
                DatabaseCollections.INSTANCES.insert_one(document=instance_response)
                create_instances_response[key] = instance_response

                is_valid = True
            except ParamValidationError as err:
                http_status_code = HttpCodes.BAD_REQUEST

                create_instances_response[key] = prepare_error_response(
                    msg=err.__str__(), http_error_code=http_status_code, req=req
                )

                is_error = True
        if is_valid and is_error:
            http_status_code = HttpCodes.MULTI_STATUS
        return ApiResponse(response=create_instances_response, http_status_code=http_status_code)

    @staticmethod
    @request_error_validation
    def get_all_instances():
        """
        Get all the instances available at the server.

        Returns:
            ApiResponse: an api response object.

        Raises:
            InstanceNotFoundError: in case there are not instances.
        """
        instances_response = find_documents(
            document={},  # means bring everything in the collection
            collection_type=DatabaseCollections.INSTANCES,
            collection_name=INSTANCES,
            single_document=False
        )

        if instances_response:
            return ApiResponse(response=instances_response, http_status_code=HttpCodes.OK)
        else:
            raise InstanceNotFoundError(type=INSTANCES)

    @staticmethod
    @request_error_validation
    def get_specific_instance(id):
        """
        Get a specific instance by ID.

        Args:
            id (str): instance id.

        Returns:
            ApiResponse: an api response object.

        Raises:
            InstanceNotFoundError: in case there is not an instance with the ID.
        """
        instance_response = find_documents(document={ID: id}, collection_type=DatabaseCollections.INSTANCES)
        if instance_response:
            return ApiResponse(response=instance_response, http_status_code=HttpCodes.OK)
        else:
            raise InstanceNotFoundError(type=INSTANCES, id=id)

    @staticmethod
    @request_error_validation
    def delete_instance(id):
        """
        Delete a specific instance by ID.

        Args:
            id (str): instance id.

        Returns:
            ApiResponse: an api response object.

        Raises:
            InstanceNotFoundError: in case there is not an instance with the ID.

        """
        instance_document = find_documents(document={ID: id}, collection_type=DatabaseCollections.INSTANCES)
        if instance_document:
            Aws.get_aws_instance_object(id=id).terminate()
            if delete_documents(collection_type=DatabaseCollections.INSTANCES, document=instance_document):
                return ApiResponse(http_status_code=HttpCodes.NO_CONTENT)
        else:
            raise InstanceNotFoundError(type=INSTANCE, id=id)


class ContainersApi(CollectionApi):

    @staticmethod
    def create_containers(id):
        """
        Create containers by instance ID. Containers will be created over the instance with the specified ID.

        Args:
            id (str): instance ID.

        Returns:
            dict: a create containers response.
        """
        create_containers_requests = request.json
        docker_server_instance = Aws.get_docker_server_instance_object(id=id)

        create_containers_response = {CONTAINERS: []}

        if docker_server_instance:
            for image, req in create_containers_requests.items():
                container_obj = Aws.create_container(
                    instance=docker_server_instance, image=image,
                    kwargs=req, command=req.pop('Command', None)
                )
                if container_obj:
                    if find_documents(document={ID: id}, collection_type=DatabaseCollections.INSTANCES):
                        container_response = prepare_container_response(container_obj=container_obj)
                        if update_document(
                                fields={
                                    DOCKER: {
                                        CONTAINERS: container_response
                                    }
                                },
                                collection_type=DatabaseCollections.INSTANCES,
                                operation=PUSH,
                                id=id
                        ):
                            create_containers_response[CONTAINERS].append(container_response)
                    else:
                        return {"massege": f"could not update container {container_obj.id} in the database"}
                else:
                    return {"massege": "could not create new container"}
            return create_containers_response
        else:
            return {"massege": f"could not find instance with ID {id}"}

    @staticmethod
    def get_all_instance_containers(id):
        """
        Get all the containers of a specific instance.

        Args:
            id (str): instance ID.

        Returns:
            dict: a containers response, empty dict otherwise.
        """
        return {
            CONTAINERS: find_documents(
                document={ID: id}, collection_type=DatabaseCollections.INSTANCES, collection_name=CONTAINERS
            )[DOCKER][CONTAINERS]
        }

    @staticmethod
    def get_instance_container(instance_id, container_id):
        """
        Get a container by instance and container IDs

        Args:
            instance_id (str): instance ID.
            container_id (str): container ID.

        Returns:
            dict: container response if found, empty dict otherwise.
        """

        instance_response = find_documents(document={ID: instance_id}, collection_type=DatabaseCollections.INSTANCES)

        for cont_resp in instance_response[DOCKER][CONTAINERS]:
            if container_id == cont_resp["id"]:
                return cont_resp
        return {}

    @staticmethod
    def get_all_instances_containers():
        """
        Get all the containers of all the instances

        Returns:
            dict: all containers responses if there are any, empty dict otherwise.
        """
        instances_documents = find_documents(
            document={},
            collection_type=DatabaseCollections.INSTANCES,
            collection_name=INSTANCES,
            single_document=False
        )

        all_containers_response = {}

        for ins_doc in instances_documents[INSTANCES]:
            all_containers_response[ins_doc[ID]] = {CONTAINERS: []}
            for container_doc in ins_doc[DOCKER][CONTAINERS]:
                all_containers_response[ins_doc[ID]][CONTAINERS].append(container_doc)

        return all_containers_response


def find_documents(document, collection_type, collection_name="", single_document=True):
    """
    Find a document in the database, and return a parsed dict response of the document if it was found.

    Args:
        document (dict): The document to search for.
        collection_type (pymongo.Collection): the collection that the request should be searched on.
        collection_name (str): the collection name. etc: SecurityGroups, Instances, KeyPair
        single_document (bool): indicate if the search should be on a single document.

    Returns:
        dict: the result from database if it was found, otherwise empty dict.
    """
    if single_document:
        database_result = collection_type.find_one(filter=document)
        return database_result if database_result else {}
    else:
        parsed_response = {collection_name: []}
        database_result = collection_type.find(document)
        for result in database_result:
            parsed_response[collection_name].append(result)
        if parsed_response[collection_name]:
            return parsed_response
        else:
            return {}


def update_document(fields, collection_type, operation, id):
    """
    update a document in the database.

    Args:
        fields (dict): a dictionary form of what to update.
        collection_type (pymongo.Collection): the collection that the update should be on.
        operation (str): the database operation that should be used. ("$set", "$push")
        id (str): the id of the document to be updated.

        fields parameter examples:
        {
            "IpPermissionsInbound": security_group_obj.ip_permissions
        }
        means update the IpInboundPermissions To a new ip permissions


        {
         "Docker": {
            "Containers": container_response
            }
        }
        means update the Containers over an instance

    Returns:
        True if database update was successful, False otherwise.
    """
    try:
        collection_type.update_one({ID: id}, {operation: fields})
        return True
    except Exception as e:
        print(e)
        return False


def delete_documents(collection_type, document={}, single_document=True):
    """
    Deletes a single or multiple documents from a chosen collection.

    Args:
        collection_type (pymongo.Collection): The collection that should be deleted from.
        document (dict): the document from the database that should be deleted.
        single_document (bool): indicate if the deletion should be on a single document.

    Returns:
        True if deletion from database was completed successfully, False otherwise.
    """
    try:
        if single_document:
            collection_type.delete_one(filter=document)
        else:
            collection_type.delete_many(filter=document)  # means delete all of them
        return True
    except Exception as e:
        print(e)
        return False


def prepare_error_response(msg, http_error_code, req=None, path=None):
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
    return {
        "Error":
            {
                "Message": msg,
                "Code": http_error_code,
                "Request": req,
                "Url": path
            }
    }


def prepare_security_group_response(security_group_obj, path):
    """
    Create a security group parsed response for the client.

    Args:
        security_group_obj (SecurityGroup): security group object.
        path (str): the api path to the newly created security group

    Returns:
        dict: a parsed security group response.
    """
    return {
        "_id": security_group_obj.group_id,
        "Description": security_group_obj.description,
        "Name": security_group_obj.group_name,
        "Url": path.replace("Create", security_group_obj.group_id),
        "IpPermissionsInbound": security_group_obj.ip_permissions,  # means permissions to connect to the instance
        "IpPermissionsOutbound": security_group_obj.ip_permissions_egress
    }


def prepare_instance_response(instance_obj, path):
    """
    Prepare a create instance parsed response for the client.

    Args:
        instance_obj (DockerServerInstance): an instance object that was created.
        path (str): the api path to the newly created instance.

    Returns:
        dict: a parsed instance response.
    """
    return {
        "_id": instance_obj.get_instance_id(),
        "IpParameters": {
            "PublicIpAddress": instance_obj.get_public_ip_address(),
            "PublicDNSName": instance_obj.get_public_dns_name(),
            "PrivateIpAddress": instance_obj.get_private_ip_address(),
            "PrivateDNSName": instance_obj.get_private_dns_name()
        },
        "SecurityGroups": instance_obj.get_security_groups(),
        "State": instance_obj.get_state(),
        "KeyName": instance_obj.get_key_name(),
        "Docker": {
            "Containers": [],
            "Images": [],
            "Networks": []
        },
        "Url": path.replace("Create", instance_obj.get_instance_id())
    }


def prepare_container_response(container_obj):
    """
    Prepare a create container parsed response for the client.

    Args:
        container_obj (Container): a container object.

    Returns:
        dict: a parsed instance response.
    """
    return {
        "id": container_obj.id,
        "image": container_obj.image,
        "name": container_obj.name,
        "status": container_obj.status
    }


# @app.route('/keyPairs/Create', methods=['POST'])
# def create_key_pair():
#     return


# @app.route('/keyPairs/Get/<id>', methods=['GET'])
# def get_specific_key_pair(id):
#     key_pair = find_documents(
#         request={"_id": id}, collection_type=key_pair_db_collection, collection_name="KeyPair"
#     )
# 
#     return jsonify(key_pair)
# 
# 
# 
# @app.route('/keyPairs/Get', methods=['GET'])
# def get_all_key_pairs():
#     """
#     Get all the key pairs from the server.
# 
#     Returns:
#         dict: a json representation of the key pairs response.
#     """
#     key_pairs = find_documents(
#         request={},  # means bring everything in the collection
#         collection_type=key_pair_db_collection,
#         collection_name="KeyPairs",
#         single_document=False
#     )
# 
#     return jsonify(key_pairs)


if __name__ == "__main__":
    flask_wrapper = FlaskAppWrapper()
    flask_wrapper.add_endpoints(
        (
            '/SecurityGroups/Get',
            'SecurityGroupsApi.get_security_groups',
            SecurityGroupsApi.get_security_groups,
            [HttpMethods.GET]
        ),
        (
            '/SecurityGroups/Get/<id>',
            'SecurityGroupsApi.get_specific_security_group',
            SecurityGroupsApi.get_specific_security_group,
            [HttpMethods.GET]
        ),
        (
            '/SecurityGroups/Create',
            'SecurityGroupsApi.create_security_groups',
            SecurityGroupsApi.create_security_groups,
            [HttpMethods.POST]
        ),
        (
            '/SecurityGroups/Delete/<id>',
            'SecurityGroupsApi.delete_specific_security_group',
            SecurityGroupsApi.delete_specific_security_group,
            [HttpMethods.DELETE]
        ),
        (
            '/SecurityGroups/<id>/UpdateInboundPermissions',
            'SecurityGroupsApi.modify_security_group_inbound_permissions',
            SecurityGroupsApi.modify_security_group_inbound_permissions,
            [HttpMethods.PATCH]
        ),
        (
            '/Instances/Create',
            'InstancesApi.create_instances',
            InstancesApi.create_instances,
            [HttpMethods.POST]
        ),
        (
            '/Instances/Get',
            'InstancesApi.get_all_instances',
            InstancesApi.get_all_instances,
            [HttpMethods.GET]
        ),
        (
            '/Instances/Get/<id>',
            'InstancesApi.get_specific_instance',
            InstancesApi.get_specific_instance,
            [HttpMethods.GET]
        ),
        (
            '/Instances/Delete/<id>',
            'InstancesApi.delete_instance',
            InstancesApi.delete_instance,
            [HttpMethods.DELETE]
        ),
        (
            '/DockerServerInstance/<id>/CreateContainers',
            'ContainersApi.create_containers',
            ContainersApi.create_containers,
            [HttpMethods.POST]
        ),
        (
            '/DockerServerInstance/<id>/Get/Containers',
            'ContainersApi.get_all_instance_containers',
            ContainersApi.get_all_instance_containers,
            [HttpMethods.GET]
        ),
        (
            '/DockerServerInstance/<instance_id>/Get/Container/<container_id>',
            'ContainersApi.get_instance_container',
            ContainersApi.get_instance_container,
            [HttpMethods.GET]
        ),
        (
            '/DockerServerInstances/Get/Containers',
            'ContainersApi.get_all_instances_containers',
            ContainersApi.get_all_instances_containers,
            [HttpMethods.GET]
        )
    )
    flask_wrapper.run()
