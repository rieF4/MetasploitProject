from metasploit.venv.Aws import Aws
from flask import Flask, Response
from flask import jsonify
from pymongo import MongoClient
from flask_restful import Api, abort, request


app = Flask(__name__)
api = Api(app=app)

db_client = MongoClient(
    'mongodb+srv://Metasploit:FVDxbg312@metasploit.gdvxn.mongodb.net/metasploit?retryWrites=true&w=majority'
)
metasploit_db = db_client['Metasploit']

ID = "_id"

class DatabaseCollections:
    INSTANCES = metasploit_db['instances']
    SECURITY_GROUPS = metasploit_db['securityGroups']
    KEY_PAIRS = metasploit_db['keyPairs']


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
        Standard method that effectively perform the stored function of this endpoint.

        Args:
            args (list): Arguments to give to the stored function.
            kwargs (dict): Keyword arguments.

        Returns:
            Jsonify: A jsonify response of the requested action.
        """
        # Perform the function
        answer = self.function(*args, **kwargs)

        # Create the answer (bundle it in a correctly formatted HTTP answer)
        if isinstance(answer, str):
            # If it's a string, we bundle it has a HTML-like answer
            self.response = Response(answer, status=200, headers={})
        else:
            # If it's something else (dict, ..) we jsonify and send it
            self.response = jsonify(answer)

        return self.response


class FlaskAppWrapper(object):
    """
    This is a class to wrap flask program and to create its endpoints to functions.

    Attributes:
        self._api (FlaskApi) - the api of flask.
    """
    app = Flask(__name__)

    def __init__(self):
        self._api = Api(app=app)

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


class SecurityGroupsApi(object):
    
    @staticmethod
    def get_security_groups():
        """
        Get all the security groups available in the database.

        Returns:
            Json: a json representation of the security groups response.
        """
        return find_documents(
            request={},  # means bring everything in the collection
            collection_type=DatabaseCollections.SECURITY_GROUPS,
            collection_name="SecurityGroups",
            single_document=False
        )
    
    @staticmethod
    def get_specific_security_group(id):
        return find_documents(request={ID: id}, collection_type=DatabaseCollections.SECURITY_GROUPS)
    
    @staticmethod
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
            Json: a json representation of a security group response.
        """
        security_groups_requests = request.json
        security_groups_response = {}
        for index, req in enumerate(security_groups_requests.values(), 1):
            security_group_id = Aws.create_security_group(kwargs=req)

            if security_group_id:
                security_group_database = prepare_security_group_response(
                    id=security_group_id, path=request.base_url
                )
                DatabaseCollections.SECURITY_GROUPS.insert_one(document=security_group_database)
                security_groups_response[index] = security_group_database
            else:
                abort(409, message=f"Unable to create a new security group with the following params: {req}")

        return security_groups_response
    
    @staticmethod
    def delete_specific_security_group(id):
        security_group = find_documents(request={ID: id}, collection_type=DatabaseCollections.SECURITY_GROUPS)
        if Aws.delete_security_group(security_group_id=id):
            if delete_documents(
                    collection_type=DatabaseCollections.SECURITY_GROUPS, document=security_group, single_document=True
            ):
                return {}, 204  # means success
        else:
            return {}, 202
    
    @staticmethod
    def modify_security_group_inbound_permissions(id):
        """
        Modify a security group InboundPermissions.

        Args:
            id (str): the id of the security group.

        Returns:
            Json: a json object parsed as a dictionary to the client.
        """
        inbound_permissions_update_request = request.json
        err_msg = f"unable to update security group {id}"
        find_documents(request={ID: id}, collection_type=DatabaseCollections.SECURITY_GROUPS)

        if Aws.modify_security_group(security_group_id=id, kwargs=inbound_permissions_update_request):
            ip_permissions = Aws.aws_api.get_resource().SecurityGroup(id).ip_permissions
            if update_document(
                    fields={"IpPermissionsInbound": ip_permissions},
                    collection_type=DatabaseCollections.SECURITY_GROUPS,
                    operation="$set",
                    id=id
            ):
                return find_documents(request={ID: id}, collection_type=DatabaseCollections.SECURITY_GROUPS)
            else:
                abort(409, message=err_msg)
        else:
            abort(409, message=err_msg)


class InstancesApi(object):
    
    @staticmethod
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
            Json: a json representation of a create instances response.
        """
        create_instances_requests = request.json
        create_instances_response = {}

        for index, req in enumerate(create_instances_requests.values(), 1):

            instance = Aws.create_instance(kwargs=req)

            if instance:
                instance_response = prepare_instance_response(instance_obj=instance, path=request.base_url)
                DatabaseCollections.INSTANCES.insert_one(document=instance_response)
                create_instances_response[index] = instance_response
            else:
                abort(409, message=f"Unable to create a new instance with the following params {req}")

        return create_instances_response
    
    @staticmethod
    def get_all_instances():
        """
        Get all the instances available at the server.

        Returns:
             dict: a json representation of the instances response.
        """
        return find_documents(
            request={},  # means bring everything in the collection
            collection_type=DatabaseCollections.INSTANCES,
            collection_name="Instances",
            single_document=False
        )
    
    @staticmethod
    def get_specific_instance(id):
        return find_documents(request={ID: id}, collection_type=DatabaseCollections.INSTANCES)
    
    @staticmethod
    def delete_instance(id):
        instance_document = find_documents(request={ID: id}, collection_type=DatabaseCollections.INSTANCES)
        instance_obj = Aws.InstanceCollection.get(instance_id=id)
        print(Aws.InstanceCollection.list())
        if instance_obj:
            instance_obj.terminate()
            if Aws.InstanceCollection.remove(instance_id=id) and delete_documents(
                    collection_type=DatabaseCollections.INSTANCES, query=instance_document
            ):
                return {}, 204  # means success
            else:
                return 202
        else:
            return 202


class ContainersApi(object):
    
    @staticmethod
    def create_containers(id):
        create_containers_requests = request.json
        instance_obj = Aws.InstanceCollection.get(instance_id=id)

        create_containers_response = {"Containers": []}

        if instance_obj:
            for image, req in create_containers_requests.items():
                container_obj = Aws.create_container(
                    instance_id=instance_obj, image=image,
                    kwargs=req, command=req.pop('Command', None)
                )
                if container_obj:
                    if find_documents(request={ID: id}, collection_type=DatabaseCollections.INSTANCES):
                        container_response = create_container_response(container_obj=container_obj)
                        if update_document(
                                fields={
                                    "Docker": {
                                        "Containers": container_response
                                    }
                                },
                                collection_type=DatabaseCollections.INSTANCES,
                                operation="$push",
                                id=id
                        ):
                            create_containers_response["Containers"].append(container_response)
                    else:
                        return {"massege": f"could not update container {container_obj.id} in the database"}
                else:
                    return {"massege": "could not create new container"}
            return create_containers_response
        else:
            return {"massege": f"could not find instance with ID {id}"}
        
    @staticmethod
    def get_all_instance_containers(id):
        instance_response = find_documents(
            request={ID: id}, collection_type=DatabaseCollections.INSTANCES)
        return instance_response["Docker"]["Containers"]
    
    @staticmethod
    def get_instance_container(instance_id, container_id):

        instance_response = find_documents(request={ID: instance_id}, collection_type=DatabaseCollections.INSTANCES)

        for cont_resp in instance_response["Docker"]["Containers"]:
            if container_id == cont_resp["id"]:
                return cont_resp
        return jsonify(409, message=f"Container with id {container_id} does not exist")
        

def find_documents(request, collection_type, collection_name="", single_document=True):
    """
    Find a document in the database, and return a parsed dict response of the document if it was found.

    Args:
        request (dict): The request that was made by the client.
        collection_type (pymongo.Collection): the collection that the request should be searched on.
        collection_name (str): the collection name. etc: SecurityGroupsApi, Instances, KeyPair
        single_document (bool): indicate if the search should be on a single document.

    Returns:
        dict: the result from database if it was found, otherwise raises an error.
    """
    if single_document:
        database_result = collection_type.find_one(request)
        return database_result if database_result else abort(409)
    else:
        parsed_response = {collection_name: []}
        database_result = collection_type.find(request)
        for result in database_result:
            parsed_response[collection_name].append(result)
        if parsed_response[collection_name]:
            return parsed_response
        else:
            abort(409)


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


def prepare_security_group_response(id, path):
    """
    Create a security group parsed response for the client.

    Args:
        id (str): the id of the security group.
        path (str) the api path to the newly created security group

    Returns:
        dict: a parsed security group response.
    """
    security_group_obj = Aws.aws_api.get_resource().SecurityGroup(id)

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
        instance_obj (Instance): an instance object that was created.
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


def create_container_response(container_obj):
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
            '/Instance/<id>/CreateContainers',
            'ContainersApi.create_containers',
            ContainersApi.create_containers,
            [HttpMethods.POST]
        ),
        (
            '/Instance/<id>/Get/Containers',
            'ContainersApi.get_all_instance_containers',
            ContainersApi.get_all_instance_containers,
            [HttpMethods.GET]
        ),
        (
            '/Instance/<instance_id>/Get/Container/<container_id>',
            'ContainersApi.get_instance_container',
            ContainersApi.get_instance_container,
            [HttpMethods.GET]
        )
    )
    flask_wrapper.run()