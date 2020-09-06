from metasploit.venv.Aws import Aws
from metasploit.venv.Aws import config
from flask import Flask
from flask import jsonify
from pymongo import MongoClient
from flask_restful import Api, Resource, reqparse, abort, marshal_with, request


app = Flask(__name__)
api = Api(app=app)

db_client = MongoClient(
    'mongodb+srv://Metasploit:FVDxbg312@metasploit.gdvxn.mongodb.net/metasploit?retryWrites=true&w=majority'
)

metasploit_db = db_client['Metasploit']
instances_db_collection = metasploit_db['instances']
security_group_db_collection = metasploit_db['security_group']
key_pair_db_collection = metasploit_db['key_pair']


def find_documents(request, collection_type, collection_name="", single_document=True):
    """
    Find a document in the database, and return a parsed dict response of the document if it was found.

    Args:
        request (dict): The request that was made by the client.
        collection_type (pymongo.Collection): the collection that the request should be searched on.
        collection_name (str): the collection name. etc: SecurityGroups, Instances, KeyPair
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
        collection_type.update_one({"_id": id}, {operation: fields})
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


@app.route('/Instances/Create', methods=['POST'])
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
            instance_response = prepare_instance_response(instance_obj=instance, path=reqparse.request.base_url)
            instances_db_collection.insert_one(document=instance_response)
            create_instances_response[index] = instance_response
        else:
            abort(409, message=f"Unable to create a new instance with the following params {req}")

    return jsonify(create_instances_response)


@app.route('/Instances/Get', methods=['GET'])
def get_all_instances():
    """
    Get all the instances available at the server.

    Returns:
         dict: a json representation of the instances response.
    """
    instances = find_documents(
        request={},  # means bring everything in the collection
        collection_type=instances_db_collection,
        collection_name="Instances",
        single_document=False
    )

    return jsonify(instances)


@app.route('/Instances/Get/<id>', methods=['GET'])
def get_specific_instance(id):

    instance = find_documents(request={"_id": id}, collection_type=instances_db_collection)
    return jsonify(instance)


@app.route('/Instances/Delete/<id>', methods=['DELETE'])
def delete_instance(id):
    instance_document = find_documents(request={"_id":id}, collection_type=instances_db_collection)
    instance_obj = Aws.InstanceCollection.get(instance_id=id)
    if instance_obj:
        instance_obj.terminate()
        if Aws.InstanceCollection.remove(instance_id=id) and delete_documents(
                collection_type=instances_db_collection, query=instance_document
        ):
            return jsonify({}), 204  # means success
        else:
            return 202
    else:
        return 202


@app.route('/Instance/<id>/CreateContainers', methods=['POST'])
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
                if find_documents(request={"_id": id}, collection_type=instances_db_collection):
                    container_response = create_container_response(container_obj=container_obj)
                    if update_document(
                            fields={
                                "Docker": {
                                    "Containers": container_response
                                }
                            },
                            collection_type=instances_db_collection,
                            operation="$push",
                            id=id
                    ):
                        create_containers_response["Containers"].append(container_response)
                else:
                    return jsonify({"massege": f"could not update container {container_obj.id} in the database"})
            else:
                return jsonify({"massege": "could not create new container"})
        return jsonify(create_containers_response)
    else:
        return jsonify({"massege": f"could not find instance with ID {id}"})


@app.route('/Instance/<id>/Get/Containers', methods=['GET'])
def get_all_instance_containers(id):
    instance_response = find_documents(
        request={"_id": id}, collection_type=instances_db_collection)
    return jsonify(instance_response["Docker"]["Containers"])


@app.route('/Instance/<instance_id>/Get/Container/<container_id', methods=['GET'])
def get_instance_container(instance_id, container_id):

    instance_response = find_documents(request={"_id": instance_id}, collection_type=instances_db_collection)

    for cont_resp in instance_response["Docker"]["Containers"]:
        if container_id == cont_resp["id"]:
            return jsonify(cont_resp)
    return jsonify(409, message=f"Container with id {container_id} does not exist")


@app.route('/SecurityGroups/Create', methods=['POST'])
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
            security_group_database = prepare_security_group_response(id=security_group_id, path=reqparse.request.base_url)
            security_group_db_collection.insert_one(document=security_group_database)
            security_groups_response[index] = security_group_database
        else:
            abort(409, message=f"Unable to create a new security group with the following params: {req}")

    return jsonify(security_groups_response)


@app.route('/SecurityGroups/Get', methods=['GET'])
def get_security_groups():
    """
    Get all the security groups available in the database.

    Returns:
        Json: a json representation of the security groups response.
    """
    security_groups = find_documents(
        request={},  # means bring everything in the collection
        collection_type=security_group_db_collection,
        collection_name="SecurityGroups",
        single_document=False
    )

    return jsonify(security_groups)


@app.route('/SecurityGroups/Get/<id>', methods=['GET'])
def get_specific_security_group(id):

    security_group = find_documents(request={"_id": id}, collection_type=security_group_db_collection)
    return jsonify(security_group)


@app.route('/SecurityGroups/Delete/<id>', methods=['DELETE'])
def delete_specific_security_group(id):

    security_group = find_documents(request={"_id": id}, collection_type=security_group_db_collection)
    if Aws.delete_security_group(security_group_id=id):
        if delete_documents(
                collection_type=security_group_db_collection, document=security_group, single_document=True
        ):
            return jsonify({}), 204  # means success
    else:
        return jsonify({}), 202


@app.route('/SecurityGroups/<id>/UpdateInboundPermissions', methods=['PATCH'])
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
    find_documents(request={"_id": id}, collection_type=security_group_db_collection)

    if Aws.modify_security_group(security_group_id=id, kwargs=inbound_permissions_update_request):
        ip_permissions = Aws.aws_api.get_resource().SecurityGroup(id).ip_permissions
        if update_document(
            fields={"IpPermissionsInbound": ip_permissions},
            collection_type=security_group_db_collection,
            operation="$set",
            id=id
        ):
            return jsonify(find_documents(request={"_id": id}, collection_type=security_group_db_collection))
        else:
            abort(409, message=err_msg)
    else:
        abort(409, message=err_msg)


# @app.route('/keyPairs/Create', methods=['POST'])
# def create_key_pair():
#     return


@app.route('/keyPairs/Get/<id>', methods=['GET'])
def get_specific_key_pair(id):
    key_pair = find_documents(
        request={"_id": id}, collection_type=key_pair_db_collection, collection_name="KeyPair"
    )

    return jsonify(key_pair)



@app.route('/keyPairs/Get', methods=['GET'])
def get_all_key_pairs():
    """
    Get all the key pairs from the server.

    Returns:
        dict: a json representation of the key pairs response.
    """
    key_pairs = find_documents(
        request={},  # means bring everything in the collection
        collection_type=key_pair_db_collection,
        collection_name="KeyPairs",
        single_document=False
    )

    return jsonify(key_pairs)


if __name__ == "__main__":
    app.run(debug=True)