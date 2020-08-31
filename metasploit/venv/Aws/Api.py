from metasploit.venv.Aws import Aws
from metasploit.venv.Aws import config
from flask import Flask
from flask import jsonify
from pymongo import MongoClient
from flask_restful import Api, Resource, reqparse, abort, marshal_with


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


def update_document(fields, collection_type, id):
    """
    update a document in the database.

    Args:
        fields (dict): a dictionary form of what to update.
        collection_type (pymongo.Collection): the collection that the update should be on.
        id (str): the id of the document to be updated.

        field parameter example:
            {
            "IpPermissionsInbound": security_group_obj.ip_permissions
            }
    """
    try:
        collection_type.update_one({"_id": id}, {"$set": fields})
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
        "url": path,
        "IpPermissionsInbound": security_group_obj.ip_permissions, # means permissions to connect to the instance
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
        "Path": path
    }


@app.route('/Instances/Create', methods=['POST'])
def create_instance():

    request = create_instance_parser()
    request['MaxCount'] = 1
    request['MinCount'] = 1

    instance = Aws.create_instance(kwargs=request)
    if instance:
        instance_response = prepare_instance_response(instance_obj=instance, path=reqparse.request.base_url)
        instances_db_collection.insert_one(document=instance_response)
        return jsonify(instance_response)
    else:
        abort(409, message="Unable to create a new instance.")


@app.route('/SecurityGroups/Create', methods=['POST'])
def create_security_group():
    request = create_security_group_parser()

    security_group_id = Aws.create_security_group(kwargs=request)

    if security_group_id:
        security_group_response = prepare_security_group_response(id=security_group_id, path=reqparse.request.base_url)
        security_group_db_collection.insert_one(document=security_group_response)
        return jsonify(security_group_response)
    else:
        abort(409, message="Unable to create a new security group.")


@app.route('/SecurityGroups/Get', methods=['GET'])
def get_security_groups():
    """
    Get all the security groups available in the database.

    Returns:
        dict: a json representation of the security groups response.
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
        security_group_db_collection.delete_one(filter=security_group)
        return jsonify({}), 204  # means success
    else:
        return jsonify({}), 202


@app.route('/SecurityGroups/Update/<id>', methods=['PATCH'])
def modify_security_group(id):
    """
    Modify a security group InboundPermissions.

    Args:
        id (str): the id of the security group.

    Returns:
        Jsonify: a jsonify object parsed as a dictionary to the client.
    """
    request = modify_security_group_parser()
    err_msg = f"unable to update security group {id}"
    find_documents(request={"_id": id}, collection_type=security_group_db_collection)

    if Aws.modify_security_group(security_group_id=id, kwargs=request):
        ip_permissions = Aws.aws_api.get_resource().SecurityGroup(id).ip_permissions
        if update_document(
            fields={"IpPermissionsInbound": ip_permissions},
            collection_type=security_group_db_collection,
            id=id
        ):
            return jsonify(find_documents(request={"_id": id}, collection_type=security_group_db_collection))
        else:
            print("Failed on updated in database")
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


def create_instance_parser():
    create_instance_args = reqparse.RequestParser()
    create_instance_args.add_argument(
        "ImageId",
        type=str,
        help="The image ID of the instance. this is required.",
        required=True
    )
    create_instance_args.add_argument(
        "InstanceType",
        type=str,
        help="The processor type of the instance. this is required.",
        required=True
    )
    create_instance_args.add_argument(
        "KeyName",
        type=str,
        help="A key pair that this instance will be initiated with. this is required.",
        required=True
    )
    create_instance_args.add_argument(
        "SecurityGroupIds",
        type=list,
        help="The security group IDs for the instance to be initiated with. this is required.",
        required=True
    )
    return create_instance_args.parse_args()


def modify_security_group_parser():
    modify_security_group_args = reqparse.RequestParser()
    modify_security_group_args.add_argument(
        "IpProtocol",
        type=str,
        help="The protocol to add to the security group. this is required",
        required=True
    )
    modify_security_group_args.add_argument(
        "FromPort",
        type=int,
        help="From which port to open the connection. this is required",
        required=True
    )
    modify_security_group_args.add_argument(
        "ToPort",
        type=int,
        help="To which port to open the connection. this is required",
        required=True
    )
    modify_security_group_args.add_argument(
        "CidrIp",
        type=str,
        help="From which ip it can be accessed. this is required",
        required=True
    )
    return modify_security_group_args.parse_args()


def create_security_group_parser():
    create_security_group_args = reqparse.RequestParser()
    create_security_group_args.add_argument(
        "Description",
        type=str,
        help="The description for the security group. this is required",
        required=True
    )
    create_security_group_args.add_argument(
        "GroupName",
        type=str,
        help="The group name for the security group. this is required",
        required=True
    )
    return create_security_group_args.parse_args()


def create_instances_parser():
    create_instance_args = reqparse.RequestParser()
    create_instance_args.add_argument(
        "ImageID",
        type=str,
        help="Image ID that the instance will be created with. for example: 'ami-016b213e65284e9c9', this is required",
        required=True
    )
    create_instance_args.add_argument(
        "Type",
        type=str,
        help="The type of cpu for the instance. for example t2.micro. This is required",
        required=True
    )
    create_instance_args.add_argument(
        "KeyName",
        type=str,
        help="The key name that will be used for the instance. This is required",
        required=True
    )
    create_instance_args.add_argument(
        "SecurityGroupID",
        type=str,
        help="The security group ID for the instance. This is required",
        required=True
    )
    return create_instance_args.parse_args()


if __name__ == "__main__":
    app.run(debug=True)