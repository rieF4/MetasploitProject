from pymongo import MongoClient
from metasploit.venv.Aws import Constants

db_client = MongoClient(
    'mongodb+srv://Metasploit:FVDxbg312@metasploit.gdvxn.mongodb.net/metasploit?retryWrites=true&w=majority'
)
metasploit_db = db_client['Metasploit']


class DatabaseCollections:
    INSTANCES = metasploit_db['instances']
    SECURITY_GROUPS = metasploit_db['securityGroups']
    KEY_PAIRS = metasploit_db['keyPairs']


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
        collection_type.update_one({Constants.ID: id}, {operation: fields})
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