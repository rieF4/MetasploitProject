from pymongo import MongoClient
from metasploit.venv.Aws import Constants
from metasploit.venv.Aws.ServerExceptions import (
    ResourceNotFoundError,
    DeleteDatabaseError,
    InsertDatabaseError,
)

db_client = MongoClient(
    'mongodb+srv://Metasploit:FVDxbg312@metasploit.gdvxn.mongodb.net/metasploit?retryWrites=true&w=majority'
)
metasploit_db = db_client['Metasploit']


class DatabaseCollections:
    INSTANCES = metasploit_db['instances']
    SECURITY_GROUPS = metasploit_db['securityGroups']


class DataBaseManager(object):
    """
    Class to manage all database operations.

    Attributes:
        collection_type (pymongo.Collection): the collection to use in the DB.
        document (dict): the document to use all DB operations.
    """
    def __init__(self, collection_type, **kwargs):

        self._collection_type = collection_type
        self._resource_id = kwargs.get("resource_id", "")

        if self._resource_id:
            self._document = self.find_document(
                collection_name=kwargs.get("collection_name", Constants.INSTANCES),
                single_document=kwargs.get("single_document", True),
                type=kwargs.get("type", Constants.INSTANCE)
            )
        else:
            self._document = {}

    def find_document(self, collection_name=Constants.INSTANCES, single_document=True, type=Constants.INSTANCE):
        """
        Finds a document in the database, and return a parsed dict response of the document if it was found.

        Args:
            collection_name (str): the collection name. etc: SecurityGroups, Instances
            single_document (bool): indicate if the search should be on a single document.
            type (str): what type of document it is. etc. Instances, Instance, SecurityGroup

        Returns:
            dict: the result from database if it was found.

        Raises:
            ResourceNotFoundError: in case the resource was not found in the DB.
        """
        if single_document:
            database_result = self._collection_type.find_one(filter={Constants.ID: self._resource_id})
            self._document = database_result
            if database_result:
                return database_result
            else:
                raise ResourceNotFoundError(type=type, id=self._resource_id)
        else:
            parsed_response = {collection_name: []}
            database_result = self._collection_type.find(self._document)
            for result in database_result:
                parsed_response[collection_name].append(result)
            if parsed_response[collection_name]:
                return parsed_response
            else:
                raise ResourceNotFoundError(type=type)

    def delete_document(self):
        """
        Deletes a single document from DB.

        Raises:
            DeleteDatabaseError: in case delete operation failed in the DB.
        """
        try:
            self._collection_type.delete_one(filter=self._document)
        except Exception as error:
            raise DeleteDatabaseError(document=self._document, error_msg=error.__str__())

    def insert_document(self):
        """
        Inserts a document into the DB.

        Raises:
            InsertDatabaseError: in case insertion to the DB fails.
        """
        try:
            self._collection_type.insert_one(document=self._document)
        except Exception as error:
            raise InsertDatabaseError(document=self._document, error_msg=error.__str__())

    def update_document(self, updated_document):
        """
        Updates a document in the DB
        """
        self.delete_document()
        self._document = updated_document
        self.insert_document()

    @property
    def document(self):
        return self._document

    @document.setter
    def document(self, document):
        if isinstance(document, dict):
            self._document = document
        else:
            raise AttributeError(f"{document} is not a dict type")


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


def insert_document(collection_type, document):
    try:
        collection_type.insert_one(document=document)
        return True
    except Exception as e:
        print("failed inserting element to DB")
        print(e)
        return False


def update_instance_document_in_database(instance_id, instance_response):
    if delete_documents(collection_type=DatabaseCollections.INSTANCES, document={Constants.ID: instance_id}):
        if insert_document(collection_type=DatabaseCollections.INSTANCES, document=instance_response):
            return True
        else:
            return False
    else:
        return False
