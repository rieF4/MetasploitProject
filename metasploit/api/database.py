from pymongo import MongoClient

from metasploit.api import constants as global_constants
from metasploit.api.errors import (
    DeleteDatabaseError,
    InsertDatabaseError,
    AmazonResourceNotFoundError,
    DockerResourceNotFoundError,
    UpdateDatabaseError,
    DuplicateUserNameError,
    UserNotFoundError
)

db_client = MongoClient(
    'mongodb+srv://Metasploit:FVDxbg312@metasploit.gdvxn.mongodb.net/metasploit?retryWrites=true&w=majority'
)
metasploit_db = db_client['Metasploit']


class DatabaseCollections:
    INSTANCES = metasploit_db['instances']
    SECURITY_GROUPS = metasploit_db['securityGroups']
    USERS = metasploit_db['users']


class DatabaseOperations(object):
    """
    Class to manage all database operations.

    Attributes:
        collection_type (pymongo.Collection): the collection to use in the DB.
    """
    def __init__(self, collection_type):
        """
        Initialize the DatabaseOperations class attributes.

        Args:
            collection_type (pymongo.Collection): the collection to use to access/modify DB documents.
        """
        self._collection_type = collection_type

    @property
    def collection_type(self):
        return self._collection_type

    def get_amazon_document(self, resource_id, type="Instance"):
        """
        Gets a document from the DB with the resource ID provided.

        Args:
            resource_id (str): resource ID.
            type (str): type of the document. e.g.: Instance, SecurityGroup

        Returns:
            dict: in case the document was found in the DB, None otherwise.
        """
        document = self.collection_type.find_one(filter={global_constants.ID: resource_id})
        if document:
            return document
        else:
            raise AmazonResourceNotFoundError(type=type, id=resource_id)

    def get_user_document_by_id(self, user_id, username, password, type='User'):
        """
        Gets a user document from the DB by it's ID.

        Args:
            user_id (str): user ID.
            username (str): user name.
            password (str): user password.
            type (str): resource type in this case (a user).

        Returns:
            dict: a user document in case it was found.

        Raises:
            UserNotFoundError: in case the user was not found.
        """
        user_document = self.collection_type.find_one(filter={global_constants.ID: user_id})
        if user_document:
            return user_document
        else:
            raise UserNotFoundError(type=type, id=f"username: {username}, password: {password}")

    def get_docker_document(self, amazon_resource_id, docker_resource_id, type="Container"):
        """
        Gets a docker document from the DB.

        Args:
            amazon_resource_id (str): amazon resource ID.
            docker_resource_id (str): docker resource ID.
            type (str): type of the document. e.g.: Container, Image

        Returns:
            dict: a matching document to the docker resource ID.
        """
        amazon_document = self.get_amazon_document(resource_id=amazon_resource_id)
        docker_document = _find_specific_document(amazon_document[f"{type}s"], docker_resource_id=docker_resource_id)

        if docker_document:
            return docker_document
        raise DockerResourceNotFoundError(type=type, id=docker_resource_id)

    def get_docker_documents(self, amazon_resource_id, type):
        """
        Gets all the docker documents from the DB.

        Args:
            amazon_resource_id (str): amazon resource ID.
            type (str): type of the document. e.g.: Container, Image

        Returns:
            list(dict): a list of dict with all documents with requested type, empty list in case there aren't.
        """
        amazon_document = self.get_amazon_document(resource_id=amazon_resource_id)
        return amazon_document[f"{type}s"]

    def get_all_amazon_documents(self):
        """
        Gets all documents from the DB of a specific collection.

        Returns:
            list(dict): a list of all the documents available, empty list in case there aren't any available documents.
        """
        results = []
        all_documents = self.collection_type.find({})

        for document in all_documents:
            results.append(document)
        return results

    def delete_docker_document(self, amazon_resource_id, docker_resource_id, docker_document_type):
        """
        Deletes a docker document from DB.

        Args:
            amazon_resource_id (str): amazon resource ID.
            docker_resource_id (str): docker resource ID.
            docker_document_type (str): document type, eg. "Container", "Network", "Image"

        update example:

            test.update_one(
                filter={
                    "_id": "i-086d96f9de57d095b"
                },
                update={
                "$pull": {
                    "Containers": {
                        "_id": 2
                    }
                }
            }
        )

        Remove container document that its ID is 2.


        Raises:
            UpdateDatabaseError: in case pulling docker document from the array has failed.

        """
        docker_document = self.get_docker_document(
            amazon_resource_id=amazon_resource_id, docker_resource_id=docker_resource_id, type=docker_document_type
        )

        try:
            self.collection_type.update_one(
                filter={
                    global_constants.ID: amazon_resource_id
                },
                update={
                    global_constants.PULL: {
                        f"{docker_document_type}s": {
                            global_constants.ID: docker_resource_id
                        }
                    }
                }
            )
        except Exception as error:
            raise UpdateDatabaseError(document=docker_document, error_msg=str(error))

    def add_docker_document(self, amazon_resource_id, docker_document_type, new_docker_document):
        """
        Adds a docker document to the DB.

        Args:
            amazon_resource_id (str): amazon resource ID.
            docker_document_type (str): document type, eg. "Container", "Network", "Image"
            new_docker_document (dict): the new docker document.

        new_docker_document example:
            {
                "_id": 1,
                "image": "metasploit_image",
                "name": "Awesome",
                "status": "running",
                "ports": [55555, 55556]
            }

        Raises:
            UpdateDatabaseError: in case updating the DB with a new docker document fails.
        """
        amazon_document = self.get_amazon_document(resource_id=amazon_resource_id)

        try:
            self.collection_type.update_one(
                filter={
                    global_constants.ID: amazon_document[global_constants.ID]
                },
                update={
                    global_constants.ADD_TO_SET: {
                        f"{docker_document_type}s": new_docker_document
                    }
                }
            )
        except Exception as error:
            raise UpdateDatabaseError(document=amazon_document, error_msg=str(error))

    def add_metasploit_document(self, amazon_resource_id, metasploit_document):
        """
        Adds a new metasploit document to the DB.

        Args:
            amazon_resource_id (str): amazon resource ID.
            metasploit_document (str): new metasploit document.

        Raises:
            UpdateDatabaseError: in case updating the DB with a new metasploit document fails.
        """
        amazon_document = self.get_amazon_document(resource_id=amazon_resource_id)

        try:
            self.collection_type.update_one(
                filter={
                    global_constants.ID: amazon_document[global_constants.ID]
                },
                update={
                    global_constants.ADD_TO_SET: {
                        "Metasploit": metasploit_document
                    }
                }
            )
        except Exception as error:
            raise UpdateDatabaseError(document=amazon_document, error_msg=str(error))

    def update_docker_document(self, docker_document_type, docker_document_id, update, docker_server_id):
        """
        Updates a docker document in the DB.

        Args:
            docker_document_type (str): document type, eg. "Container", "Image"
            docker_document_id (str): the ID of the docker document.
            update (dict): a dictionary that represents which values needs to be updated.
            docker_server_id (str): docker server ID.

        update examples:
            {
                "Containers.$.State": "stopped"
            }

            means update the State key to a "stopped" state.
        """
        amazon_document = self.get_amazon_document(resource_id=docker_server_id)

        try:
            self.collection_type.update_one(
                filter={
                    global_constants.ID: amazon_document[global_constants.ID],
                    f"{docker_document_type}s.{global_constants.ID}": docker_document_id
                },
                update={
                    global_constants.SET: update
                }
            )
        except Exception as error:
            raise UpdateDatabaseError(document=amazon_document, error_msg=str(error))

    def insert_amazon_document(self, new_amazon_document):
        """
        Inserts a document into the DB.

        Raises:
            InsertDatabaseError: in case insertion to the DB fails.
        """
        try:
            self.collection_type.insert_one(document=new_amazon_document)
        except Exception as error:
            raise InsertDatabaseError(document=new_amazon_document, error_msg=str(error))

    def insert_user_document(self, new_user_document):
        """
        Inserts a user document into the DB.

        Args:
            new_user_document (dict): a new user document.

        Raises:
            InsertDatabaseError: in case insertion to the DB fails.
            DuplicateUserNameError: in case there is a duplicate user name.
        """
        try:
            self.collection_type.insert_one(document=new_user_document)
        except Exception as error:
            if "duplicate key error" in str(error):
                raise DuplicateUserNameError(username=new_user_document.get("username"))
            raise InsertDatabaseError(document=new_user_document, error_msg=str(error))

    def delete_amazon_document(self, resource_id, type):
        """
        Deletes a single amazon document from the DB.

        Args:
            resource_id (str): amazon resource ID.
            type (str): amazon resource type. e.g.: Instance, SecurityGroup

        Raises:
            DeleteDatabaseError: in case the deletion has failed.
        """
        amazon_document = self.get_amazon_document(resource_id=resource_id, type=type)

        try:
            self.collection_type.delete_one(filter=amazon_document)
        except Exception as error:
            raise DeleteDatabaseError(document=amazon_document, error_msg=str(error))

    def update_amazon_document(self, amazon_resource_id, update):
        """
        Updates the amazon document

        Args:
            amazon_resource_id (str): amazon resource ID.
            update (dict): a dictionary that represents which values needs to be updated.

        update examples:

            update = {"IpPermissionsInbound": ip_permissions}

            means update IpInboundPermission of a security group to a new ip permissions
        """
        amazon_document = self.get_amazon_document(resource_id=amazon_resource_id)

        try:
            self.collection_type.update_one(
                filter={
                    global_constants.ID: amazon_resource_id
                },
                update={
                    global_constants.SET: update
                }
            )
        except Exception as error:
            raise UpdateDatabaseError(document=amazon_document, error_msg=str(error))


def _find_specific_document(docker_documents, docker_resource_id):
    """
    Finds a docker document with the specified ID.

    Args:
        docker_documents (dict): documents form.
        docker_resource_id (str): docker resource ID.

    Returns:
        dict: a docker document if found, empty dict otherwise.
    """
    for document in docker_documents:
        if document[global_constants.ID] == docker_resource_id:
            return document
    return {}


"""
Given this array how to update operation on containers
"""

# d = {
#     "Containers": [
#         {
#             "_id": 1,
#             "state": "running"
#         },
#         {
#             "_id": 2,
#             "state": "stopped"
#         }
#     ],
#     "Images": [],
#     "Networks": [],
#     "IpParameters": {
#         "PrivateDNSName": "ip-172-31-32-241.us-east-2.compute.internal",
#         "PrivateIpAddress": "172.31.32.241",
#         "PublicDNSName": "ec2-18-220-31-187.us-east-2.compute.amazonaws.com",
#         "PublicIpAddress": "18.220.31.187"
#       },
#     "KeyName": "default_key_pair_name",
#     "SecurityGroups": [
#         {
#           "GroupId": "sg-0cde419d7de10fff7",
#           "GroupName": "zzz"
#         }
#       ],
#     "State": {
#         "Code": 16,
#         "Name": "running"
#     },
#     "_id": "i-086d96f9de57d095b"
#     }
#
#
# test = DatabaseCollections.INSTANCES


"""
How to remove a container from DB
"""
# test.update_one(
#     filter={
#         "_id": "i-086d96f9de57d095b"
#     },
#     update={
#         "$pull": {
#             "Containers": {
#                 "_id": 2
#             }
#         }
#     }
# )


"""
Add a container to DB example
"""
# test.update_one(
#     filter={
#         "_id": "i-086d96f9de57d095b"
#     },
#     update={
#         "$addToSet": {
#             "Containers": {
#                 "_id": 3,
#                 "state": "running"
#             }
#         }
#     }
# )


"""
Update containers state in DB example
"""
# ids = [i['_id'] for i in d["Containers"]]
# print(ids)
#
# for i in ids:
#     test.update_one(
#         filter={
#             "_id": "i-086d96f9de57d095b",
#             "Containers._id": i
#         },
#         update={
#             "$set": {
#                 "Containers.$.state": "stopped"
#             }
#         }
#     )