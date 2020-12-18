from pymongo import MongoClient

from metasploit import constants as global_constants
from metasploit.api.errors import (
    DeleteDatabaseError,
    InsertDatabaseError,
    AmazonResourceNotFoundError,
    DockerResourceNotFoundError,
    UpdateDatabaseError
)
from metasploit.aws.amazon_operations import DockerServerInstanceOperations

db_client = MongoClient(
    'mongodb+srv://Metasploit:FVDxbg312@metasploit.gdvxn.mongodb.net/metasploit?retryWrites=true&w=majority'
)
metasploit_db = db_client['Metasploit']


class DatabaseCollections:
    INSTANCES = metasploit_db['instances']
    SECURITY_GROUPS = metasploit_db['securityGroups']


class DatabaseOperations(object):
    """
    Class to manage all database operations.

    Attributes:
        collection_type (pymongo.Collection): the collection to use in the DB.
        amazon_resource_id (str): amazon resource ID.
        docker_resource_id (str): docker resource ID.
        amazon_document (dict): amazon document in case it was found.
        docker_document (dict): docker document in case it was found.
    """
    def __init__(self, collection_type, **kwargs):
        """
        Initialize the DatabaseOperations class attributes.

        Args:
            collection_type (pymongo.Collection): the collection to use to access/modify DB documents.

        Keyword Arguments:
            amazon_resource_id (str): the amazon resource ID that the DB operation should be performed on.
            docker_resource_id (str): the docker resource ID that the DB operation should be performed on.
            all_docker_documents (bool): indicate if all docker document type is needed, True if yes, False otherwise.
            docker_document_type (str): indicate which type is needed for docker e.g. Constants.Containers
            single_docker_document (bool): indicate if a specific docker document is required.
                                           True if yes, False otherwise
            collection_name (str): the collection name. e.g. SecurityGroups, Instances
            single_amazon_document (bool): indicate if the search should be on a single amazon document. True if yes,
                                           False to look for all documents available in the DB.
            amazon_resource_type (str): what type of amazon document it is. e.g. Instance, SecurityGroup
            docker_resource_type (str): which type of docker document it is. e.g. Container, Image
        """
        self._collection_type = collection_type
        self._amazon_resource_id = kwargs.pop("amazon_resource_id", "")
        self._docker_resource_id = kwargs.pop("docker_resource_id", "")

        if self._amazon_resource_id or not kwargs.get("single_amazon_document", True):
            self._amazon_document, self._docker_document = self.find_document(**kwargs)
        else:
            self._amazon_document, self._docker_document = {}, {}

    def find_document(
            self,
            all_docker_documents=False,
            docker_document_type="",
            single_docker_document=False,
            collection_name="",
            single_amazon_document=True,
            amazon_resource_type="",
            docker_resource_type=""
    ):
        """
        Finds an amazon document(s) and a docker document(s)
        in the database, and return a parsed dict response of the document if it was found.

        Args:
            all_docker_documents (bool): indicate if all docker document type is needed, True if yes, False otherwise.
            docker_document_type (str): indicate which type is needed for docker e.g. Constants.Containers
            single_docker_document (bool): indicate if a specific docker document is required.
                                           True if yes, False otherwise
            collection_name (str): the collection name. e.g. SecurityGroups, Instances
            single_amazon_document (bool): indicate if the search should be on a single amazon document. True if yes,
                                           False otherwise.
            amazon_resource_type (str): what type of amazon document it is. e.g. Instance, SecurityGroup
            docker_resource_type (str): which type of docker document it is. e.g. Container, Image

        Returns:
            tuple (dict/list(dict), dict/list(dict)): first argument is the amazon document(s),
                the second argument is the docker document(s). In case it's a single amazon document is True
                it will be dict, otherwise it will be a list of dictionaries. In case all_docker_documents is True,
                it will be a list of dictionaries, otherwise dict.



        Raises:
            DockerResourceNotFoundError: in case the docker resource was not found in the DB.
            AmazonResourceNotFoundError: in case the amazon resource was not found in the DB.
        """
        if single_amazon_document:
            amazon_document = self.collection_type.find_one(filter={global_constants.ID: self.amazon_resource_id})
            if amazon_document:
                if not all_docker_documents and not single_docker_document:
                    return amazon_document, {}

                docker_documents = amazon_document[docker_document_type]

                if all_docker_documents:
                    if docker_documents and not single_docker_document:
                        return amazon_document, docker_documents
                    else:
                        raise DockerResourceNotFoundError(type=docker_resource_type)

                if single_docker_document:
                    docker_document = _find_specific_document(
                        docker_documents=docker_documents, docker_resource_id=self.docker_resource_id
                    )
                    if docker_document:
                        return amazon_document, docker_document
                    else:
                        raise DockerResourceNotFoundError(type=docker_resource_type, id=self.docker_resource_id)
            else:
                raise AmazonResourceNotFoundError(type=amazon_resource_type, id=self.amazon_resource_id)
        else:
            parsed_response = {collection_name: []}
            amazon_documents = self.collection_type.find({})  # means find all of amazon documents.
            for result in amazon_documents:
                parsed_response[collection_name].append(result)
            if parsed_response[collection_name]:
                return parsed_response, {}
            else:
                raise AmazonResourceNotFoundError(type=amazon_resource_type)

    def delete_docker_document(self, docker_document_type):
        """
        Deletes a docker document from DB.

        Args:
            docker_document_type (str): document type, eg. "Containers", "Networks", "Images"

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
        try:
            self.collection_type.update_one(
                filter={
                    global_constants.ID: self._amazon_document[global_constants.ID]
                },
                update={
                    global_constants.PULL: {
                        docker_document_type: {
                            global_constants.ID: self.docker_resource_id
                        }
                    }
                }
            )
        except Exception as error:
            print("problem in delete docker document")
            raise UpdateDatabaseError(document=self.amazon_document, error_msg=error.__str__())

    def add_docker_document(self, docker_document_type, new_docker_document):
        """
        Adds a docker document to the DB.

        Args:
            docker_document_type (str): document type, eg. "Containers", "Networks", "Images"
            new_docker_document (dict): the new docker document.

        new_docker_document examples:
            {
                "_id": 1,
                "image": metasploit_image,
                "name": Awesome,
                "status": "running",
                "ports": [55555, 55556]
            }

        Raises:
            UpdateDatabaseError: in case updating the DB with a new docker document fails.
        """
        try:
            self.collection_type.update_one(
                filter={
                    global_constants.ID: self.amazon_document[global_constants.ID]
                },
                update={
                    global_constants.ADD_TO_SET: {
                        docker_document_type: new_docker_document
                    }
                }
            )
        except Exception as error:
            print("problem in add docker document")
            raise UpdateDatabaseError(document=self.amazon_document, error_msg=error.__str__())

    def add_metasploit_document(self, metasploit_document):
        """
        Adds a new metasploit document to the DB.

        Args:
            metasploit_document (str): new metasploit document.

        Raises:
            UpdateDatabaseError: in case updating the DB with a new metasploit document fails.
        """
        try:
            self.collection_type.update_one(
                filter={
                    global_constants.ID: self.amazon_document[global_constants.ID]
                },
                update={
                    global_constants.ADD_TO_SET: {
                        "Metasploit": metasploit_document
                    }
                }
            )
        except Exception as error:
            print("problem in add metasploit document")
            raise UpdateDatabaseError(document=self.amazon_document, error_msg=error.__str__())

    def update_docker_document(self, docker_document_type, docker_document_id, update, docker_server_id):
        """
        Updates a docker document in the DB.

        Args:
            docker_document_type (str): document type, eg. "Containers", "Networks", "Images"
            docker_document_id (str): the ID of the docker document.
            update (dict): a dictionary that represents which values needs to be updated.
            docker_server_id (str): docker server ID.

        update examples:
            {
                "Containers.$.State": "stopped"
            }

            means update the State key to a "stopped" state.
        """
        try:
            if global_constants.INSTANCES in self.amazon_document:
                for ins_doc in self.amazon_document[global_constants.INSTANCES]:
                    if ins_doc[global_constants.ID] == docker_server_id:
                        amazon_doc = ins_doc[global_constants.ID]
                        break
            else:
                amazon_doc = self.amazon_document[global_constants.ID]

            # need to find a way if all documents needs to be updated how to extract the correct ID

            self.collection_type.update_one(
                filter={
                    global_constants.ID: amazon_doc,
                    f"{docker_document_type}.{global_constants.ID}": docker_document_id
                },
                update={
                    global_constants.SET: update
                }
            )
        except Exception as error:
            print("problem in update docker document")
            raise UpdateDatabaseError(document=self.amazon_document, error_msg=error.__str__())

    def insert_amazon_document(self, new_amazon_document):
        """
        Inserts a document into the DB.

        Raises:
            InsertDatabaseError: in case insertion to the DB fails.
        """
        try:
            self.collection_type.insert_one(document=new_amazon_document)
        except Exception as error:
            raise InsertDatabaseError(document=new_amazon_document, error_msg=error.__str__())

    def delete_amazon_document(self):
        """
        Deletes a single amazon document from DB.

        Raises:
            DeleteDatabaseError: in case delete operation failed in the DB.
        """
        try:
            if isinstance(self.amazon_document, dict):
                self.collection_type.delete_one(filter=self.amazon_document)
            else:
                self.collection_type.delete_many(filter={})
        except Exception as error:
            raise DeleteDatabaseError(document=self.amazon_document, error_msg=error.__str__())

    def update_amazon_document(self, update):
        """
        Updates the amazon document

        Args:
            update (dict): a dictionary that represents which values needs to be updated.

        update examples:

            update = {"IpPermissionsInbound": ip_permissions}

            means update IpInboundPermission of a security group to a new ip permissions
        """
        try:
            self.collection_type.update_one(
                filter={
                    global_constants.ID: self.amazon_resource_id
                },
                update={
                    global_constants.SET: update
                }
            )
        except Exception as error:
            raise UpdateDatabaseError(document=self.amazon_document, error_msg=error.__str__())

    @property
    def collection_type(self):
        return self._collection_type

    @property
    def docker_resource_id(self):
        return self._docker_resource_id

    @property
    def amazon_resource_id(self):
        return self._amazon_resource_id

    @property
    def amazon_document(self):
        return self._amazon_document

    @amazon_document.setter
    def amazon_document(self, amazon_doc):
        if isinstance(amazon_doc, dict):
            self._amazon_document = amazon_doc
        else:
            raise AttributeError(f"{amazon_doc} is not a dict type")

    @property
    def docker_document(self):
        return self._docker_document

    @docker_document.setter
    def docker_document(self, docker_doc):
        if isinstance(docker_doc, dict):
            self._docker_document = docker_doc
        else:
            raise AttributeError(f"{docker_doc} is not a dict type")


class DatabaseManager(object):

    def __init__(self, api_manager):
        self._api_manager = api_manager

    @property
    def api_manager(self):
        return self._api_manager

    @property
    def amazon_document(self):
        return self.api_manager.db_operations_manager.amazon_document

    @property
    def docker_document(self):
        return self.api_manager.db_operations_manager.docker_document

    def insert_amazon_document(self, new_amazon_document):
        """
        Inserts a new amazon document.

        Args:
            new_amazon_document (dict): a new amazon document to insert into the DB.
        """
        self.api_manager.db_operations_manager.insert_amazon_document(new_amazon_document=new_amazon_document)

    def delete_amazon_document(self):
        """
        Deletes amazon document from the DB.
        """
        self.api_manager.db_operations_manager.delete_amazon_document()

    def update_amazon_document(self, update):
        """
        Updates an amazon document in the DB.

        Args:
             update (dict): a dictionary that represents which values needs to be updated.
        """
        self.api_manager.db_operations_manager.update_amazon_document(update=update)

    def insert_docker_document(self, docker_document_type, new_docker_document):
        """
        Creates docker document in the DB.

        Args:
            docker_document_type (str): docker document type, eg. "Containers", "Networks", "Images"
            new_docker_document (dict): the new docker document.
        """
        self.api_manager.db_operations_manager.add_docker_document(
            docker_document_type=docker_document_type,
            new_docker_document=new_docker_document
        )

    def delete_docker_document(self, docker_document_type):
        """
        Deletes a docker server document(s) from the DB.
        """
        self.api_manager.db_operations_manager.delete_docker_document(docker_document_type=docker_document_type)

    def update_docker_document(self, docker_document_type, docker_document_id, update, docker_server_id):
        """
        Updates a docker document in the DB.
        """
        self.api_manager.db_operations_manager.update_docker_document(
            docker_document_type=docker_document_type,
            docker_document_id=docker_document_id,
            update=update,
            docker_server_id=docker_server_id
        )

    def insert_metasploit_document(self, metasploit_document):
        """
        inserts a new metasploit document in the DB.

        Args:
            metasploit_document (dict): a new metasploit document.
        """
        self.api_manager.db_operations_manager.add_metasploit_document(metasploit_document=metasploit_document)


class DockerServerDatabaseManager(DatabaseManager):

    def __init__(self, api_manager, is_update_required):
        super(DockerServerDatabaseManager, self).__init__(api_manager=api_manager)

        # updates the container states
        if is_update_required:
            if global_constants.INSTANCES not in self.amazon_document:
                if self.amazon_document[global_constants.CONTAINERS]:
                    docker_server_id = self.api_manager.amazon_resource_id
                    print(docker_server_id)
                    self._update_container_state(docker_server_id=docker_server_id)
            elif self.amazon_document[global_constants.INSTANCES]:
                for instance_document in self.amazon_document[global_constants.INSTANCES]:
                    if instance_document[global_constants.CONTAINERS]:
                        self._update_container_state(
                            docker_server_id=instance_document[global_constants.ID]
                        )

    def _update_container_state(self, docker_server_id):
        """
        Updates container states.

        Args:
            docker_server_id (str): docker server ID.
        """
        for container_id, state in _get_container_states_ids(docker_server_id=docker_server_id):
            super().update_docker_document(
                docker_document_type=global_constants.CONTAINERS,
                docker_document_id=container_id,
                update={"Containers.$.status": state},
                docker_server_id=docker_server_id
            )

    @property
    def get_docker_server_instance_document(self):
        """
        Get all the instance document(s) from DB.

        Returns:
            dict: docker instance document(s)
        """
        return super().amazon_document

    def insert_docker_server_document(self, new_docker_server_document):
        """
        Creates a docker server instance document and inserts them to the DB.

        Returns:
            dict: a new instance document.
        """
        super().insert_amazon_document(new_amazon_document=new_docker_server_document)

    def delete_docker_server_instance_document(self):
        """
        Deletes a docker server instance document.
        """
        super().delete_amazon_document()


class SecurityGroupDatabaseManager(DatabaseManager):

    @property
    def get_security_group_document(self):
        """
        Get the security groups(s) documents from the DB
        """
        return super().amazon_document

    def insert_security_group_document(self, new_amazon_document):
        """
        Creates a security group document and inserts it into the DB.
        """
        super().insert_amazon_document(new_amazon_document=new_amazon_document)

    def delete_security_group_document(self):
        """
        Deletes a security group document.
        """
        super().delete_amazon_document()

    def update_security_group_document(self, update):
        """
        Updates a security group document.

        Args:
            update (dict): a dictionary that represents which values needs to be updated.
        """
        super().update_amazon_document(update=update)


class ContainerDatabaseManager(DockerServerDatabaseManager):

    @property
    def get_container_document(self):
        """
        Get container document(s) from DB.
        """
        return super().docker_document

    def insert_container_document(self, new_container_document):
        """
        Creates container document and inserts it into the DB.
        """
        super().insert_docker_document(
            docker_document_type=global_constants.CONTAINERS, new_docker_document=new_container_document
        )

    def delete_container_document(self):
        """
        Deletes a container document from DB.
        """
        super().delete_docker_document(docker_document_type=global_constants.CONTAINERS)


class ImageDatabaseManager(DockerServerDatabaseManager):

    @property
    def get_image_document(self):
        """
        Get images document(s) from the DB.
        """
        return super().docker_document

    def insert_image_document(self, new_image_document):
        """
        Creates image document and inserts it into the DB.
        """
        super().insert_docker_document(
            docker_document_type=global_constants.IMAGES, new_docker_document=new_image_document
        )

    def delete_image_document(self):
        """
        Deletes image document from the DB.
        """
        super().delete_docker_document(docker_document_type=global_constants.IMAGES)


class NetworkDatabaseManager(DockerServerDatabaseManager):

    @property
    def get_network_document(self):
        """
        Get network document(s) from the DB.
        """
        return super().docker_document

    def insert_network_document(self, new_network_document):
        """
        Creates image document and inserts it into the DB.
        """
        super().insert_docker_document(
            docker_document_type=global_constants.NETWORKS, new_docker_document=new_network_document
        )

    def delete_network_document(self):
        """
        Deletes image document from the DB.
        """
        super().delete_docker_document(docker_document_type=global_constants.NETWORKS)


class MetasploitDataBaseManager(DatabaseManager):

    @property
    def get_all_metasploit_documents(self):
        """
        Get metasploit documents from DB.
        """
        return super().amazon_document['Metasploit']

    def insert_metasploit_document(self, new_metasploit_document):
        """
        Inserts a metasploit document into the DB.

        Args:
            new_metasploit_document (dict): new metasploit document.
        """
        super().insert_metasploit_document(metasploit_document=new_metasploit_document)


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


def _update_container_docs_attrs(api_manager, docker_server_id):
    """
    Updates the container(s) attributes that belongs to the instance.

    Args:
        api_manager (ApiManager): api manager object.
        docker_server_id (str): docker server instance ID.

    Returns:
        list(dict): a list of dictionaries that composes the container updated documents.
    """

    container_documents = []

    docker_server = DockerServerInstanceOperations(instance_id=docker_server_id).docker_server
    containers = docker_server.docker.container_collection.list(all=True)

    for container in containers:
        container_documents.append(api_manager.container_response(container=container).response)

    return container_documents


def _get_container_states_ids(docker_server_id):
    """
    Yields a container states and id's.

    Args:
        docker_server_id (str): docker server ID.

    Yields:
        tuple(str, str): a container id and state. etc. (1234, "running"), (3243, "stopped"), (54363, "exited")
    """
    docker_server = DockerServerInstanceOperations(instance_id=docker_server_id).docker_server
    containers = docker_server.docker.container_collection.list(all=True)
    for container in containers:
        yield container.id, container.status


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