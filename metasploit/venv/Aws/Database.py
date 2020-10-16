from pymongo import MongoClient
from metasploit.venv.Aws import Constants
from metasploit.venv.Aws.ServerExceptions import (
    DeleteDatabaseError,
    InsertDatabaseError,
    AmazonResourceNotFoundError,
    DockerResourceNotFoundError
)
from metasploit.venv.Aws.Response import (
    PrepareResponse
)

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
        document (dict): the document to use all DB operations.
    """
    def __init__(self, collection_type, **kwargs):

        self._collection_type = collection_type
        self._amazon_resource_id = kwargs.pop("amazon_resource_id", "")
        self._docker_resource_id = kwargs.pop("docker_resource_id", "")

        if self._amazon_resource_id:
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
            tuple (dict, list): first argument is the amazon document(s), the second argument is the docker document(s).

        Raises:
            DockerResourceNotFoundError: in case the docker resource was not found in the DB.
            AmazonResourceNotFoundError: in case the amazon resource was not found in the DB.
        """
        if single_amazon_document:
            amazon_document = self.collection_type.find_one(filter={Constants.ID: self.amazon_resource_id})
            if amazon_document:
                if not all_docker_documents and not single_docker_document:
                    return amazon_document, {}

                docker_documents = amazon_document[Constants.DOCKER][docker_document_type]

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

    def delete_amazon_document(self):
        """
        Deletes a single amazon document from DB.

        Raises:
            DeleteDatabaseError: in case delete operation failed in the DB.
        """
        try:
            if isinstance(self._amazon_document, dict):
                self.collection_type.delete_one(filter=self.amazon_document)
            self.collection_type.delete_many(filter={})
        except Exception as error:
            raise DeleteDatabaseError(document=self.amazon_document, error_msg=error.__str__())

    def delete_docker_document(self):
        """
        Deletes a docker document(s) from DB.

        Raises:
            DeleteDatabaseError: in case delete operation failed in the DB.
        """
        #  need to complete code
        return

    def insert_amazon_document(self):
        """
        Inserts a document into the DB.

        Raises:
            InsertDatabaseError: in case insertion to the DB fails.
        """
        try:
            self.collection_type.insert_one(document=self.amazon_document)
        except Exception as error:
            raise InsertDatabaseError(document=self.amazon_document, error_msg=error.__str__())

    def update_amazon_document(self, updated_document):
        """
        Updates a document in the DB
        """
        self.delete_amazon_document()
        self.amazon_document = updated_document
        self.insert_amazon_document()

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

    def delete_amazon_document(self):
        """
        Deletes amazon document from the DB.
        """
        self.api_manager.db_operations_manager.delete_amazon_document()


class DockerServerDatabaseManager(DatabaseManager):

    def __init__(self, api_manager, docker_server):
        super(DockerServerDatabaseManager, self).__init__(api_manager=api_manager)
        self._docker_server = docker_server

        if self.docker_server:
            instances_documents = super().amazon_document
            for instance_doc in instances_documents:
                if instance_doc[Constants.DOCKER][Constants.CONTAINERS]:
                    instance_doc[Constants.DOCKER][Constants.CONTAINERS] = _update_container_document_attributes(
                        docker_server=self.docker_server
                    )
                    self.api_manager.db_operations_manager.update_amazon_document(updated_document=instance_doc)

    @property
    def get_docker_server_instance_document(self):
        """
        Get all the instance document(s) from DB.

        Returns:
            dict: docker instance document(s)
        """
        return super().amazon_document

    @property
    def create_docker_server_instance_document(self):
        """
        Creates instance document and inserts them to the DB.

        Returns:
            dict: a new instance document.
        """
        instance_document = PrepareResponse.prepare_instance_response(docker_server=self.docker_server)
        self.api_manager.db_operations_manager.amazon_document = instance_document
        self.api_manager.db_operations_manager.insert_amazon_document()
        return instance_document

    def delete_docker_server_instance_document(self):
        """
        Deletes a docker server instance document.
        """
        super().delete_amazon_document()

    @property
    def docker_server(self):
        return self._docker_server


class SecurityGroupDatabaseManager(DatabaseManager):

    def __init__(self, api_manager, security_group):
        super(SecurityGroupDatabaseManager, self).__init__(api_manager=api_manager)
        self._security_group = security_group

    @property
    def get_security_group_document(self):
        """
        Get the security groups(s) documents from the DB
        """
        return super().amazon_document

    @property
    def create_security_group_document(self):
        """
        Creates a security group document and inserts it into the DB.
        """
        security_group_document = PrepareResponse.prepare_security_group_response(
            security_group_obj=self.security_group
        )
        self.api_manager.db_operations_manager.amazon_document = security_group_document
        self.api_manager.db_operations_manager.insert_amazon_document()
        return security_group_document

    def delete_security_group_document(self):
        """
        Deletes a security group document.
        """
        super().delete_amazon_document()

    def security_group(self):
        return self._security_group


class ContainerDatabaseManager(DockerServerDatabaseManager):
    def __init__(self, api_manager, docker_server, container):
        super(ContainerDatabaseManager, self).__init__(api_manager=api_manager, docker_server=docker_server)
        self._container = container

    @property
    def get_container_document(self):
        """
        Get container document(s) from DB.
        """
        return super().docker_document

    def create_container(self):
        """
        Creates container document and inserts it into the DB.
        """
        container_document = PrepareResponse.prepare_container_response(container=self.container)

        self.api_manager.db_operations_manager.docker_document = container_document

        updated_instance_document = super().amazon_document[Constants.DOCKER][Constants.CONTAINERS].append(
            container_document
        )

        self.api_manager.db_operations_manager.update_amazon_document(updated_document=updated_instance_document)

        return container_document

    @property
    def container(self):
        return self._container


class ImageDatabaseManager(DockerServerDatabaseManager):
    def __init__(self, api_manager, docker_server, image):
        super(ImageDatabaseManager, self).__init__(api_manager=api_manager, docker_server=docker_server)
        self._image = image

    @property
    def image(self):
        return self._image


def _find_specific_document(docker_documents, docker_resource_id):
    """
    Finds a document with the specified ID.

    Args:
        docker_documents (dict): documents form.

    Returns:
        dict: a container document if found, empty dict otherwise.
    """
    for document in docker_documents:
        if document[Constants.ID] == docker_resource_id:
            return document
    return {}


def _update_container_document_attributes(docker_server):
    """
    Updates the container(s) docker_documents that belongs to the instance.

    Args:
        docker_server (DockerServerInstance): docker server instance object.

    Returns:
        list(dict): a list of dictionaries that composes the container updated docker_documents.
    """

    container_documents = []

    containers = docker_server.docker.get_container_collection().list(all=True)

    for container in containers:
        container_documents.append(PrepareResponse.prepare_container_response(container=container))

    return container_documents

# def find_documents(document, collection_type, collection_name="", single_document=True):
#     """
#     Find a document in the database, and return a parsed dict response of the document if it was found.
#
#     Args:
#         document (dict): The document to search for.
#         collection_type (pymongo.Collection): the collection that the request should be searched on.
#         collection_name (str): the collection name. etc: SecurityGroups, Instances, KeyPair
#         single_document (bool): indicate if the search should be on a single document.
#
#     Returns:
#         dict: the result from database if it was found, otherwise empty dict.
#     """
#     if single_document:
#         database_result = collection_type.find_one(filter=document)
#         return database_result if database_result else {}
#     else:
#         parsed_response = {collection_name: []}
#         database_result = collection_type.find(document)
#         for result in database_result:
#             parsed_response[collection_name].append(result)
#         if parsed_response[collection_name]:
#             return parsed_response
#         else:
#             return {}
#
#
# def update_amazon_document(fields, collection_type, operation, id):
#     """
#     update a document in the database.
#
#     Args:
#         fields (dict): a dictionary form of what to update.
#         collection_type (pymongo.Collection): the collection that the update should be on.
#         operation (str): the database operation that should be used. ("$set", "$push")
#         id (str): the id of the document to be updated.
#
#         fields parameter examples:
#         {
#             "IpPermissionsInbound": security_group_obj.ip_permissions
#         }
#         means update the IpInboundPermissions To a new ip permissions
#
#
#         {
#          "Docker": {
#             "Containers": container_response
#             }
#         }
#         means update the Containers over an instance
#
#     Returns:
#         True if database update was successful, False otherwise.
#     """
#     try:
#         collection_type.update_one({Constants.ID: id}, {operation: fields})
#         return True
#     except Exception as e:
#         print(e)
#         return False
#
#
# def delete_documents(collection_type, document={}, single_document=True):
#     """
#     Deletes a single or multiple docker_documents from a chosen collection.
#
#     Args:
#         collection_type (pymongo.Collection): The collection that should be deleted from.
#         document (dict): the document from the database that should be deleted.
#         single_document (bool): indicate if the deletion should be on a single document.
#
#     Returns:
#         True if deletion from database was completed successfully, False otherwise.
#     """
#     try:
#         if single_document:
#             collection_type.delete_one(filter=document)
#         else:
#             collection_type.delete_many(filter=document)  # means delete all of them
#         return True
#     except Exception as e:
#         print(e)
#         return False
#
#
# def insert_amazon_document(collection_type, document):
#     try:
#         collection_type.insert_one(document=document)
#         return True
#     except Exception as e:
#         print("failed inserting element to DB")
#         print(e)
#         return False
#
#
# def update_instance_document_in_database(instance_id, instance_response):
#     if delete_documents(collection_type=DatabaseCollections.INSTANCES, document={Constants.ID: instance_id}):
#         if insert_amazon_document(collection_type=DatabaseCollections.INSTANCES, document=instance_response):
#             return True
#         else:
#             return False
#     else:
#         return False
