from metasploit.venv.Aws.Database import DataBaseManager
from metasploit.venv.Aws import Constants
from metasploit.venv.Aws import Aws_Api_Functions
from metasploit.venv.Aws import Docker_Utils
from metasploit.venv.Aws.Response import (
    PrepareResponse,
    ApiResponse,
    HttpCodes
)
from metasploit.venv.Aws.ServerExceptions import choose_http_error_code


class ApiManager(object):

    def __init__(self, collection_type, **kwargs):

        self._client_request = kwargs.get('client_request', {})
        self._resource_id = kwargs.get('resource_id', '')
        self._sub_resource_id = kwargs.get('sub_resource_id', '')
        self._db_manager = DataBaseManager(
            collection_type=collection_type,
            resource_id=self.resource_id,
            collection_name=kwargs.get("collection_name", Constants.INSTANCES),
            single_document=kwargs.get("single_document", True),
            type=kwargs.get("type", Constants.INSTANCE)

        )

    @property
    def resource_id(self):
        return self._resource_id

    @property
    def sub_resource_id(self):
        return self._sub_resource_id

    @property
    def db_manager(self):
        return self._db_manager

    @property
    def client_request(self):
        return self._client_request

    @property
    def create_resource(self):
        return CreateResource(self)

    @property
    def get_resource(self):
        return GetResource(self)

    @property
    def delete_resource(self):
        return DeleteResource(self)

    @property
    def update_resource(self):
        return UpdateResource(self)

    def client_request_modifier(self, code):
        def client_request_decorator(api_func):
            def client_request_wrapper():

                response = {}

                http_status_code = code
                is_valid = False
                is_error = False

                for key, req in self.client_request.items():
                    try:
                        response[key] = api_func(req=req)
                        is_valid = True
                    except Exception as err:
                        http_status_code = choose_http_error_code(error=err)
                        response[key] = PrepareResponse.prepare_error_response(
                            msg=err.__str__(), http_error_code=http_status_code, req=req
                        )
                        is_error = True

                if is_valid and is_error:
                    http_status_code = HttpCodes.MULTI_STATUS

                return ApiResponse(response=response, http_status_code=http_status_code)
            return client_request_wrapper
        return client_request_decorator


class ResourceOperation(object):
    def __init__(self, api_manager):
        self.api_manager = api_manager


class CreateResource(ResourceOperation):

    @property
    @ApiManager.client_request_modifier(code=HttpCodes.CREATED)
    def create_instance(self, req=None):

        docker_server = Aws_Api_Functions.create_instance(kwargs=req)
        instance_document = PrepareResponse.prepare_instance_response(docker_server=docker_server)
        self.api_manager.db_manager.document = instance_document
        self.api_manager.db_manager.insert_document()
        return instance_document

    @property
    @ApiManager.client_request_modifier(code=HttpCodes.CREATED)
    def create_security_group(self, req=None):

        security_group = Aws_Api_Functions.create_security_group(kwargs=req)
        security_group_document = PrepareResponse.prepare_security_group_response(security_group_obj=security_group)
        self.api_manager.db_manager.document = security_group_document
        self.api_manager.db_manager.insert_document()
        return security_group_document

    @property
    @ApiManager.client_request_modifier(code=HttpCodes.CREATED)
    def create_container(self, req=None):

        container = Docker_Utils.create_container(
            instance_id=self.api_manager.resource_id,
            image=req.pop("Image"),
            command=req.pop("Command", None)
        )
        container_document = PrepareResponse.prepare_container_response(container=container)

        updated_instance_document = self.api_manager.db_manager.document[Constants.DOCKER][Constants.CONTAINERS].append(
            container_document
        )
        self.api_manager.db_manager.update_document(updated_document=updated_instance_document)

        return container_document

    @property
    @ApiManager.client_request_modifier(code=HttpCodes.CREATED)
    def pull_image(self, req=None):

        repository = req.pop("Repository")
        image = Docker_Utils.pull_image(
            instance_id=self.api_manager.resource_id,
            repository=repository,
            tag=f"{repository}:latest"
        )
        image_document = PrepareResponse.prepare_image_response(image=image)
        updated_instance_document = self.api_manager.db_manager.document[Constants.DOCKER][Constants.IMAGES].append(
            image_document
        )
        self.api_manager.db_manager.update_document(updated_document=updated_instance_document)
        return image_document


class GetResource(ResourceOperation):

    @property
    def get_resource(self):
        return ApiResponse(response=self.api_manager.db_manager.document, http_status_code=HttpCodes.OK)
        # need to think of a way how to update container document

    def get_all_sub_resource(self, document_type):

        return ApiResponse(
            response=self.api_manager.db_manager.document[Constants.DOCKER][document_type],
            http_status_code=HttpCodes.OK
        )

    def get_specific_sub_resource(self, document_type):

        documents = self.api_manager.db_manager.document[Constants.DOCKER][document_type]
        return ApiResponse(
            response=_find_specific_document(documents=documents),
            http_status_code=HttpCodes.OK
        )


class DeleteResource(ResourceOperation):

    @property
    def delete_instance(self):

        Aws_Api_Functions.get_docker_server_instance(id=self.api_manager.resource_id).terminate()
        self.api_manager.db_manager.delete_document()
        return ApiResponse(http_status_code=HttpCodes.NO_CONTENT)

    @property
    def delete_security_group(self):

        Aws_Api_Functions.get_security_group_object(id=self.api_manager.resource_id)
        self.api_manager.db_manager.delete_document()
        return ApiResponse(http_status_code=HttpCodes.NO_CONTENT)

    @property
    def delete_container(self):

        Docker_Utils.get_container(
            instance_id=self.api_manager.resource_id, container_id=self.api_manager.sub_resource_id
        ).remove()

        # update here all the container documents [TO DO!!!]
        updated_containers_documents = None

        self.api_manager.db_manager.update_document(updated_document=updated_containers_documents)
        return ApiResponse(http_status_code=HttpCodes.NO_CONTENT)


class UpdateResource(ResourceOperation):

    @property
    @ApiManager.client_request_modifier(code=HttpCodes.OK)
    def modify_security_group_inbound_permissions(self, req=None):

        Aws_Api_Functions.update_security_group_inbound_permissions(
            security_group_id=self.api_manager.resource_id,
            req=req
        )

        security_group_document = PrepareResponse.prepare_security_group_response(
            security_group_obj=Aws_Api_Functions.get_security_group_object(id=self.api_manager.resource_id)
        )

        self.api_manager.db_manager.update_document(updated_document=security_group_document)

        return security_group_document

    @property
    def start_container(self):
        return 


def _find_specific_document(self, documents):
    """
    Finds a container document with the specified ID.

    Args:
        documents (dict): a container documents form.

    Returns:
        dict: a container document if found, empty dict otherwise.
        """
    for document in documents:
        if document[Constants.ID] == self.api_manager.sub_resource_id:
            return document
    return {}
