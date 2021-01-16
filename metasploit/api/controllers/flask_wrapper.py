from flask import Flask, jsonify
from flask_restful import Api, request

from metasploit.api.response import (
    HttpCodes
)
from .api_endpoints import (
    InstancesController,
    ContainersController,
    MetasploitController
)
from metasploit.api.utils import (
    HttpMethods
)
from metasploit.api.service_implmentation.docker_server_service import DockerServerServiceImplementation
from metasploit.api.service_implmentation.container_service import ContainerServiceImplementation
from metasploit.api.service_implmentation.metasploit_service import MetasploitServiceImplementation


class FlaskAppWrapper(object):
    """
    This is a class to wrap flask program and to create its endpoints to functions.

    Attributes:
        self._api (FlaskApi) - the api of flask.
    """
    app = Flask(__name__)

    def __init__(self):
        self._api = Api(app=FlaskAppWrapper.app)

    @app.errorhandler(HttpCodes.NOT_FOUND)
    def invalid_urls_error(self):
        """
        Catches a client request that is not a valid API URL.

        Returns:
            tuple (Json, int): an error response that shows all available URL's for the client to use.
        """
        url_error = {
            "Error": f"The given url {request.base_url} is invalid ",
            "AvailableUrls": [
                '/SecurityGroups/Get',
                '/SecurityGroups/Get/<id>',
                '/SecurityGroups/Create',
                '/SecurityGroups/Delete/<id>',
                '/SecurityGroups/<id>/UpdateInboundPermissions',
                '/DockerServerInstances/Create',
                '/DockerServerInstances/Get',
                '/DockerServerInstances/Get/<id>',
                '/DockerServerInstances/Delete/<id>',
                '/DockerServerInstances/<id>/Containers/Get',
                '/DockerServerInstances/<instance_id>/Containers/Get/<container_id>',
                '/DockerServerInstances/<instance_id>/Containers/Delete/<container_id>',
                '/DockerServerInstances/<id>/Images/Pull',
                '/DockerServerInstances/<instance_id>/Containers/CreateMetasploitContainer',
                '/DockerServerInstances/<instance_id>/Metasploit/<target>/RunExploit',
                '/DockerServerInstances/<instance_id>/Metasploit/<target>/ScanOpenPorts',
                '/DockerServerInstances/<instance_id>/Metasploit/<exploit_name>/ExploitInfo'
            ]
        }

        return jsonify(url_error), HttpCodes.BAD_REQUEST

    @app.errorhandler(HttpCodes.METHOD_NOT_ALLOWED)
    def method_not_allowed(self):

        method_not_allowed_err = {
            "Error": f"Method {request.method} is not allowed in URL {request.base_url}",
            "AvailableMethods": "In progress"
        }

        return jsonify(method_not_allowed_err), HttpCodes.METHOD_NOT_ALLOWED

    @app.errorhandler(HttpCodes.BAD_REQUEST)
    def bad_request(self):

        bad_request_error = {
            "Error": "Invalid data type!!"
        }

        return jsonify(bad_request_error), HttpCodes.BAD_REQUEST

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

    def add_all_endpoints(self):
        self._add_container_endpoints()
        self._add_docker_instance_endpoints()
        self._add_metasploit_endpoints()

    def _add_docker_instance_endpoints(self):

        docker_server_controller_kwargs = {'docker_server_implementation': DockerServerServiceImplementation}

        self._api.add_resource(
            InstancesController,
            '/DockerServerInstances/Create',
            endpoint='/DockerServerInstances/Create',
            methods=[HttpMethods.POST],
            resource_class_kwargs=docker_server_controller_kwargs,
        )

        self._api.add_resource(
            InstancesController,
            '/DockerServerInstances/Get',
            endpoint='/DockerServerInstances/Get',
            methods=[HttpMethods.GET],
            resource_class_kwargs=docker_server_controller_kwargs,
        )

        self._api.add_resource(
            InstancesController,
            '/DockerServerInstances/Get/<instance_id>',
            endpoint='/DockerServerInstances/Get/<instance_id>',
            methods=[HttpMethods.GET],
            resource_class_kwargs=docker_server_controller_kwargs,
        )

        self._api.add_resource(
            InstancesController,
            '/DockerServerInstances/Delete/<instance_id>',
            endpoint='/DockerServerInstances/Delete/<instance_id>',
            methods=[HttpMethods.DELETE],
            resource_class_kwargs=docker_server_controller_kwargs,
        )

    def _add_container_endpoints(self):

        container_controller_kwargs = {'container_service_implementation': ContainerServiceImplementation}

        self._api.add_resource(
            ContainersController,
            '/DockerServerInstances/<instance_id>/Containers/Get',
            endpoint='/DockerServerInstances/<instance_id>/Containers/Get',
            methods=[HttpMethods.GET],
            resource_class_kwargs=container_controller_kwargs,
        )

        self._api.add_resource(
            ContainersController,
            '/DockerServerInstances/<instance_id>/Containers/Get/<container_id>',
            endpoint='/DockerServerInstances/<instance_id>/Containers/Get/<container_id>',
            methods=[HttpMethods.GET],
            resource_class_kwargs=container_controller_kwargs,
        )

        self._api.add_resource(
            ContainersController,
            '/DockerServerInstances/<instance_id>/Containers/Delete/<container_id>',
            endpoint='/DockerServerInstances/<instance_id>/Containers/Delete/<container_id>',
            methods=[HttpMethods.DELETE],
            resource_class_kwargs=container_controller_kwargs,
        )

        self._api.add_resource(
            ContainersController,
            '/DockerServerInstances/<instance_id>/Containers/CreateMetasploitContainer',
            endpoint='/DockerServerInstances/<instance_id>/Containers/CreateMetasploitContainer',
            methods=[HttpMethods.POST],
            resource_class_kwargs=container_controller_kwargs,
        )

    def _add_metasploit_endpoints(self):

        metasploit_controller_kwargs = {
            'metasploit_service_implementation': MetasploitServiceImplementation
        }

        self._api.add_resource(
            MetasploitController,
            '/DockerServerInstances/<instance_id>/Metasploit/<target>/RunExploit',
            endpoint='/DockerServerInstances/<instance_id>/Metasploit/<target>/RunExploit',
            methods=[HttpMethods.POST],
            resource_class_kwargs=metasploit_controller_kwargs,
        )

        self._api.add_resource(
            MetasploitController,
            '/DockerServerInstances/<instance_id>/Metasploit/<target>/ScanOpenPorts',
            endpoint='/DockerServerInstances/<instance_id>/Metasploit/<target>/ScanOpenPorts',
            methods=[HttpMethods.GET],
            resource_class_kwargs=metasploit_controller_kwargs,
        )

        self._api.add_resource(
            MetasploitController,
            '/DockerServerInstances/<instance_id>/Metasploit/<exploit_name>/ExploitInfo',
            endpoint='/DockerServerInstances/<instance_id>/Metasploit/<exploit_name>/ExploitInfo',
            methods=[HttpMethods.GET],
            resource_class_kwargs=metasploit_controller_kwargs,
        )


# from metasploit.connections import Metasploit

# source_host = '18.218.217.142'
# m = Metasploit(server=source_host, port=50000)
# target_host = 'google.co.il'
# result = []
# for e in m.exploits[300:500]:
#     try:
#         print(f"sessions {m.metasploit_client.sessions.list}")
#         exploit = m.metasploit_client.modules.use('exploit', mname=e)
#         if 'RHOSTS' in exploit.options:
#             exploit['RHOSTS'] = target_host
#             for p in exploit.targetpayloads():
#                 result.append(exploit.execute(payload=p))
#
#     except Exception as e:
#         print(e)
#
# print(m.exploits)


flask_wrapper = FlaskAppWrapper()
flask_wrapper.add_all_endpoints()
flask_wrapper.run()
