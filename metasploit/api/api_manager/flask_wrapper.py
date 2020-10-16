from flask import Flask, jsonify
from flask_restful import Api

from metasploit.api.response import (
    HttpCodes,
    make_error_response
)
from metasploit.api.errors import (
    ResourceNotFoundError,
    BadJsonInput,
    choose_http_error_code
)


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
            "AvailableUrls": "In progress"
        }

        return jsonify(url_error), 404

    @app.errorhandler(HttpCodes.BAD_REQUEST)
    def method_not_allowed(self):
        method_not_allowed_err = {
            "Error": f"Method {request.method} is not allowed in URL {request.base_url}",
            "AvailableMethods": "In progress"
        }

        return jsonify(method_not_allowed_err), 400

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
                'SecurityGroup.get_security_groups_endpoint',
                SecurityGroup.get_security_groups_endpoint,
                [HttpMethods.GET]
            ),
            (
                '/Instances/Create',
                'Instances.create_instances_endpoint',
                Instances.create_instances_endpoint,
                [HttpMethods.POST]
            )
        ]
        """
        for url_rule, endpoint_name, func, http_methods in add_url_rules_params:
            try:
                self.app.add_url_rule(
                    rule=url_rule, endpoint=endpoint_name, view_func=EndpointAction(func), methods=http_methods
                )
            except Exception as e:
                print(e)


class EndpointAction(object):
    """
    Defines an Endpoint for a specific function for a client.

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
        Standard method that effectively perform the stored function of its endpoint.

        Args:
            args (list): Arguments to give to the stored function.
            kwargs (dict): Keyword arguments to the stored functions.

        Returns:
           tuple (Json, int): an API response to the client.
        """
        # Perform the function
        try:
            return self.function(*args, **kwargs)
        except (ResourceNotFoundError, BadJsonInput) as err:
            http_error = choose_http_error_code(error=err)
            return make_error_response(
                msg=err.__str__(), http_error_code=http_error, req=request.json, path=request.base_url
            )