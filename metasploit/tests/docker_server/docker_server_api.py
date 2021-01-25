import logging

from metasploit.tests.test_wrapper import BaseApiInterface
from metasploit.tests import constants as test_const
from metasploit.tests.helpers import convert

logger = logging.getLogger("DockerServerApi")


class DockerServerApi(BaseApiInterface):

    def post(
            self,
            num_of_docker_servers_to_create=1,
            create_docker_server_url=test_const.CREATE_DOCKER_SERVER,
            create_docker_server_request=test_const.CREATE_DOCKER_SERVER_REQUEST
    ):
        """
        Sends a POST request in order to create new docker servers.

        Args:
            num_of_docker_servers_to_create (int): number of docker servers to create.
            create_docker_server_url (str): the URL to create a docker server.
            create_docker_server_request (dict): the request to create a docker server.

        Returns:
            list[tuple[dict, int]]: a list of tuples containing the data response and status code of each post request
            where the first argument in the tuple is the data and the second argument is the status code.
        """
        all_created_instances = []

        for docker_server_num in range(1, num_of_docker_servers_to_create + 1):

            logger.info(
                f"create the {docker_server_num} num docker server using POST, "
                f"URL: {create_docker_server_url}, REQUEST: {create_docker_server_request}"
            )

            new_docker_instance_response = self._test_client.post(
                create_docker_server_url, json=create_docker_server_request
            )
            data_response = convert(response_as_bytes=new_docker_instance_response.data)
            status_code = new_docker_instance_response.status_code

            all_created_instances.append((data_response, status_code))

        return all_created_instances

    def get_many(self, *args, **kwargs):
        """
        Sends a GET request to retrieve all the docker server instances available.

        Returns:
            tuple[list[dict], int]: a tuple containing the data response as a first arg, and status code as second arg.
        """
        get_all_docker_servers_url = test_const.GET_ALL_DOCKER_SERVERS

        logger.info(f"Get all the docker servers using GET, URL: {get_all_docker_servers_url}")

        all_available_instances = self._test_client.get(get_all_docker_servers_url)
        data_response = convert(response_as_bytes=all_available_instances.data)
        status_code = all_available_instances.status_code

        return data_response, status_code

    def get_one(self, instance_id):
        """
        Sends a GET request to retrieve a docker server instance.

        Args:
            instance_id (str): instance ID.

        Returns:
            tuple[dict, int]: a tuple containing the data response as a first arg, and status code as second arg.
        """
        get_docker_server_url = test_const.GET_DOCKER_SERVER.format(instance_id=instance_id)

        logger.info(f"Get a docker server using GET, URL: {get_docker_server_url}")

        docker_instance = self._test_client.get(get_docker_server_url)
        data_response = convert(response_as_bytes=docker_instance.data)
        status_code = docker_instance.status_code

        return data_response, status_code

    def delete(self, instance_id):
        """
        Sends a DELETE request to delete a docker server instance.

        Args:
            instance_id (str): instance ID.

        Returns:
            tuple[dict, int]: a tuple containing the data response as first arg, and status code as second arg.
        """
        delete_docker_server_url = test_const.DELETE_DOCKER_SERVER.format(instance_id=instance_id)

        logger.info(f"Delete a docker server using DELETE, URL: {delete_docker_server_url}")

        delete_response = self._test_client.delete(delete_docker_server_url)
        data_response = '{}'
        # data_response = convert(response_as_bytes=delete_response.data)
        status_code = delete_response.status_code

        return data_response, status_code
