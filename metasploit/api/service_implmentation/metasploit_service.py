from metasploit.api.interfaces.services import MetasploitService
from metasploit.api.database import DatabaseOperations, DatabaseCollections
from metasploit.aws.amazon_operations import DockerServerInstanceOperations
from metasploit.metasploit_manager import module_executor
from metasploit.api import response


class MetasploitServiceImplementation(MetasploitService):

    def __init__(self):
        self.database = DatabaseOperations(collection_type=DatabaseCollections.INSTANCES)

    def scan(self, *args, **kwargs):
        return self.scan_all_ports(**kwargs)

    def run(self, *args, **kwargs):
        return self.run_exploit(**kwargs)

    def info(self, *args, **kwargs):
        return self.get_exploit_info(*args, **kwargs)

    def run_exploit(self, instance_id, exploit_request, target):
        """
        run exploits over a metasploit container with msfrpc daemon connected.

        Example of exploits running request where the key is the target host and the values are exploit's params:

        exploits_requests = {
            "1": {
                "module_type": 'exploit',
                "exploit_name": "aix/local/ibstat_path",
                "payloads": [
                    'cmd/unix/bind_perl',
                    'cmd/unix/bind_perl_ipv6',
                    'cmd/unix/reverse_perl',
                    'cmd/unix/reverse_perl_ssl'
                ],
                "options": {
                    'SESSION': "value1",
                    'WritableDir': "value2"
                }
            },
            "2": {
                "module_type": 'exploit'
                "exploit_name": "aix/rpc_cmsd_opcode21",
                "payloads": [
                    'aix/ppc/shell_bind_tcp',
                    'aix/ppc/shell_reverse_tcp',
                    'generic/custom',
                    'generic/shell_bind_tcp',
                    'generic/shell_reverse_tcp'
                ],
                "options": {
                    'RHOSTS': "value1",
                    'RPORT': "value2",
                    'SSLVERSION': "value3",
                    'ConnectTimeout': "value4",
                    'TIMEOUT': "value5"
                }
            }
        }
        """

        all_payload_exploit_results = module_executor.ExploitExecution(
            target_host=target,
            source_host=DockerServerInstanceOperations(instance_id=instance_id).docker_server.public_ip_address,
            port=50000
        ).execute_exploit(**exploit_request)

        for payload_res in all_payload_exploit_results:
            self.database.add_metasploit_document(metasploit_document=payload_res)

        return all_payload_exploit_results

    def scan_all_ports(self, instance_id, target):
        """
        Gets all the open ports of a target host

        Args:
            instance_id (str): instance ID.
            target (str): target host to scan.

        Returns:
            ApiResponse: api response composed of a list with the open ports, if no open ports then empty list.
        """
        return response.ApiResponse(
            response=module_executor.AuxiliaryExecution(
                target_host=target,
                source_host=DockerServerInstanceOperations(instance_id=instance_id).docker_server.public_ip_address,
                port=50000
            ).port_scanning
        ).make_response

    def get_exploit_info(self, instance_id, exploit_name):
        """
        Gets massive information about an exploit by it's name

        Args:
            instance_id (str): instance ID.
            exploit_name (str): exploit name.

        Returns:
            ApiResponse: api response composed of a dict with the exploit information.
        """
        return response.ApiResponse(
            response=module_executor.ExploitExecution(
                target_host='',
                source_host=DockerServerInstanceOperations(instance_id=instance_id).docker_server.public_ip_address,
                port=50000
            ).exploit_information(exploit_name=exploit_name.replace(" ", "/"))
        ).make_response
