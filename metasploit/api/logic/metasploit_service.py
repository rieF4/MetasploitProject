from metasploit.api.logic.services import MetasploitService
from metasploit.api.database import DatabaseOperations, DatabaseCollections
from metasploit.api.aws.amazon_operations import DockerServerInstanceOperations
from metasploit.api.utils.decorators import validate_json_request


class MetasploitServiceImplementation(MetasploitService):
    """
    Implements the metasploit service.

    Attributes:
        database (DatabaseOperations): DatabaseOperations object.
        module: (MetasploitModule): metasploit module subclass object, e.g.: PayLoad, PortScanning, Exploit
        docker_server (DockerServerInstance): a docker server object where the metasploit operations will be executed.
    """
    def __init__(self, module, *args, **kwargs):
        self.database = DatabaseOperations(collection_type=DatabaseCollections.INSTANCES)

        instance_id = kwargs.pop("instance_id")
        self.database.get_amazon_document(resource_id=instance_id)

        self.docker_sever = DockerServerInstanceOperations(instance_id=instance_id).docker_server
        self.module = module(source_host=self.docker_sever.public_ip_address, *args, **kwargs)

    def run(self, *args, **kwargs):
        return self.run_exploit(*args, **kwargs)

    def info(self, *args, **kwargs):
        """
        Gets information about a module (Exploit, Payload, PortScanning) parameters.
        """
        return self.module.info(*args, **kwargs)

    @validate_json_request("name", "payloads", "options")
    def run_exploit(self, exploit_request):
        """
        run exploits over a metasploit container with msfrpc daemon connected.

        Args:
            exploit_request (dict): exploit details from the client.

        Returns:
            list(dict): a list with all the successful payloads information.

        Example of exploits running request where the key is the target host and the values are exploit's params:

        exploits_request = {
            "exploit_name": "unix/ftp/vsftpd_234_backdoor",
            "payloads": {
                "cmd/unix/interact": {
                    "option1": "value1",
                    "option2": value2"
                }
            },
            "options": {
                "RHOSTS": "target IP/DNS"
            }
        }
        """
        exploit_results = self.module.execute(**exploit_request)

        for exploit_details in exploit_results:
            self.database.add_metasploit_document(
                amazon_resource_id=self.docker_sever.instance_id, metasploit_document=exploit_details)
        return exploit_results
