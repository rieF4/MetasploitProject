from metasploit.connections import Metasploit

from . import utils


class ModuleExecution(object):
    """
    This is a class for module execution in metasploit on a container on amazon docker server.
    """
    def __init__(self, target_host, source_host, port):
        """
        Initializes the module execution constructor and implement a connection to the right container with the port.

        Args:
            target_host (str): the target host to "attack". can be either IP/DNS
            source_host (str): the source host that performs the "attack". can be either IP/DNS
            port (int): The port that the msfrpcd listens to.
        """
        self._target_host = target_host
        self._source_host = source_host
        self._metasploit_connection = Metasploit(server=source_host, port=port)

    @property
    def metasploit_connection(self):
        """
        Returns the metasploit connection object.
        """
        return self._metasploit_connection

    def execute_module(self, module_name, module_type):
        """
        Executes the requested module of the metasploit.

        Args:
            module_name (str): module name.
            module_type (str): module type.

        Returns:
            MsfModule: a msfmodule object. e.g. ExploitModule, AuxiliaryModule, PayloadModule.
        """
        utils.check_if_module_is_supported(
            module_name=module_name,
            module_type=module_type,
            metasploit_connection=self.metasploit_connection
        )
        return self.metasploit_connection.modules.use(mtype=module_name, mname=module_type)


class ExploitExecution(ModuleExecution):

    def execute_exploit(self, exploit_name, options, payloads, module_type='exploit'):

        exploit = super().execute_module(module_name=exploit_name, module_type=module_type)
        required_options = exploit.missing_required
        utils.check_required_options_for_module(
            required_params=required_options, options=options, module_name=exploit_name
        )
        utils.check_if_payloads_are_supported(available_payloads=exploit.payloads, client_payloads=payloads)

        for option, option_value in options.items():
            exploit[option] = option_value

        successful_exploits = []
        for payload in payloads:
            executed_exploit = exploit.execute(payload=payload)
            if executed_exploit['job_id']:
                successful_exploits.append(executed_exploit)
        return successful_exploits
