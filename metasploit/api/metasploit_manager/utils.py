from metasploit.api.errors import (
    ModuleOptionsError,
    ModuleNotSupportedError,
    PayloadNotSupportedError,
    MetasploitActionError
)
from metasploit.api.response import HttpCodes


def check_required_options_for_module(required_params, options, module_name):
    """
    Check whether all the required options of the module are filled up by the client.

    Args:
        required_params (list): all the required parameters for the executed module (exploit, auxiliary, etc)
        options (dict): all the parameters that were filled by the client for the module.
        module_name (str): module name.

    Raises:
        ModuleOptionsError: in case the required options for the module were not filled correctly by the client.
    """
    not_in_requirements = []
    for option in options.keys():
        if option not in required_params:
            not_in_requirements.append(option)
    if not_in_requirements:
        raise ModuleOptionsError(options=not_in_requirements, module_name=module_name)


def metasploit_action_verification(func):
    """
    Verifies that the metasploit actions that are performed are valid.

    Args:
        func (Function): metasploit function.
    """
    def wrapper(self, *args, **kwargs):
        """
        Catches error of metasploit actions in case there are any.
        """
        try:
            return func(self, *args, **kwargs)
        except Exception as error:
            raise MetasploitActionError(error_msg=str(error), error_code=HttpCodes.BAD_REQUEST)
    return wrapper


def check_if_module_is_supported(module_name, module_type, metasploit_connection):
    """
    Checks whether module type and name are valid parameters.

    Args:
        module_name (str): module name to be executed. e.g. 'aix/local/ibstat_path'
        module_type (str): module type that module name belong to. e.g. 'exploit'
        metasploit_connection (Metasploit): the metasploit obj.

    Raises:
        ModuleNotSupportedError: in case module type or name are invalid parameters.
    """
    if module_type == 'exploit':
        if module_name not in metasploit_connection.exploits:
            raise ModuleNotSupportedError(module_type=module_type, module_name=module_name)
    elif module_type == 'auxiliary':
        if module_name not in metasploit_connection.auxiliaries:
            raise ModuleNotSupportedError(module_type=module_type, module_name=module_name)
    elif module_type == 'payloads':
        if module_name not in metasploit_connection.payloads:
            raise ModuleNotSupportedError(module_type=module_type, module_name=module_name)
    else:
        raise ModuleNotSupportedError(module_type=module_type)


def check_if_payloads_are_supported(available_payloads, client_payloads):
    """
    Checks whether all the payloads that client sent are valid and supported.

    Args:
        available_payloads (list(str)): a list of all the payloads that are available for the exploit.
        client_payloads (list(str)): a list of all the payloads that were provided by the client.

    Raises:
        PayloadNotSupportedError: in case the client sent unsupported payloads for the exploit
    """
    unsupported_payloads = [payload for payload in client_payloads if payload not in available_payloads]
    if unsupported_payloads:
        raise PayloadNotSupportedError(unsupported_payloads=unsupported_payloads)
