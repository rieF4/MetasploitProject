

EXECUTE_EXPLOIT_URL = "/DockerServerInstances/{instance_id}/Containers/CreateMetasploitContainer"
SCAN_PORTS_URL = "/DockerServerInstances/{instance_id}/Metasploit/{target_host}/ScanOpenPorts"
GET_EXPLOIT_URL = "/DockerServerInstances/{instance_id}/Metasploit/{exploit_name}/ExploitInfo"
GET_PAYLOAD_URL = "/DockerServerInstances/{instance_id}/Metasploit/{payload_name}/PayloadInfo"

INVALID_IP_ADDRESS = "1.2.3.4"
INVALID_DOMAIN_NAME = "walla.blabla"
INVALID_HOST_NAME = "blabla"

VALID_HOST_NAME_1 = "8.8.8.8"
VALID_HOST_NAME_2 = "itsecgames.com"
VALID_HOST_NAME_3 = "defendtheweb.net"
VALID_HOST_NAME_4 = "google-gruyere.appspot.com"
VALID_IP_ADDRESS_5 = "104.20.66.68"

INVALID_EXPLOIT_NAME_1 = "unix.ftp.vsftpd_234_backdoor"
INVALID_EXPLOIT_NAME_2 = "unix/ftp/vsftpd_234_backdoor"
INVALID_EXPLOIT_NAME_3 = "unix ftp vsftpd_234_backdoorr"

VALID_EXPLOIT_NAME_1 = 'windows wins ms04_045_wins'
VALID_EXPLOIT_NAME_2 = 'aix rpc_cmsd_opcode21'
VALID_EXPLOIT_NAME_3 = 'unix ftp vsftpd_234_backdoor'

INVALID_PAYLOAD_NAME_1 = "cmd.unix.interact"
INVALID_PAYLOAD_NAME_2 = "cmd/unix/interact"
INVALID_PAYLOAD_NAME_3 = "cmd unix interactt"

VALID_PAYLOAD_NAME_1 = "windows meterpreter reverse_tcp"
VALID_PAYLOAD_NAME_2 = "cmd unix interact"
VALID_PAYLOAD_NAME_3 = "generic shell_reverse_tcp"

