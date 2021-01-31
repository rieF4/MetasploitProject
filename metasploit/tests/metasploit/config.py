

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

