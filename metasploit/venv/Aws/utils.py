import paramiko


class SSH:
    """
    This is a class to connect with ssh to the instance
    """

    def __init__(self, hostname, username, private_key):
        self._ssh_client = paramiko.SSHClient()
        self._ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._private_key = paramiko.RSAKey.from_private_key(open(private_key))
        while True:
            try:
                self._ssh_client.connect(hostname=hostname, username=username, pkey=self._private_key)
                break
            except Exception:
                pass
        self._sftp = self._ssh_client.open_sftp()
        print()

    def get_client(self):
        return self._ssh_client

    def get_sftp(self):
        return self._sftp

    def get_private_key(self):
        return self._private_key
