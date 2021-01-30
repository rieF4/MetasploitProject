
class BaseApiInterface(object):

    def __init__(self, test_client):
        self._test_client = test_client

    def post(self, *args, **kwargs):
        pass

    def get_many(self, *args, **kwargs):
        pass

    def get_one(self, *args, **kwargs):
        pass

    def delete(self, *args, **kwargs):
        pass


class MetasploitApiInterface(BaseApiInterface):

    def scan_ports(self, *args, **kwargs):
        pass

    def get_exploit(self, *args, **kwargs):
        pass

    def get_payload(self, *args, **kwargs):
        pass
