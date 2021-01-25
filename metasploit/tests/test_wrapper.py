
class TestWrapper(object):

    def __init__(self, test_client, class_type, *class_args, **class_kwargs):
        self._class_type = class_type(test_client=test_client, *class_args, **class_kwargs)

    def post(self, *args, **kwargs):
        return self._class_type.post(*args, **kwargs)

    def get_many(self, *args, **kwargs):
        return self._class_type.get_many(*args, **kwargs)

    def get_one(self, *args, **kwargs):
        return self._class_type.get_one(*args, **kwargs)

    def delete(self, *args, **kwargs):
        return self._class_type.delete(*args, **kwargs)


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
