

class ServiceWrapper(object):

    def __init__(self, class_type, *args, **kwargs):
        self._class_type = class_type(*args, **kwargs)

    @property
    def class_type(self):
        return self._class_type

    def create(self, *args, **kwargs):
        return self.class_type.create(*args, **kwargs)

    def get_all(self, *args, **kwargs):
        return self.class_type.get_all(*args, **kwargs)

    def get_one(self, *args, **kwargs):
        return self.class_type.get_one(*args, **kwargs)

    def delete_one(self, *args, **kwargs):
        return self.class_type.delete_one(*args, **kwargs)

    def run(self, *args, **kwargs):
        return self.class_type.run(*args, **kwargs)

    def info(self, *args, **kwargs):
        return self.class_type.info(*args, **kwargs)
