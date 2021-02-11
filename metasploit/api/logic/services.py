

class Service(object):

    def create(self, *args, **kwargs):
        pass

    def get_all(self, *args, **kwargs):
        pass

    def get_one(self, *args, **kwargs):
        pass

    def delete_one(self, *args, **kwargs):
        pass

    def run(self, *args, **kwargs):
        pass

    def info(self, *args, **kwargs):
        pass


class DockerServerService(Service):

    def get_docker_server(self, instance_id):
        pass

    def get_all_docker_servers(self):
        pass

    def create_docker_server(self, docker_server_json):
        pass

    def delete_docker_server(self, instance_id):
        pass


class ContainerService(Service):

    def get_container(self, instance_id, container_id):
        pass

    def get_all_containers(self, instance_id):
        pass

    def create_metasploit_container(self, instance_id):
        pass

    def delete_container(self, instance_id, container_id):
        pass


class MetasploitService(Service):

    def run_exploit(self, instance_id, exploit_request, target):
        pass


class UserService(Service):

    def create_user(self, *args, **kwargs):
        pass

    def get_user(self, *args, **kwargs):
        pass

    def get_all_users(self, *args, **kwargs):
        pass

    def delete_user(self, *args, **kwargs):
        pass
