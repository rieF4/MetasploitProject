
from .flask_wrapper import FlaskAppWrapper
from metasploit.api.utils import (
    HttpMethods
)
from .api_endpoints import (
    SecurityGroupsApi,
    InstancesApi,
    ContainersApi,
    DockerImagesApi
)

# class a(object):
#
#     def __init__(self, n):
#         self._n = n
#
#     @property
#     def b(self):
#         return self._n
#
#
# class c(a):
#     def __init__(self, n, p):
#         super(c, self).__init__(n=n)
#         self.p = p
#
#     def d(self):
#         print("bla")
#
# y = c(n=4, p=5)
# print(y.)

flask_wrapper = FlaskAppWrapper()
flask_wrapper.add_endpoints(
    (
        '/SecurityGroups/Get',
        'SecurityGroupsApi.get_security_groups_endpoint',
        SecurityGroupsApi.get_security_groups_endpoint,
        [HttpMethods.GET]
    ),
    (
    '/SecurityGroups/Get/<id>',
        'SecurityGroupsApi.get_specific_security_group_endpoint',
        SecurityGroupsApi.get_specific_security_group_endpoint,
        [HttpMethods.GET]
    ),
    (
        '/SecurityGroups/Create',
        'SecurityGroupsApi.create_security_groups_endpoint',
        SecurityGroupsApi.create_security_groups_endpoint,
        [HttpMethods.POST]
    ),
    (
        '/SecurityGroups/Delete/<id>',
        'SecurityGroupsApi.delete_specific_security_group_endpoint',
        SecurityGroupsApi.delete_specific_security_group_endpoint,
        [HttpMethods.DELETE]
    ),
    (
        '/SecurityGroups/<id>/UpdateInboundPermissions',
        'SecurityGroupsApi.modify_security_group_inbound_permissions_endpoint',
        SecurityGroupsApi.modify_security_group_inbound_permissions_endpoint,
        [HttpMethods.PATCH]
    ),
    (
        '/DockerServerInstances/Create',
        'InstancesApi.create_instances_endpoint',
        InstancesApi.create_instances_endpoint,
        [HttpMethods.POST]
    ),
    (
        '/DockerServerInstances/Get',
        'InstancesApi.get_all_instances_endpoint',
        InstancesApi.get_all_instances_endpoint,
        [HttpMethods.GET]
    ),
    (
        '/DockerServerInstances/Get/<id>',
        'InstancesApi.get_specific_instance_endpoint',
        InstancesApi.get_specific_instance_endpoint,
        [HttpMethods.GET]
    ),
    (
        '/DockerServerInstances/Delete/<id>',
        'InstancesApi.delete_instance_endpoint',
        InstancesApi.delete_instance_endpoint,
        [HttpMethods.DELETE]
    ),
    (
        '/DockerServerInstances/<id>/CreateContainers',
        'ContainersApi.create_containers_endpoint',
        ContainersApi.create_containers_endpoint,
        [HttpMethods.POST]
    ),
    (
        '/DockerServerInstances/<id>/Containers/Get',
        'ContainersApi.get_all_instance_containers_endpoint',
        ContainersApi.get_all_instance_containers_endpoint,
        [HttpMethods.GET]
    ),
    (
        '/DockerServerInstances/<instance_id>/Containers/Get/<container_id>',
        'ContainersApi.get_instance_container_endpoint',
        ContainersApi.get_instance_container_endpoint,
        [HttpMethods.GET]
    ),
    (
        '/DockerServerInstances/Containers/Get',
        'ContainersApi.get_all_instances_containers_endpoint',
        ContainersApi.get_all_instances_containers_endpoint,
        [HttpMethods.GET]
    ),
    (
        '/DockerServerInstances/<instance_id>/Containers/Delete/<container_id>',
        'ContainersApi.delete_container_endpoint',
        ContainersApi.delete_container_endpoint,
        [HttpMethods.DELETE]
    ),
    (
        '/DockerServerInstances/<instance_id>/Containers/Start/<container_id>',
        'ContainersApi.start_container_endpoint',
        ContainersApi.start_container_endpoint,
        [HttpMethods.PATCH],
    ),
    (
        '/DockerServerInstances/<id>/Images/Pull',
        'DockerImagesApi.pull_instance_images_endpoint',
        DockerImagesApi.pull_instance_images_endpoint,
        [HttpMethods.POST]
    ),
    (
        '/DockerServerInstances/<instance_id>/Images/Get',
        'DockerImagesApi.get_instance_images_endpoint',
        DockerImagesApi.get_instance_images_endpoint,
        [HttpMethods.GET]
    ),
    (
        '/DockerServerInstances/<instance_id>/Containers/ExecuteCommand/<container_id>',
        'ContainersApi.execute_command_endpoint',
        ContainersApi.execute_command_endpoint,
        [HttpMethods.PATCH]
    ),
    (
        '/DockerServerInstances/<instance_id>/Containers/CreateMetasploitContainer',
        'ContainersApi.run_container_with_metasploit_daemon_endpoint',
        ContainersApi.run_container_with_metasploit_daemon_endpoint,
        [HttpMethods.POST]
    )
)
flask_wrapper.run()
