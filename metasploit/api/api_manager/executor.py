
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

# import metasploit.aws.aws_access as aws_acc
#
# for i in aws_acc.aws_api.resource.instances.all():
#     print(i.state['Name'])
#     print(i.id)

from metasploit.api.database import DatabaseCollections

# from metasploit.connections import Metasploit
#
# m = Metasploit(server='ec2-13-59-38-180.us-east-2.compute.amazonaws.com', port=50000)
# print(m.exploits)

"""
Given this array how to update operation on containers
"""

# d = {
#     "Containers": [
#         {
#             "_id": 1,
#             "state": "running"
#         },
#         {
#             "_id": 2,
#             "state": "stopped"
#         }
#     ],
#     "Images": [],
#     "Networks": [],
#     "IpParameters": {
#         "PrivateDNSName": "ip-172-31-32-241.us-east-2.compute.internal",
#         "PrivateIpAddress": "172.31.32.241",
#         "PublicDNSName": "ec2-18-220-31-187.us-east-2.compute.amazonaws.com",
#         "PublicIpAddress": "18.220.31.187"
#       },
#     "KeyName": "default_key_pair_name",
#     "SecurityGroups": [
#         {
#           "GroupId": "sg-0cde419d7de10fff7",
#           "GroupName": "zzz"
#         }
#       ],
#     "State": {
#         "Code": 16,
#         "Name": "running"
#     },
#     "_id": "i-086d96f9de57d095b"
#     }
#
#
# test = DatabaseCollections.INSTANCES


"""
How to remove a container from DB
"""
# test.update_one(
#     filter={
#         "_id": "i-086d96f9de57d095b"
#     },
#     update={
#         "$pull": {
#             "Containers": {
#                 "_id": 2
#             }
#         }
#     }
# )


"""
Add a container to DB example
"""
# test.update_one(
#     filter={
#         "_id": "i-086d96f9de57d095b"
#     },
#     update={
#         "$addToSet": {
#             "Containers": {
#                 "_id": 3,
#                 "state": "running"
#             }
#         }
#     }
# )


"""
Update containers state in DB example
"""
# ids = [i['_id'] for i in d["Containers"]]
# print(ids)
#
# for i in ids:
#     test.update_one(
#         filter={
#             "_id": "i-086d96f9de57d095b",
#             "Containers._id": i
#         },
#         update={
#             "$set": {
#                 "Containers.$.state": "stopped"
#             }
#         }
#     )



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
