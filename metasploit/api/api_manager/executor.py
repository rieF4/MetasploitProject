from .flask_wrapper import FlaskAppWrapper
from metasploit.api.utils import (
    HttpMethods
)
from .api_endpoints import (
    SecurityGroupsApi,
    InstancesApi,
    ContainersApi,
    DockerImagesApi,
    DockerNetworksApi,
    MetasploitController
)

# import metasploit.aws.aws_access as aws_acc
#
# for i in aws_acc.aws_api.resource.instances.all():
#     print(i.state['Name'])
#     print(i.id)

from metasploit.api.database import DatabaseCollections

from pymetasploit3.msfconsole import MsfRpcConsole

from metasploit.connections import Metasploit
#
# global global_positive_out
# global_positive_out = list()
# global global_console_status
# global_console_status = False
#
#
# def read_console(console_data):
#     global global_console_status
#     global_console_status = console_data['busy']
#     if '[+]' in console_data['data']:
#         sigdata = console_data['data'].rstrip().split('\n')
#         for line in sigdata:
#             if '[+]' in line:
#                 global_positive_out.append(line)
#
#
# c = MsfRpcConsole(rpc=m.metasploit_client, cb=read_console)


# print("something")
# m = Metasploit(server='18.189.194.219', port=50000)
# target_host = '172.18.0.3'
# result = []
# for e in m.exploits[300:500]:
#     try:
#         print(f"sessions {m.metasploit_client.sessions.list}")
#         exploit = m.metasploit_client.modules.use('exploit', mname=e)
#         if 'RHOSTS' in exploit.options:
#             exploit['RHOSTS'] = target_host
#             for p in exploit.targetpayloads():
#                 result.append(exploit.execute(payload=p))
#
#     except Exception as e:
#         print(e)
#
# print(m.exploits)


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
    ),
    (
        '/DockerServerInstances/<instance_id>/Networks/Create',
        'DockerNetworksApi.create_network_endpoint',
        DockerNetworksApi.create_network_endpoint,
        [HttpMethods.POST]
    ),
    (
        '/DockerServerInstances/<instance_id>/Metasploit/RunExploit',
        'MetasploitController.run_exploit',
        MetasploitController.run_exploit,
        [HttpMethods.POST]
    ),
    (
        '/DockerServerInstances/<instance_id>/Metasploit/ScanOpenPorts',
        'MetasploitController.scan_ports',
        MetasploitController.scan_ports,
        [HttpMethods.POST]
    )
)
flask_wrapper.run()
