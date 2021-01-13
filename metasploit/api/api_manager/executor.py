from .flask_wrapper import FlaskAppWrapper
from metasploit.api.utils import (
    HttpMethods
)
from .api_endpoints import (
    SecurityGroupsController,
    InstancesController,
    ContainersController,
    DockerImagesController,
    MetasploitController
)


def str_to_dict(string):
    """
    Args:
        string (str):
    """
    d = {}
    lst =  string.split()
    for l in lst:
        if ":" in l:
            d[l]

import queue
queue.LifoQueue

s = 'VULNERABLE: Apache byterange filter DoS State: VULNERABLE IDs: BID:49303 CVE:CVE-2011-3192 The Apache web server is vulnerable to a denial of service attack when numerous overlapping byte ranges are requested. Disclosure date: 2011-08-19 References: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192 https://www.securityfocus.com/bid/49303 https://seclists.org/fulldisclosure/2011/Aug/175 https://www.tenable.com/plugins/nessus/55976'
r = str_to_dict(string=s)
print()


# from metasploit.connections import Metasploit
#
# source_host = '3.17.4.62'
# m = Metasploit(server=source_host, port=50000)
# target_host = '172.17.0.3'
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
        'SecurityGroupsController.get_security_groups_endpoint',
        SecurityGroupsController.get_security_groups_endpoint,
        [HttpMethods.GET]
    ),
    (
        '/SecurityGroups/Get/<id>',
        'SecurityGroupsController.get_specific_security_group_endpoint',
        SecurityGroupsController.get_specific_security_group_endpoint,
        [HttpMethods.GET]
    ),
    (
        '/SecurityGroups/Create',
        'SecurityGroupsController.create_security_groups_endpoint',
        SecurityGroupsController.create_security_groups_endpoint,
        [HttpMethods.POST]
    ),
    (
        '/SecurityGroups/Delete/<id>',
        'SecurityGroupsController.delete_specific_security_group_endpoint',
        SecurityGroupsController.delete_specific_security_group_endpoint,
        [HttpMethods.DELETE]
    ),
    (
        '/SecurityGroups/<id>/UpdateInboundPermissions',
        'SecurityGroupsController.modify_security_group_inbound_permissions_endpoint',
        SecurityGroupsController.modify_security_group_inbound_permissions_endpoint,
        [HttpMethods.PATCH]
    ),
    (
        '/DockerServerInstances/Create',
        'InstancesController.create_instances_endpoint',
        InstancesController.create_instances_endpoint,
        [HttpMethods.POST]
    ),
    (
        '/DockerServerInstances/Get',
        'InstancesController.get_all_instances_endpoint',
        InstancesController.get_all_instances_endpoint,
        [HttpMethods.GET]
    ),
    (
        '/DockerServerInstances/Get/<id>',
        'InstancesController.get_specific_instance_endpoint',
        InstancesController.get_specific_instance_endpoint,
        [HttpMethods.GET]
    ),
    (
        '/DockerServerInstances/Delete/<id>',
        'InstancesController.delete_instance_endpoint',
        InstancesController.delete_instance_endpoint,
        [HttpMethods.DELETE]
    ),
    (
        '/DockerServerInstances/<id>/Containers/Get',
        'ContainersController.get_all_instance_containers_endpoint',
        ContainersController.get_all_instance_containers_endpoint,
        [HttpMethods.GET]
    ),
    (
        '/DockerServerInstances/<instance_id>/Containers/Get/<container_id>',
        'ContainersController.get_instance_container_endpoint',
        ContainersController.get_instance_container_endpoint,
        [HttpMethods.GET]
    ),
    (
        '/DockerServerInstances/<instance_id>/Containers/Delete/<container_id>',
        'ContainersController.delete_container_endpoint',
        ContainersController.delete_container_endpoint,
        [HttpMethods.DELETE]
    ),
    (
        '/DockerServerInstances/<id>/Images/Pull',
        'DockerImagesController.pull_instance_images_endpoint',
        DockerImagesController.pull_instance_images_endpoint,
        [HttpMethods.POST]
    ),
    (
        '/DockerServerInstances/<instance_id>/Containers/CreateMetasploitContainer',
        'ContainersController.run_container_with_metasploit_daemon_endpoint',
        ContainersController.run_container_with_metasploit_daemon_endpoint,
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
