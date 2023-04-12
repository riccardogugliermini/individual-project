from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_p4runtime_API import SimpleSwitchP4RuntimeAPI

topo = load_topo('topology.json')

print(topo.get_p4rtswitches()['s1'])

# s1
controller1 = SimpleSwitchP4RuntimeAPI(topo.get_p4rtswitches()['s1']['device_id'],
                                       topo.get_grpc_port('s1'),
                                       p4rt_path=topo.get_p4rtswitches()['s1']['p4rt_path'],
                                       json_path=topo.get_p4switches()['s1']['json_path'])

# s2
controller2 = SimpleSwitchP4RuntimeAPI(topo.get_p4rtswitches()['s2']['device_id'],
                                       topo.get_grpc_port('s2'),
                                       p4rt_path=topo.get_p4rtswitches()['s2']['p4rt_path'],
                                       json_path=topo.get_p4switches()['s2']['json_path'])

# s3
controller3 = SimpleSwitchP4RuntimeAPI( topo.get_p4rtswitches()['s3']['device_id'],
                                       topo.get_grpc_port('s3'),
                                       p4rt_path=topo.get_p4rtswitches()['s3']['p4rt_path'],
                                       json_path=topo.get_p4switches()['s3']['json_path'])


# add h1, h2, h3 to s1 routing table
for neigh in topo.get_neighbors('s1'):
    if topo.isHost(neigh):
        controller1.table_add('ipv4_lpm',
                             'ipv4_forward',
                             [topo.get_host_ip(neigh)],
                             [str(topo.get_host_mac(neigh)), str(topo.node_to_node_port_num('s1', neigh))])
        controller1.table_add('egress_ipv4_lpm',
                             'egress_ipv4_forward',
                             [topo.get_host_ip(neigh)],
                             [str(topo.get_host_mac(neigh)), str(topo.node_to_node_port_num('s1', neigh))])
        controller2.table_add('ipv4_lpm',
                             'ipv4_forward',
                             [topo.get_host_ip(neigh)],
                             [str(topo.get_host_mac(neigh)), str(topo.node_to_node_port_num('s2', 's1'))])
        controller2.table_add('egress_ipv4_lpm',
                             'egress_ipv4_forward',
                             [topo.get_host_ip(neigh)],
                             [str(topo.get_host_mac(neigh)), str(topo.node_to_node_port_num('s2', 's1'))])
        controller3.table_add('ipv4_lpm',
                             'ipv4_forward',
                             [topo.get_host_ip(neigh)],
                             [str(topo.get_host_mac(neigh)), str(topo.node_to_node_port_num('s3', 's1'))])
        controller3.table_add('egress_ipv4_lpm',
                             'egress_ipv4_forward',
                             [topo.get_host_ip(neigh)],
                             [str(topo.get_host_mac(neigh)), str(topo.node_to_node_port_num('s3', 's1'))])

# add h1, h2 to s2 routing table
for neigh in topo.get_neighbors('s2'):
    if topo.isHost(neigh):
        controller2.table_add('ipv4_lpm',
                             'ipv4_forward',
                             [topo.get_host_ip(neigh)],
                             [str(topo.get_host_mac(neigh)), str(topo.node_to_node_port_num('s2', neigh))])
        controller2.table_add('egress_ipv4_lpm',
                             'egress_ipv4_forward',
                             [topo.get_host_ip(neigh)],
                             [str(topo.get_host_mac(neigh)), str(topo.node_to_node_port_num('s2', neigh))])
        controller1.table_add('ipv4_lpm',
                             'ipv4_forward',
                             [topo.get_host_ip(neigh)],
                             [str(topo.get_host_mac(neigh)), str(topo.node_to_node_port_num('s1', 's2'))])
        controller1.table_add('egress_ipv4_lpm',
                             'egress_ipv4_forward',
                             [topo.get_host_ip(neigh)],
                             [str(topo.get_host_mac(neigh)), str(topo.node_to_node_port_num('s1', 's2'))])
        # controller3.table_add('ipv4_lpm',
        #                      'ipv4_forward',
        #                      [topo.get_host_ip(neigh)],
        #                      [str(topo.get_host_mac(neigh)), str(topo.node_to_node_port_num('s2', 's3'))])
        # controller3.table_add('egress_ipv4_lpm',
        #                      'egress_ipv4_forward',
        #                      [topo.get_host_ip(neigh)],
        #                      [str(topo.get_host_mac(neigh)), str(topo.node_to_node_port_num('s2', 's3'))])


# add h1, h3 to s3 routing table
for neigh in topo.get_neighbors('s3'):
    if topo.isHost(neigh):
        controller3.table_add('ipv4_lpm',
                             'ipv4_forward',
                             [topo.get_host_ip(neigh)],
                             [str(topo.get_host_mac(neigh)), str(topo.node_to_node_port_num('s3', neigh))])
        controller3.table_add('egress_ipv4_lpm',
                             'egress_ipv4_forward',
                             [topo.get_host_ip(neigh)],
                             [str(topo.get_host_mac(neigh)), str(topo.node_to_node_port_num('s3', neigh))])
        controller1.table_add('ipv4_lpm',
                             'ipv4_forward',
                             [topo.get_host_ip(neigh)],
                             [str(topo.get_host_mac(neigh)), str(topo.node_to_node_port_num('s1', 's3'))])
        controller1.table_add('egress_ipv4_lpm',
                             'egress_ipv4_forward',
                             [topo.get_host_ip(neigh)],
                             [str(topo.get_host_mac(neigh)), str(topo.node_to_node_port_num('s1', 's3'))])
        # controller2.table_add('ipv4_lpm',
        #                      'ipv4_forward',
        #                      [topo.get_host_ip(neigh)],
        #                      [str(topo.get_host_mac(neigh)), str(topo.node_to_node_port_num('s3', 's2'))])
        # controller2.table_add('egress_ipv4_lpm',
        #                      'egress_ipv4_forward',
        #                      [topo.get_host_ip(neigh)],
        #                      [str(topo.get_host_mac(neigh)), str(topo.node_to_node_port_num('s3', 's2'))])
