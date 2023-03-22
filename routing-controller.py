from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_p4runtime_API import SimpleSwitchP4RuntimeAPI

topo = load_topo('topology.json')

print(topo.get_p4switches()['s1'])

controller1 = SimpleSwitchP4RuntimeAPI(topo.get_p4switch_id('s1'),
                                       topo.get_p4switches()['s1']['grpc_port'],
                                       p4rt_path=topo.get_p4switches()['s1']['p4rt_path'],
                                       json_path=topo.get_p4switches()['s1']['json_path'])
controller2 = SimpleSwitchP4RuntimeAPI(topo.get_p4switch_id('s2'),
                                       topo.get_p4switches()['s2']['grpc_port'],
                                       p4rt_path=topo.get_p4switches()['s2']['p4rt_path'],
                                       json_path=topo.get_p4switches()['s2']['json_path'])
controller3 = SimpleSwitchP4RuntimeAPI(topo.get_p4switch_id('s3'),
                                       topo.get_p4switches()['s3']['grpc_port'],
                                       p4rt_path=topo.get_p4switches()['s3']['p4rt_path'],
                                       json_path=topo.get_p4switches()['s3']['json_path'])
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
                             [str(topo.get_host_mac(neigh)), str(topo.node_to_node_port_num('s1', 's2'))])
        controller2.table_add('egress_ipv4_lpm',
                             'egress_ipv4_forward',
                             [topo.get_host_ip(neigh)],
                             [str(topo.get_host_mac(neigh)), str(topo.node_to_node_port_num('s1', 's2'))])
        controller3.table_add('ipv4_lpm',
                             'ipv4_forward',
                             [topo.get_host_ip(neigh)],
                             [str(topo.get_host_mac(neigh)), str(topo.node_to_node_port_num('s1', 's3'))])
        controller3.table_add('egress_ipv4_lpm',
                             'egress_ipv4_forward',
                             [topo.get_host_ip(neigh)],
                             [str(topo.get_host_mac(neigh)), str(topo.node_to_node_port_num('s1', 's3'))])

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
                             [str(topo.get_host_mac(neigh)), str(topo.node_to_node_port_num('s2', 's1'))])
        controller1.table_add('egress_ipv4_lpm',
                             'egress_ipv4_forward',
                             [topo.get_host_ip(neigh)],
                             [str(topo.get_host_mac(neigh)), str(topo.node_to_node_port_num('s2', 's1'))])
        controller3.table_add('ipv4_lpm',
                             'ipv4_forward',
                             [topo.get_host_ip(neigh)],
                             [str(topo.get_host_mac(neigh)), str(topo.node_to_node_port_num('s2', 's3'))])
        controller3.table_add('egress_ipv4_lpm',
                             'egress_ipv4_forward',
                             [topo.get_host_ip(neigh)],
                             [str(topo.get_host_mac(neigh)), str(topo.node_to_node_port_num('s2', 's3'))])

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
                             [str(topo.get_host_mac(neigh)), str(topo.node_to_node_port_num('s3', 's1'))])
        controller1.table_add('egress_ipv4_lpm',
                             'egress_ipv4_forward',
                             [topo.get_host_ip(neigh)],
                             [str(topo.get_host_mac(neigh)), str(topo.node_to_node_port_num('s3', 's1'))])
        controller2.table_add('ipv4_lpm',
                             'ipv4_forward',
                             [topo.get_host_ip(neigh)],
                             [str(topo.get_host_mac(neigh)), str(topo.node_to_node_port_num('s3', 's2'))])
        controller2.table_add('egress_ipv4_lpm',
                             'egress_ipv4_forward',
                             [topo.get_host_ip(neigh)],
                             [str(topo.get_host_mac(neigh)), str(topo.node_to_node_port_num('s3', 's2'))])
