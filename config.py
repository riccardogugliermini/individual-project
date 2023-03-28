
from p4utils.mininetlib.network_API import NetworkAPI

net = NetworkAPI()

net.setCompiler(p4rt=True)


# Network general options
net.setLogLevel('info')

# Network definition
net.addP4RuntimeSwitch('s1')
net.addP4RuntimeSwitch('s2')
net.addP4RuntimeSwitch('s3')
net.setP4Source('s1','/home/user/individual-project/ingress.p4')
net.setP4Source('s2','/home/user/individual-project/egress.p4')
net.setP4Source('s3','/home/user/individual-project/egress.p4')

net.addHost('h1')
net.addHost('h2')
net.addHost('h3')

net.addLink("h1", "s1")
net.addLink("h2", "s2")
net.addLink("h3", "s3")
net.addLink("s1", "s2")
net.addLink("s1", "s3")

net.setBwAll(1000)

# Assignment strategy
net.mixed()

# Nodes general options
net.enablePcapDumpAll()
#net.enableLogAll()
net.enableCli()
net.startNetwork()
