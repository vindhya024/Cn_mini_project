from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel

def start_topology():
    net = Mininet(switch=OVSSwitch)

    # Single SDN Switch
    s1 = net.addSwitch('s1', failMode='standalone')

    # Server Host (h1) and Single Client Host (h2)
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')

    # Connect hosts to switch
    net.addLink(h1, s1)
    net.addLink(h2, s1)

    net.start()
    print("\n[MININET] Topology Ready: h1 (Server: 10.0.0.1) <---> s1 <---> h2 (Client: 10.0.0.2)")
    print("[MININET] Run 'xterm h1 h2' to open separate terminals.\n")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    start_topology()
