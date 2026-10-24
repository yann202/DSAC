from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.log import setLogLevel

class DSACTopo(Topo):
    def build(self):
        # Domaine A (ONOS)
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        h1 = self.addHost('h1', ip='10.0.1.1/24')
        self.addLink(h1, s1)

        # Domaine B (OpenDaylight)
        s2 = self.addSwitch('s2', protocols='OpenFlow13')
        h2 = self.addHost('h2', ip='10.0.2.1/24')
        self.addLink(h2, s2)

        # Liaison East-West physique entre les deux switchs
        self.addLink(s1, s2)

def run():
    setLogLevel('info')
    topo = DSACTopo()
    net = Mininet(topo=topo, controller=None)
    
    # Connexion aux contrôleurs SDN
    # ONOS écoute généralement sur 6653
    c1 = net.addController('c1', controller=RemoteController, ip='127.0.0.1', port=6653)
    # ODL écoute généralement sur 6633
    c2 = net.addController('c2', controller=RemoteController, ip='127.0.0.1', port=6633)
    
    net.start()
    net.get('s1').start([c1])
    net.get('s2').start([c2])
    
    print("\n[DSAC] Topologie Multi-Domaine Active")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    run()
