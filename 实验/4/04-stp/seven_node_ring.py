#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
import time
import os
import filecmp

def clearIP(n):
    for iface in n.intfList():
        n.cmd('ifconfig %s 0.0.0.0' % (iface))
class ringTopo8(Topo):
    def build(self):
        b1 = self.addHost('b1')
        b2 = self.addHost('b2')
        b3 = self.addHost('b3')
        b4 = self.addHost('b4')
        b5 = self.addHost('b5')
        b6 = self.addHost('b6')
        b7 = self.addHost('b7')
        b8 = self.addHost('b8')

        self.addLink(b1, b2)
        self.addLink(b2, b3)
        self.addLink(b3, b4)
        self.addLink(b4, b5)
        self.addLink(b5, b6)
        self.addLink(b6, b7)
        self.addLink(b7, b8)
        self.addLink(b1, b8)
        self.addLink(b1, b3)
        self.addLink(b1, b7)
        self.addLink(b2, b5)
        self.addLink(b3, b7)
        self.addLink(b4, b6)
        self.addLink(b6, b8)
class RingTopo(Topo):
    def build(self):
        b1 = self.addHost('b1')
        b2 = self.addHost('b2')
        b3 = self.addHost('b3')
        b4 = self.addHost('b4')

        self.addLink(b1, b2)
        self.addLink(b1, b3)
        self.addLink(b2, b4)
        self.addLink(b3, b4)

def run(file):
    topo = ringTopo8()
    net = Mininet(topo = topo, controller = None) 

    # dic = { 'b1': 2, 'b2': 2, 'b3': 2, 'b4': 2 }
    nports = [ 2, 2, 2, 2 ,2,2,2,2]

    net = Mininet(topo=topo, controller=None)

    for idx in range(8):
        name = 'b' + str(idx+1)
        node = net.get(name)
        clearIP(node)
        node.cmd('./disable_offloading.sh')
        node.cmd('./disable_ipv6.sh')

        # set mac address for each interface
        for port in range(len(node.intfList())):
            intf = '%s-eth%d' % (name, port)
            mac = '00:00:00:00:0%d:0%d' % (idx+1, port+1)
            node.setMAC(mac, intf=intf)
    b1, b2, b3, b4, b5, b6, b7, b8 = net.get(
        "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8")
    
    for b in [b1, b2, b3, b4, b5, b6, b7, b8]:
        b.cmd('./%s > %s-output.txt 2>&1 &' % (file,b.name))
    time.sleep(20)

    os.system("sudo pkill -SIGTERM %s" % file)
    time.sleep(1)
    net.stop()
    
    os.system("./dump_output.sh 8 >ref.txt")
    os.system("cat dump.txt")
    
    if filecmp.cmp("dump.txt","ref.txt"):
        print("result is true")
        return 1
    else:
        print("result is false")
        return 0
    
if __name__ == "__main__":
    result_list = []
    file = "stp-reference"
    res = run(file)


