#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.node import RemoteController, Host, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def myNetwork():

    net = Mininet(
        topo=None,
        build=False,
        ipBase='10.0.0.0/8'
    )

    info('*** Adding controller\n')
    c0 = net.addController(
        name='c0',
        controller=RemoteController,
        ip='127.0.0.1',
        protocol='tcp',
        port=6653
    )

    info('*** Add switches\n')
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch)

    info('*** Add hosts\n')
    h1 = net.addHost('h1', cls=Host, ip='10.0.0.1', mac='02:00:00:00:00:01', defaultRoute=None)
    srv1 = net.addHost('srv1', cls=Host, ip='10.0.0.2', mac='02:00:00:00:00:02', defaultRoute=None)
    srv2 = net.addHost('srv2', cls=Host, ip='10.0.0.3', mac='02:00:00:00:00:03', defaultRoute=None)
    srv3 = net.addHost('srv3', cls=Host, ip='10.0.0.4', mac='02:00:00:00:00:04', defaultRoute=None)

    info('*** Add links\n')
    net.addLink(h1, s2)
    net.addLink(srv1, s2)
    net.addLink(srv2, s2)
    net.addLink(srv3, s2)

    info('*** Starting network\n')
    net.build()
    info('*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info('*** Starting switches\n')
    net.get('s2').start([c0])

    info('*** Post configure switches and hosts\n')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    myNetwork()
