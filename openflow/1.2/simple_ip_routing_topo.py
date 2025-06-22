#!/usr/bin/env python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call

def myNetwork():

    net = Mininet( topo=None,
                   build=False,
                   ipBase='10.0.0.0/8')

    info( '*** Adding controller\n' )
    c6=net.addController(name='c6',
                      controller=RemoteController,
                      ip='127.0.0.1',
                      protocol='tcp',
                      port=6633)

    info( '*** Add switches\n')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch)

    info( '*** Add hosts\n')
    h1 = net.addHost('h1', cls=Host, ip='10.0.1.1', defaultRoute='via 10.0.1.254')
    h2 = net.addHost('h2', cls=Host, ip='10.0.1.2', defaultRoute='via 10.0.1.254')
    h3 = net.addHost('h3', cls=Host, ip='10.0.1.3', defaultRoute='via 10.0.1.254')
    h4 = net.addHost('h4', cls=Host, ip='10.0.1.4', defaultRoute='via 10.0.1.254')
    h5 = net.addHost('h5', cls=Host, ip='10.0.2.1', defaultRoute='via 10.0.2.254')
    h6 = net.addHost('h6', cls=Host, ip='10.0.2.2', defaultRoute='via 10.0.2.254')
    h7 = net.addHost('h7', cls=Host, ip='10.0.2.3', defaultRoute='via 10.0.2.254')
    h8 = net.addHost('h8', cls=Host, ip='10.0.2.4', defaultRoute='via 10.0.2.254')

    info( '*** Add links\n')
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s1)
    net.addLink(h5, s1)
    net.addLink(h6, s1)
    net.addLink(h7, s1)
    net.addLink(h8, s1)

    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('s1').start([c6])

    info( '*** Post configure switches and hosts\n')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()

