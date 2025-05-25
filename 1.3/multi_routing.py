import ipaddress
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet.arp import arp
from ryu.lib.packet.packet import Packet

class L3Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L3Switch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_to_mac = {}
        
        self.routing_table = {
            1: [  # OFS1
                {'network': '10.0.1.0/28', 'next_hop': None, 'port': 2, 'gateway_ip': '10.0.1.14'},
                {'network': '10.0.2.0/24', 'next_hop': None, 'port': 1, 'gateway_ip': '10.0.2.254'},
                {'network': '10.0.3.0/26', 'next_hop': None, 'port': 3, 'gateway_ip': '10.0.3.62'},
                {'network': '10.0.4.0/30', 'next_hop': '10.0.2.252', 'port': 1, 'gateway_ip': '10.0.2.254'}
            ],
            2: [  # OFS2
                {'network': '10.0.2.0/24', 'next_hop': None, 'port': 2, 'gateway_ip': '10.0.2.252'},
                {'network': '10.0.3.0/26', 'next_hop': '10.0.2.254', 'port': 2, 'gateway_ip': '10.0.2.252'},
                {'network': '10.0.1.0/28', 'next_hop': '10.0.2.254', 'port': 2, 'gateway_ip': '10.0.2.252'},
                {'network': '10.0.4.0/30', 'next_hop': None, 'port': 1, 'gateway_ip': '10.0.4.2'}
            ]
        }
        
        self.gateway_interfaces = {
            1: {  # OFS1
                '10.0.1.14': '52:00:00:00:00:11',
                '10.0.2.254': '52:00:00:00:00:12',
                '10.0.3.62': '52:00:00:00:00:13'
            },
            2: {  # OFS2
                '10.0.2.252': '52:00:00:00:00:21',
                '10.0.4.2': '52:00:00:00:00:23'
            }
        }

        self.gateway_port_mapping = {
            1: {
                '10.0.1.14': 2,
                '10.0.2.254': 1,
                '10.0.3.62': 3
            },
            2: {
                '10.0.4.2': 1
            }
        }

    def initial_setup(self, datapath):
        dpid = datapath.id
        ofproto = datapath.ofproto

        self.logger.info(f"Running initial ARP setup for switch {dpid}")

        if dpid not in self.gateway_port_mapping:
            return
        
        for ip, port in self.gateway_port_mapping[dpid].items():
            src_mac = self.gateway_interfaces[dpid][ip]
            
            # Finde das Netzwerk zu dieser IP in der routing_table
            network = None
            for route in self.routing_table.get(dpid, []):
                if route['gateway_ip'] == ip:
                    network = route['network']
                    break
            
            if network is None:
                self.logger.warning(f"No network found for gateway IP {ip} on switch {dpid}")
                continue
            
            # Wähle eine Ziel-IP für den ARP-Request - z.B. die erste Host-IP im Subnetz
            # Achtung: .hosts() ist ein Generator, konvertiere zu Liste oder nimm next()
            dst_ip = next(ipaddress.ip_network(network).hosts(), None)
            if dst_ip is None:
                self.logger.warning(f"No host IP found in network {network} for ARP request")
                continue

            # Broadcast-ARP-Request auf jedes Subnetz
            self.logger.info(f"Sending ARP request from {ip} ({src_mac}) out of port {port}")
            self.send_arp(
                datapath=datapath,
                opcode=1,
                srcMac=src_mac,
                srcIp=ip,
                dstMac='FF:FF:FF:FF:FF:FF',
                dstIp=dst_ip,  
                outPort=port
                )


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.initial_setup(datapath)

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def send_packet(self, datapath, port, pkt, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt.serialize()
        self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data

        actions = [parser.OFPActionOutput(port=port)]

        if buffer_id:
            out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=buffer_id,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        else:
            out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)

        datapath.send_msg(out)

    def do_arp(self, datapath, packet, frame, inPort):
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        arp_packet = packet.get_protocol(arp)
        src_mac = frame.src
        src_ip = arp_packet.src_ip
        dst_ip = arp_packet.dst_ip
        

        self.mac_to_port.setdefault(dpid, {})
        self.ip_to_mac.setdefault(dpid, {})

        self.mac_to_port[dpid][src_mac] = inPort
        self.ip_to_mac[dpid][src_ip] = src_mac
        self.logger.info(f"Learned ARP: {src_ip} is at {src_mac} on port {inPort}")

        if dst_ip in self.gateway_interfaces.get(dpid, {}):
            reply_mac = self.gateway_interfaces[dpid][dst_ip]

            self.logger.info(f"Send ARP reply from {dst_ip} ({reply_mac}) to {src_ip} ({src_mac})")

            self.send_arp(
                datapath=datapath,
                opcode=2,
                srcMac=reply_mac,
                srcIp=dst_ip,
                dstMac=src_mac,
                dstIp=src_ip,
                outPort=inPort
            )
        else:
            self.logger.info(f"ARP request for unknown IP {dst_ip}, flooding")
            self.send_arp(
                datapath=datapath,
                opcode=1,
                srcMac=src_mac,
                srcIp=src_ip,
                dstMac='FF:FF:FF:FF:FF:FF',
                dstIp=dst_ip,
                outPort=datapath.ofproto.OFPP_FLOOD
            )

    def send_arp(self, datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort):
        if opcode == 1:
            targetMac = "FF:FF:FF:FF:FF:FF"
            targetIp = dstIp
        elif opcode == 2:
            targetMac = dstMac
            targetIp = dstIp
        e = ethernet.ethernet(dstMac, srcMac, ether_types.ETH_TYPE_ARP)
        a = arp(1, 0x0800, 6, 4, opcode, srcMac, srcIp, targetMac, targetIp)
        p = Packet()
        p.add_protocol(e)
        p.add_protocol(a)

        self.send_packet(datapath, outPort, p)

    def do_icmp(self, datapath, port, pkt_ethernet, pkt_ipv4, pkt_icmp):
        if pkt_icmp.type != icmp.ICMP_ECHO_REQUEST:
            return
        
        dpid = datapath.id
        src_mac = self.gateway_interfaces[dpid][pkt_ipv4.dst]
        src_ip = pkt_ipv4.dst

        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                           dst=pkt_ethernet.src,
                                           src=src_mac))
        pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src,
                                   src=src_ip,
                                   proto=pkt_ipv4.proto))
        pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,
                                   code=icmp.ICMP_ECHO_REPLY_CODE,
                                   csum=0,
                                   data=pkt_icmp.data))
        self.logger.info("do icmp: %s" %(pkt,))
        self.send_packet(datapath, port, pkt)

    def do_l2_switch(self, datapath, dpid, packet, frame, in_port, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if frame.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][frame.dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=frame.dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if buffer_id == ofproto.OFP_NO_BUFFER:
            data = packet.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def find_route(self, dpid, dst_ip_str):
        ip_dst = ipaddress.ip_address(dst_ip_str)
        best_match = None
        for entry in self.routing_table.get(dpid, []):
            if ip_dst in ipaddress.ip_network(entry['network']):
                if not best_match or entry['network'].prefixlen > best_match['network'].prefixlen:
                    best_match = entry
        return best_match  # kann None sein, wenn kein Match gefunden wurde

    def do_ip(self, datapath, in_port, pkt, eth, ip_packet):
        dpid = datapath.id
        dst_ip = ip_packet.dst
        src_ip = ip_packet.src

        route = self.find_route(dpid, dst_ip)
        if not route:
            self.logger.warning(f"No route for {dst_ip} on switch {dpid}")
            return
        
        next_ip = dst_ip if route['next_hop'] is None else route['next_hop']
        out_port = route['port']

        gateway_ip_str = route['gateway_ip']
        src_mac = self.gateway_interfaces[dpid].get(gateway_ip_str)

        if not src_mac:
            self.logger.warning(f"No source MAC known for gateway IP {gateway_ip_str} on switch {dpid}")
            return
        

        # MAC already known?
        if next_ip in self.ip_to_mac[dpid]:
            dst_mac = self.ip_to_mac[dpid][next_ip]

            new_eth = ethernet.ethernet(dst=dst_mac, src=src_mac, ethertype=eth.ethertype)
            new_packet = packet.Packet()
            new_packet.add_protocol(new_eth)
            new_packet.add_protocol(ip_packet)
            new_packet.serialize()

            self.send_packet(datapath=datapath, port=out_port, pkt=new_packet)
            self.logger.info(f"Sent IP packet from {src_ip} to {dst_ip} via port {out_port} (next hop: {next_ip})")
        else:
            # MAC unknown => send ARP request
            self.logger.info(f"MAC for {next_ip} unknown, sending ARP")
            self.send_arp(datapath, opcode=1,
                        srcMac=src_mac,
                        srcIp=gateway_ip_str,
                        dstMac="FF:FF:FF:FF:FF:FF",
                        dstIp=next_ip,
                        outPort=out_port)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.ip_to_mac.setdefault(dpid, {})

        self.logger.info("packet in dpid: %s, src: %s, dest: %s, in_port: %s", dpid, src, dst, in_port)

        #learn mac to port mapping
        if src not in self.mac_to_port[dpid]:
            self.mac_to_port[dpid][src] = in_port

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.do_arp(datapath, pkt, eth, in_port)
            return

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ipv4_pkt = pkt.get_protocol(ipv4.ipv4)


            #check if packet is for this switch
            if str(ipv4_pkt.dst) in self.gateway_interfaces.get(dpid):
                icmp_pkt = pkt.get_protocol(icmp.icmp)
                self.logger.info(f"ICMP packet: {icmp_pkt}")
                if icmp_pkt:
                    self.do_icmp(datapath, in_port, eth, ipv4_pkt, icmp_pkt)
            else:
                # here we would forward the packet into other subnets
                self.do_ip(datapath=datapath, in_port=in_port, pkt=pkt, eth=eth, ip_packet=ipv4_pkt)

        # L2-Switching nur, wenn Ziel nicht eine unserer Gateway-MACs ist
        if dst not in self.gateway_interfaces.get(dpid, {}).values():
            self.do_l2_switch(datapath, dpid, pkt, eth, in_port, msg.buffer_id)
        return
