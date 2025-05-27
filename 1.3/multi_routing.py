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
        
        # switch interfaces (gateway_ip, gateway_mac, network)
        self.gateway_interfaces = {
            # OFS1 (dpid=1) is directly connected to Network1, Network2, Network3
            1: [
                ("10.0.1.14", "00:00:00:00:01:0A", ipaddress.IPv4Network('10.0.1.0/28')),
                ("10.0.2.254", "00:00:00:00:01:FE", ipaddress.IPv4Network('10.0.2.0/24')), 
                ("10.0.3.62", "00:00:00:00:03:3E", ipaddress.IPv4Network('10.0.3.0/26')),  
            ],
            # OFS2 (dpid=2) is directly connected to Network2 and Network4
            2: [
                ("10.0.2.252", "00:00:00:00:02:FC", ipaddress.IPv4Network('10.0.2.0/24')), 
                ("10.0.4.2", "00:00:00:00:04:02", ipaddress.IPv4Network('10.0.4.0/30')), 
            ],
        }
        # routing tables for the two switches (network, outPort, nextHop)
        self.routing_table = {
            # OFS1: direct nets 1,2,3; net4 via Network2 (port to OFS2)
            1: [
                (ipaddress.IPv4Network('10.0.1.0/28'), 2, None),  # Network1: /28
                (ipaddress.IPv4Network('10.0.2.0/24'), 1, None),  # Network2: /24
                (ipaddress.IPv4Network('10.0.3.0/26'), 3, None),  # Network3: /26
                (ipaddress.IPv4Network('10.0.4.0/30'), 4, '10.0.2.252'),  # Network4 via OFS2 through Network2
            ],
            # OFS2: direct nets 2,4; net1 & net3 via Network2 (port to OFS1)
            2: [
                (ipaddress.IPv4Network('10.0.1.0/28'), 3, '10.0.2.254'),  # Network1 via OFS1 through Network2
                (ipaddress.IPv4Network('10.0.2.0/24'), 3, '10.0.2.254'),  # Network2: via OFS1 through Network2
                (ipaddress.IPv4Network('10.0.3.0/26'), 3, '10.0.2.254'),  # Network3 via OFS1 through Network2
                (ipaddress.IPv4Network('10.0.4.0/30'), 1, None),  # Network4: /30
            ],
        }

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

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

    def do_arp(self, datapath, pkt, eth, in_port):
        dpid = datapath.id
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        arp_pkt = pkt.get_protocol(arp)
        # Always learn sender
        self.mac_to_port.setdefault(dpid, {})[eth.src] = in_port
        self.ip_to_mac.setdefault(dpid, {})[arp_pkt.src_ip] = eth.src

        # Handle ARP request to gateway IPs
        if arp_pkt.opcode == 1:
            for gw_ip, gw_mac, _ in self.gateway_interfaces[dpid]:
                if arp_pkt.dst_ip == gw_ip:
                    # Send ARP reply from gateway
                    reply = Packet()
                    reply.add_protocol(ethernet.ethernet(
                        ethertype=ether_types.ETH_TYPE_ARP,
                        dst=eth.src, src=gw_mac))
                    reply.add_protocol(arp(opcode=2,
                        src_mac=gw_mac, src_ip=gw_ip,
                        dst_mac=eth.src, dst_ip=arp_pkt.src_ip))
                    self.send_packet(datapath, in_port, reply)
                    return
            # Not a gateway IP, fall through to flood for learning
            self.send_packet(datapath, ofp.OFPP_FLOOD, pkt)
            return

        # Handle ARP reply: learn mapping, no further action needed
        if arp_pkt.opcode == 2:
            # Mapping already learned above
            self.logger.info(f"Learned ARP reply: {arp_pkt.src_ip} -> {eth.src} on port {in_port}")
            return

        self.send_packet(datapath, ofp.OFPP_FLOOD, pkt)

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
        ip_addr = pkt_ipv4.dst
        dpid = datapath.id
        if pkt_icmp.type == icmp.ICMP_ECHO_REQUEST and self.is_gateway_ip(ip_addr, dpid):
            mac_addr = self.get_interface_mac(ip_addr, dpid)
            pkt = packet.Packet()
            pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                            dst=pkt_ethernet.src,
                                            src=mac_addr))
            pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src,
                                    src=ip_addr,
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

    def is_gateway_ip(self, ip, dpid):
        return any(ip == gateway_ip for gateway_ip, _, _ in self.gateway_interfaces[dpid])
    
    def is_gateway_mac(self, mac, dpid):
        return any(mac == gateway_mac for _, gateway_mac, _ in self.gateway_interfaces[dpid])

    def get_interface_mac(self, ip, dpid):
        for gateway_ip, gateway_mac, _ in self.gateway_interfaces[dpid]:
            if gateway_ip == ip:
                return gateway_mac

    def get_transit_interface(self, dpid, next_hop_ip):
        next_hop_addr = ipaddress.IPv4Address(next_hop_ip)
        for gateway_ip, gateway_mac, network in self.gateway_interfaces[dpid]:
            if next_hop_addr in network:
                return (gateway_ip, gateway_mac)
        return None
    
    def get_gateway_mac_for_network(self, dpid, target_network):
        for gateway_ip, gateway_mac, network in self.gateway_interfaces[dpid]:
            if target_network == network:
                return gateway_mac
        return None
            
    def route_packet(self, datapath, msg, pkt, eth, ip_pkt, in_port):
        dpid = datapath.id
        parser = datapath.ofproto_parser
        dst_ip = ipaddress.IPv4Address(ip_pkt.dst)
        self.logger.info(f"route_packet invoked on dpid {dpid} for {dst_ip}")

        # check TTL
        if ip_pkt.ttl <= 1:
            self.logger.info(f"TTL expired for packet from {src_ip} to {dst_ip}, dropping packet")
            return

        # search in the routing table
        for network, out_port, next_hop_ip in self.routing_table.get(dpid, []):
            if dst_ip in network:
                self.logger.info(f"Match in {network}, out_port={out_port}, next_hop={next_hop_ip}")
                next_hop_mac = None

                if next_hop_ip:
                    next_hop_mac = self.ip_to_mac[dpid].get(next_hop_ip)
                    if not next_hop_mac:
                        transit_info = self.get_transit_interface(dpid, next_hop_ip)
                        if transit_info:
                            src_ip, src_mac = transit_info
                            self.send_arp(datapath,
                                        opcode=1,
                                        srcMac=src_mac,
                                        srcIp=src_ip,
                                        dstMac="FF:FF:FF:FF:FF:FF",
                                        dstIp=next_hop_ip,
                                        outPort=out_port)
                            self.logger.info(f"Sent ARP request for next hop {next_hop_ip} via port {out_port}")
                            return False
                        else:
                            self.logger.warning(f"No transit interface found for next hop {next_hop_ip}")
                            return False
                else:
                    # direct connected network
                    next_hop_mac = self.ip_to_mac[dpid].get(ip_pkt.dst)
                    if not next_hop_mac:
                        for gateway_ip, gateway_mac, net in self.gateway_interfaces[dpid]:
                            if net == network:
                                self.send_arp(datapath, 1, gateway_mac, gateway_ip, "FF:FF:FF:FF:FF:FF", str(dst_ip), out_port)
                                self.logger.info(f"Sent ARP request for target {dst_ip} on local network via port {out_port}")
                                return False
                        self.logger.warning(f"No gateway found for network {network}")
                        return False

                # install flow
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_dst=(str(network.network_address), str(network.netmask)))
                actions = []

                # decrement TTL
                actions.append(parser.OFPActionDecNwTtl())

                if next_hop_mac:
                    gateway_mac = self.get_gateway_mac_for_network(dpid, network)
                    if gateway_mac:
                        actions.append(parser.OFPActionSetField(eth_src=gateway_mac))

                    actions.append(parser.OFPActionSetField(eth_dst=next_hop_mac))

                actions.append(parser.OFPActionOutput(out_port))
                
                buffer_id = msg.buffer_id if msg.buffer_id != datapath.ofproto.OFP_NO_BUFFER else None
                self.add_flow(datapath, 10, match, actions, buffer_id=buffer_id)
                self.logger.info(f"Flow installed for {dst_ip}: gateway_mac={gateway_mac}, next_hop_mac={next_hop_mac}, out_port={out_port}")
                return True
            
        self.logger.info(f"No route found for {dst_ip}")
        return False
    

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
            if self.is_gateway_ip(ipv4_pkt.dst, dpid):
                icmp_pkt = pkt.get_protocol(icmp.icmp)
                if icmp_pkt:
                    self.do_icmp(datapath, in_port, eth, ipv4_pkt, icmp_pkt)
                    return
            else:
                # here we would forward the packet into other subnets
                if self.route_packet(datapath, msg, pkt, eth, ipv4_pkt, in_port):
                    return 

        # packet is not for this switch, so do l2 switching
        if not self.is_gateway_mac(dst, dpid):
            self.do_l2_switch(datapath, dpid, pkt, eth, in_port, msg.buffer_id)
            return
        return
