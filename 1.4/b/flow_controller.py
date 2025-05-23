#!/usr/bin/env python3
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, tcp, ether_types
import random

class FlowAnycast(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FlowAnycast, self).__init__(*args, **kwargs)
        self.anycast_ip = '10.0.0.100'
        self.anycast_mac = '00:00:00:00:AA:BB'
        self.server_ips = ['10.0.0.2', '10.0.0.3', '10.0.0.4']
        self.server_macs = [
            '02:00:00:00:00:02',
            '02:00:00:00:00:03',
            '02:00:00:00:00:04',
        ]
        self.ip_to_port = {
            '10.0.0.2': 2,
            '10.0.0.3': 3,
            '10.0.0.4': 4,
        }
        self.flow_table = {}

    def _get_flow_key(self, pkt_ipv4, pkt_tcp):
        return (
            pkt_ipv4.src, pkt_tcp.src_port,
            pkt_ipv4.dst, pkt_tcp.dst_port,
            pkt_ipv4.proto
        )

    def _get_server_for_flow(self, flow_key):
        if flow_key not in self.flow_table:
            server_index = random.randint(0, len(self.server_ips) - 1)
            self.flow_table[flow_key] = server_index
        return self.flow_table[flow_key]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=0, match=match, instructions=inst))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if not eth_pkt:
            return

        arp_pkt = pkt.get_protocol(arp.arp)
        ip4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        if arp_pkt:
            if arp_pkt.opcode == arp.ARP_REQUEST and arp_pkt.dst_ip == self.anycast_ip:
                self.logger.info("ARP-Anycast: Replying %s -> %s (Anycast MAC %s)",
                                 arp_pkt.src_ip, self.anycast_ip, self.anycast_mac)
                
                eth_reply = ethernet.ethernet(
                    ethertype=ether_types.ETH_TYPE_ARP,
                    dst=eth_pkt.src,
                    src=self.anycast_mac
                )
                arp_reply_pkt = arp.arp(
                    opcode=arp.ARP_REPLY,
                    src_mac=self.anycast_mac,
                    src_ip=self.anycast_ip,
                    dst_mac=arp_pkt.src_mac,
                    dst_ip=arp_pkt.src_ip
                )
                
                reply = packet.Packet()
                reply.add_protocol(eth_reply)
                reply.add_protocol(arp_reply_pkt)
                reply.serialize()
                
                actions = [parser.OFPActionOutput(in_port)]
                out = parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                                          in_port=ofp.OFPP_CONTROLLER, actions=actions, data=reply.data)
                dp.send_msg(out)
                return
            else:
                self.logger.info("ARP: Flooding ARP packet from %s (In-Port %d, Dst-IP %s)",
                                 eth_pkt.src, in_port, arp_pkt.dst_ip if arp_pkt else "N/A")
                actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
                out = parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                                          in_port=in_port, actions=actions, data=msg.data)
                dp.send_msg(out)
                return
        
        if ip4_pkt and tcp_pkt and ip4_pkt.dst == self.anycast_ip:
            client_ip = ip4_pkt.src
            client_tcp_src_port = tcp_pkt.src_port
            anycast_tcp_dst_port = tcp_pkt.dst_port

            flow_key = self._get_flow_key(ip4_pkt, tcp_pkt)
            
            if flow_key not in self.flow_table or tcp_pkt.has_flags(tcp.TCP_SYN) and not tcp_pkt.has_flags(tcp.TCP_ACK):
                server_idx = self._get_server_for_flow(flow_key)
                
                target_server_ip = self.server_ips[server_idx]
                target_server_mac = self.server_macs[server_idx]
                target_server_switch_port = self.ip_to_port[target_server_ip]

                self.logger.info(
                    "Flow-Anycast: Client %s:%d -> Anycast %s:%d mapped to Server %s/%s (Switch-Port %d). In_port Client: %d",
                    client_ip, client_tcp_src_port, self.anycast_ip, anycast_tcp_dst_port,
                    target_server_ip, target_server_mac, target_server_switch_port, in_port
                )

                actions_forward = [
                    parser.OFPActionSetField(ipv4_dst=target_server_ip),
                    parser.OFPActionSetField(eth_dst=target_server_mac),
                    parser.OFPActionOutput(target_server_switch_port)
                ]
                match_forward = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=client_ip,
                    ipv4_dst=self.anycast_ip,
                    ip_proto=ip4_pkt.proto,
                    tcp_src=client_tcp_src_port,
                    tcp_dst=anycast_tcp_dst_port
                )
                inst_forward = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions_forward)]
                fm_forward = parser.OFPFlowMod(
                    datapath=dp, priority=100, match=match_forward, instructions=inst_forward,
                    idle_timeout=60, hard_timeout=120
                )
                dp.send_msg(fm_forward)

                actions_reverse = [
                    parser.OFPActionSetField(eth_src=self.anycast_mac),
                    parser.OFPActionSetField(ipv4_src=self.anycast_ip),
                    parser.OFPActionOutput(in_port)
                ]
                match_reverse = parser.OFPMatch(
                    in_port=target_server_switch_port,
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=target_server_ip,
                    ipv4_dst=client_ip,
                    ip_proto=ip4_pkt.proto,
                    tcp_src=anycast_tcp_dst_port,
                    tcp_dst=client_tcp_src_port
                )
                inst_reverse = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions_reverse)]
                fm_reverse = parser.OFPFlowMod(
                    datapath=dp, priority=100, match=match_reverse, instructions=inst_reverse,
                    idle_timeout=60, hard_timeout=120
                )
                dp.send_msg(fm_reverse)
                self.logger.info("Flow-Anycast: Reverse flow for Server %s -> Client %s installed.", target_server_ip, client_ip)

                out = parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                                          in_port=in_port,
                                          actions=actions_forward,
                                          data=msg.data)
                dp.send_msg(out)
                return
            else:
                self.logger.debug("Packet for existing flow received, should be handled by switch.")
                pass