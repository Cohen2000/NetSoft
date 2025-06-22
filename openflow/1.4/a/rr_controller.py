#!/usr/bin/env python3
# rr_controller.py

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, ether_types

class RRAnycast(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RRAnycast, self).__init__(*args, **kwargs)
        self.anycast_ip   = '10.0.0.100'
        self.server_ips   = ['10.0.0.2', '10.0.0.3', '10.0.0.4']
        self.server_macs  = [
            '02:00:00:00:00:02',  # srv1
            '02:00:00:00:00:03',  # srv2
            '02:00:00:00:00:04',  # srv3
        ]
        self.next_index   = 0

    def get_next(self):
        idx = self.next_index
        ip  = self.server_ips[idx]
        mac = self.server_macs[idx]
        self.next_index = (idx + 1) % len(self.server_ips)
        return ip, mac

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp     = ev.msg.datapath
        ofp    = dp.ofproto
        parser = dp.ofproto_parser
       
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst    = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=0, match=match, instructions=inst))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg      = ev.msg
        dp       = msg.datapath
        ofp      = dp.ofproto
        parser   = dp.ofproto_parser
        in_port  = msg.match['in_port']

        pkt      = packet.Packet(msg.data)
        eth      = pkt.get_protocol(ethernet.ethernet)
        arp_pkt  = pkt.get_protocol(arp.arp)
        ip4      = pkt.get_protocol(ipv4.ipv4)

        if arp_pkt and arp_pkt.opcode == arp.ARP_REQUEST \
           and arp_pkt.dst_ip == self.anycast_ip:

            target_ip, target_mac = self.get_next()
            self.logger.info("ARP-Anycast: replying %s → %s/%s",
                             arp_pkt.src_ip, target_ip, target_mac)

            eth_reply = ethernet.ethernet(
                ethertype=ether_types.ETH_TYPE_ARP,
                dst=eth.src,
                src=target_mac
            )
            arp_reply = arp.arp(
                opcode=arp.ARP_REPLY,
                src_mac=target_mac,
                src_ip=self.anycast_ip,
                dst_mac=eth.src,
                dst_ip=arp_pkt.src_ip
            )
            reply = packet.Packet()
            reply.add_protocol(eth_reply)
            reply.add_protocol(arp_reply)
            reply.serialize()

            actions = [parser.OFPActionOutput(in_port)]
            out = parser.OFPPacketOut(datapath=dp,
                                      buffer_id=ofp.OFP_NO_BUFFER,
                                      in_port=ofp.OFPP_CONTROLLER,
                                      actions=actions,
                                      data=reply.data)
            dp.send_msg(out)
            return

        if ip4 and ip4.dst == self.anycast_ip:
            target_ip, target_mac = self.get_next()
            self.logger.info("Anycast-IPv4: %s → %s/%s",
                             ip4.src, target_ip, target_mac)
            actions = [
                parser.OFPActionSetField(ipv4_dst=target_ip),
                parser.OFPActionSetField(eth_dst=target_mac),
                parser.OFPActionOutput(ofp.OFPP_FLOOD)
            ]

            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                    ipv4_dst=self.anycast_ip)
            inst  = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                  actions)]
            fm = parser.OFPFlowMod(datapath=dp,
                                   priority=100,
                                   match=match,
                                   instructions=inst,
                                   idle_timeout=0,
                                   hard_timeout=1)
            dp.send_msg(fm)

            out = parser.OFPPacketOut(datapath=dp,
                                      buffer_id=ofp.OFP_NO_BUFFER,
                                      in_port=in_port,
                                      actions=actions,
                                      data=msg.data)
            dp.send_msg(out)
            return

        return
