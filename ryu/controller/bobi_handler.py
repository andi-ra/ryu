# Copyright (C) 2011, 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011, 2012 Isaku Yamahata <yamahata at valinux co jp>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Basic OpenFlow handling including negotiation.
"""

import itertools
import logging
import warnings

import ryu.base.app_manager

from ryu.lib import hub
from ryu import utils
from ryu.controller import bobi_event
from ryu.controller.controller import OpenFlowController
from ryu.controller.controller import OpenFlowController
from ryu.controller.handler import set_ev_handler
from ryu.controller.handler import HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, \
    MAIN_DISPATCHER
from ryu.ofproto import ofproto_parser
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

# The state transition: HANDSHAKE -> CONFIG -> MAIN
#
# HANDSHAKE: if it receives HELLO message with the valid OFP version,
# sends Features Request message, and moves to CONFIG.
#
# CONFIG: it receives Features Reply message and moves to MAIN
#
# MAIN: it does nothing. Applications are expected to register their
# own handlers.
#
# Note that at any state, when we receive Echo Request message, send
# back Echo Reply message.


class OFPHandler(ryu.base.app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(OFPHandler, self).__init__(*args, **kwargs)
        self.name = bobi_event.NAME
        self.controller = None
        self.logger.debug("BOBI BOBI!!")

    def start(self):
        super(OFPHandler, self).start()
        self.controller = OpenFlowController()
        return hub.spawn(self.controller)

    def _hello_failed(self, datapath, error_desc):
        self.logger.error('%s on datapath %s', error_desc, datapath.address)
        error_msg = datapath.ofproto_parser.OFPErrorMsg(
            datapath=datapath,
            type_=datapath.ofproto.OFPET_HELLO_FAILED,
            code=datapath.ofproto.OFPHFC_INCOMPATIBLE,
            data=error_desc)
        datapath.send_msg(error_msg, close_socket=True)

    @set_ev_handler(bobi_event.EventOFPHello, [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER])
    def hello_handler(self, ev):
        self.logger.debug('hello ev %s', ev)
        msg = ev.msg
        datapath = msg.datapath

        # check if received version is supported.
        # pre 1.0 is not supported
        elements = getattr(msg, 'elements', None)
        if elements:
            switch_versions = set()
            for version in itertools.chain.from_iterable(
                    element.versions for element in elements):
                switch_versions.add(version)
            usable_versions = switch_versions & set(
                datapath.supported_ofp_version)

            # We didn't send our supported versions for interoperability as
            # most switches would not understand elements at the moment.
            # So the switch would think that the negotiated version would
            # be max(negotiated_versions), but actual usable version is
            # max(usable_versions).
            negotiated_versions = set(
                version for version in switch_versions
                if version <= max(datapath.supported_ofp_version))
            if negotiated_versions and not usable_versions:
                # e.g.
                # versions of OF 1.0 and 1.1 from switch
                # max of OF 1.2 from Ryu and supported_ofp_version = (1.2, )
                # negotiated version = 1.1
                # usable version = None
                error_desc = (
                        'no compatible version found: '
                        'switch versions %s controller version 0x%x, '
                        'the negotiated version is 0x%x, '
                        'but no usable version found. '
                        'If possible, set the switch to use one of OF version %s'
                        % (switch_versions, max(datapath.supported_ofp_version),
                           max(negotiated_versions),
                           sorted(datapath.supported_ofp_version)))
                self._hello_failed(datapath, error_desc)
                return
            if (negotiated_versions and usable_versions and
                    max(negotiated_versions) != max(usable_versions)):
                # e.g.
                # versions of OF 1.0 and 1.1 from switch
                # max of OF 1.2 from Ryu and supported_ofp_version = (1.0, 1.2)
                # negotiated version = 1.1
                # usable version = 1.0
                #
                # TODO: In order to get the version 1.0, Ryu need to send
                # supported verions.
                error_desc = (
                        'no compatible version found: '
                        'switch versions 0x%x controller version 0x%x, '
                        'the negotiated version is %s but found usable %s. '
                        'If possible, '
                        'set the switch to use one of OF version %s' % (
                            max(switch_versions),
                            max(datapath.supported_ofp_version),
                            sorted(negotiated_versions),
                            sorted(usable_versions), sorted(usable_versions)))
                self._hello_failed(datapath, error_desc)
                return
        else:
            usable_versions = set(version for version
                                  in datapath.supported_ofp_version
                                  if version <= msg.version)
            if (usable_versions and
                    max(usable_versions) != min(msg.version,
                                                datapath.ofproto.OFP_VERSION)):
                # The version of min(msg.version, datapath.ofproto.OFP_VERSION)
                # should be used according to the spec. But we can't.
                # So log it and use max(usable_versions) with the hope that
                # the switch is able to understand lower version.
                # e.g.
                # OF 1.1 from switch
                # OF 1.2 from Ryu and supported_ofp_version = (1.0, 1.2)
                # In this case, 1.1 should be used according to the spec,
                # but 1.1 can't be used.
                #
                # OF1.3.1 6.3.1
                # Upon receipt of this message, the recipient must
                # calculate the OpenFlow protocol version to be used. If
                # both the Hello message sent and the Hello message
                # received contained a OFPHET_VERSIONBITMAP hello element,
                # and if those bitmaps have some common bits set, the
                # negotiated version must be the highest version set in
                # both bitmaps. Otherwise, the negotiated version must be
                # the smaller of the version number that was sent and the
                # one that was received in the version fields.  If the
                # negotiated version is supported by the recipient, then
                # the connection proceeds. Otherwise, the recipient must
                # reply with an OFPT_ERROR message with a type field of
                # OFPET_HELLO_FAILED, a code field of OFPHFC_INCOMPATIBLE,
                # and optionally an ASCII string explaining the situation
                # in data, and then terminate the connection.
                version = max(usable_versions)
                error_desc = (
                        'no compatible version found: '
                        'switch 0x%x controller 0x%x, but found usable 0x%x. '
                        'If possible, set the switch to use OF version 0x%x' % (
                            msg.version, datapath.ofproto.OFP_VERSION,
                            version, version))
                self._hello_failed(datapath, error_desc)
                return

        if not usable_versions:
            error_desc = (
                    'unsupported version 0x%x. '
                    'If possible, set the switch to use one of the versions %s' % (
                        msg.version, sorted(datapath.supported_ofp_version)))
            self._hello_failed(datapath, error_desc)
            return
        datapath.set_version(max(usable_versions))

        # Move on to config state
        self.logger.debug('move onto config mode')
        datapath.set_state(CONFIG_DISPATCHER)

        # Finally, send feature request
        features_request = datapath.ofproto_parser.OFPFeaturesRequest(datapath)
        datapath.send_msg(features_request)

    @set_ev_handler(bobi_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        self.logger.debug('switch features ev %s', msg)

        datapath.id = msg.datapath_id

        # hacky workaround, will be removed. OF1.3 doesn't have
        # ports. An application should not depend on them. But there
        # might be such bad applications so keep this workaround for
        # while.
        if datapath.ofproto.OFP_VERSION < 0x04:
            datapath.ports = msg.ports
        else:
            datapath.ports = {}

        if datapath.ofproto.OFP_VERSION <= 0x04:
            self.logger.debug('move onto main mode')
            ev.msg.datapath.set_state(MAIN_DISPATCHER)
        else:
            port_desc = datapath.ofproto_parser.OFPPortDescStatsRequest(
                datapath, 0)
            datapath.send_msg(port_desc)

    @set_ev_handler(bobi_event.EventOFPPortDescStatsReply, CONFIG_DISPATCHER)
    def multipart_reply_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            for port in msg.body:
                datapath.ports[port.port_no] = port

        if msg.flags & datapath.ofproto.OFPMPF_REPLY_MORE:
            return
        self.logger.debug('move onto main mode')
        ev.msg.datapath.set_state(MAIN_DISPATCHER)

    @set_ev_handler(bobi_event.EventOFPEchoRequest,
                    [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def echo_request_handler(self, ev):
        self.logger.debug('Received REQUEST')
        print('Received REQUEST')
        msg = ev.msg
        datapath = msg.datapath
        echo_reply = datapath.ofproto_parser.OFPEchoReply(datapath)
        echo_reply.xid = msg.xid
        echo_reply.data = msg.data
        datapath.send_msg(echo_reply)

    @set_ev_handler(bobi_event.EventOFPEchoReply,
                    [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def echo_reply_handler(self, ev):
        self.logger.debug('Received ECHO REPLY')
        print('Received ECHO REPLY')
        msg = ev.msg
        datapath = msg.datapath
        datapath.acknowledge_echo_reply(msg.xid)

    @set_ev_handler(bobi_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        if msg.reason in [ofproto.OFPPR_ADD, ofproto.OFPPR_MODIFY]:
            datapath.ports[msg.desc.port_no] = msg.desc
        elif msg.reason == ofproto.OFPPR_DELETE:
            datapath.ports.pop(msg.desc.port_no, None)
        else:
            return

        self.send_event_to_observers(
            bobi_event.EventOFPPortStateChange(
                datapath, msg.reason, msg.desc.port_no),
            datapath.state)

    @set_ev_handler(bobi_event.EventOFPErrorMsg,
                    [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        msg = ev.msg
        ofp = msg.datapath.ofproto
        self.logger.debug(
            "EventOFPErrorMsg received.\n"
            "version=%s, msg_type=%s, msg_len=%s, xid=%s\n"
            " `-- msg_type: %s",
            hex(msg.version), hex(msg.msg_type), hex(msg.msg_len),
            hex(msg.xid),
            ofp.ofp_msg_type_to_str(msg.msg_type))
        if msg.type == ofp.OFPET_EXPERIMENTER:
            self.logger.debug(
                "OFPErrorExperimenterMsg(type=%s, exp_type=%s,"
                " experimenter=%s, data=b'%s')",
                hex(msg.type), hex(msg.exp_type),
                hex(msg.experimenter), utils.binary_str(msg.data))
        else:
            self.logger.debug(
                "OFPErrorMsg(type=%s, code=%s, data=b'%s')\n"
                " |-- type: %s\n"
                " |-- code: %s",
                hex(msg.type), hex(msg.code), utils.binary_str(msg.data),
                ofp.ofp_error_type_to_str(msg.type),
                ofp.ofp_error_code_to_str(msg.type, msg.code))
        if msg.type == ofp.OFPET_HELLO_FAILED:
            self.logger.debug(
                " `-- data: %s", msg.data.decode('ascii'))
        elif len(msg.data) >= ofp.OFP_HEADER_SIZE:
            (version, msg_type, msg_len, xid) = ofproto_parser.header(msg.data)
            self.logger.debug(
                " `-- data: version=%s, msg_type=%s, msg_len=%s, xid=%s\n"
                "     `-- msg_type: %s",
                hex(version), hex(msg_type), hex(msg_len), hex(xid),
                ofp.ofp_msg_type_to_str(msg_type))
        else:
            self.logger.warning(
                "The data field sent from the switch is too short: "
                "len(msg.data) < OFP_HEADER_SIZE\n"
                "The OpenFlow Spec says that the data field should contain "
                "at least 64 bytes of the failed request.\n"
                "Please check the settings or implementation of your switch.")
    #
    # @set_ev_handler(bobi_event.EventOFPPacketIn, MAIN_DISPATCHER)
    # def _packet_in_handler(self, ev):
    #     self.logger.debug("Modified version!!")
    #     # If you hit this you might want to increase
    #     # the "miss_send_length" of your switch
    #     if ev.msg.msg_len < ev.msg.total_len:
    #         self.logger.debug("packet truncated: only %s of %s bytes",
    #                           ev.msg.msg_len, ev.msg.total_len)
    #     msg = ev.msg
    #     datapath = msg.datapath
    #     ofproto = datapath.ofproto
    #     parser = datapath.ofproto_parser
    #     in_port = msg.match['in_port']
    #
    #     pkt = packet.Packet(msg.data)
    #     eth = pkt.get_protocols(ethernet.ethernet)[0]
    #
    #     if eth.ethertype == ether_types.ETH_TYPE_LLDP:
    #         # ignore lldp packet
    #         return
    #     dst = eth.dst
    #     src = eth.src
    #
    #     dpid = format(datapath.id, "d").zfill(16)
    #
    #     self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
    #     self.logger.info("Data from packet in %s", msg.match['data'])
    #
    #
    #     out_port = ofproto.OFPP_FLOOD
    #
    #     actions = [parser.OFPActionOutput(out_port)]
    #
    #     # install a flow to avoid packet_in next time
    #     if out_port != ofproto.OFPP_FLOOD:
    #         match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
    #         # verify if we have a valid buffer_id, if yes avoid to send both
    #         # flow_mod & packet_out
    #     data = None
    #     if msg.buffer_id == ofproto.OFP_NO_BUFFER:
    #         data = msg.data
    #
    #     out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
    #                               in_port=in_port, actions=actions, data=data)
    #     datapath.send_msg(out)