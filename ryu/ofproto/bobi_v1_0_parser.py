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
Decoder/Encoder implementations of OpenFlow 1.0.
"""

import struct
import base64

import six
import netaddr

from ryu.ofproto.ofproto_parser import StringifyMixin, MsgBase
from ryu.lib import addrconv
from ryu.lib import ip
from ryu.lib import mac
from ryu.lib.packet import packet
from ryu.lib.pack_utils import msg_pack_into
from ryu.ofproto import nx_match
from ryu.ofproto import ofproto_common
from ryu.ofproto import ofproto_parser
from ryu.ofproto import ofproto_v1_0 as ofproto
from ryu.ofproto import nx_actions
from ryu import utils

import logging
LOG = logging.getLogger('ryu.ofproto.bobi_v1_0_parser')

_MSG_PARSERS = {}


def _set_msg_type(msg_type):
    '''Annotate corresponding OFP message type'''
    def _set_cls_msg_type(cls):
        cls.cls_msg_type = msg_type
        return cls
    return _set_cls_msg_type


def _register_parser(cls):
    '''class decorator to register msg parser'''
    assert cls.cls_msg_type is not None
    assert cls.cls_msg_type not in _MSG_PARSERS
    _MSG_PARSERS[cls.cls_msg_type] = cls.parser
    return cls


@ofproto_parser.register_msg_parser(ofproto.OFP_VERSION)
def msg_parser(datapath, version, msg_type, msg_len, xid, buf):
    parser = _MSG_PARSERS.get(msg_type)
    return parser(datapath, version, msg_type, msg_len, xid, buf)


# OFP_MSG_REPLY = {
#     OFPFeaturesRequest: OFPSwitchFeatures,
#     OFPBarrierRequest: OFPBarrierReply,
#     OFPQueueGetConfigRequest: OFPQueueGetConfigReply,
#
#     # ofp_stats_request -> ofp_stats_reply
#     OFPDescStatsRequest: OFPDescStatsReply,
#     OFPFlowStatsRequest: OFPFlowStatsReply,
#     OFPAggregateStatsRequest: OFPAggregateStatsReply,
#     OFPTableStatsRequest: OFPTableStatsReply,
#     OFPPortStatsRequest: OFPPortStatsReply,
#     OFPQueueStatsRequest: OFPQueueStatsReply,
#     OFPVendorStatsRequest: OFPVendorStatsReply,
#     }
def _set_msg_reply(msg_reply):
    '''Annotate OFP reply message class'''
    def _set_cls_msg_reply(cls):
        cls.cls_msg_reply = msg_reply
        return cls
    return _set_cls_msg_reply


#
# common structures
#

class OFPPhyPort(ofproto_parser.namedtuple('OFPPhyPort', (
        'port_no', 'hw_addr', 'name', 'config', 'state', 'curr', 'advertised',
        'supported', 'peer'))):
    """
    Description of a port

    ========== =========================================================
    Attribute  Description
    ========== =========================================================
    port_no    Port number and it uniquely identifies a port within
               a switch.
    hw_addr    MAC address for the port.
    name       Null-terminated string containing a human-readable name
               for the interface.
    config     Bitmap of port configration flags.

               | OFPPC_PORT_DOWN
               | OFPPC_NO_STP
               | OFPPC_NO_RECV
               | OFPPC_NO_RECV_STP
               | OFPPC_NO_FLOOD
               | OFPPC_NO_FWD
               | OFPPC_NO_PACKET_IN
    state      Bitmap of port state flags.

               | OFPPS_LINK_DOWN
               | OFPPS_STP_LISTEN
               | OFPPS_STP_LEARN
               | OFPPS_STP_FORWARD
               | OFPPS_STP_BLOCK
               | OFPPS_STP_MASK
    curr       Current features.
    advertised Features being advertised by the port.
    supported  Features supported by the port.
    peer       Features advertised by peer.
    ========== =========================================================
    """
    _TYPE = {
        'ascii': [
            'hw_addr',
        ],
        'utf-8': [
            # OF spec is unclear about the encoding of name.
            # we assumes UTF-8, which is used by OVS.
            'name',
        ]
    }

    @classmethod
    def parser(cls, buf, offset):
        port = struct.unpack_from(ofproto.OFP_PHY_PORT_PACK_STR,
                                  buf, offset)
        port = list(port)
        i = cls._fields.index('hw_addr')
        port[i] = addrconv.mac.bin_to_text(port[i])
        i = cls._fields.index('name')
        port[i] = port[i].rstrip(b'\0')
        return cls(*port)


class OFPMatch(StringifyMixin):
    """
    Flow Match Structure

    This class is implementation of the flow match structure having
    compose/query API.

    ================ ==================================================
    Attribute        Description
    ================ ==================================================
    wildcards        Wildcard fields.
    (match fields)   For the available match fields,
                     please refer to the following.
    ================ ==================================================

    ================ =============== ==================================
    Argument         Value           Description
    ================ =============== ==================================
    in_port          Integer 16bit   Switch input port.
    dl_src           MAC address     Ethernet source address.
    dl_dst           MAC address     Ethernet destination address.
    dl_vlan          Integer 16bit   Input VLAN id.
    dl_vlan_pcp      Integer 8bit    Input VLAN priority.
    dl_type          Integer 16bit   Ethernet frame type.
    nw_tos           Integer 8bit    IP ToS (actually DSCP field, 6 bits).
    nw_proto         Integer 8bit    IP protocol or lower 8 bits of
                                     ARP opcode.
    nw_src           IPv4 address    IP source address.
    nw_dst           IPv4 address    IP destination address.
    tp_src           Integer 16bit   TCP/UDP source port.
    tp_dst           Integer 16bit   TCP/UDP destination port.
    nw_src_mask      Integer 8bit    IP source address mask
                                     specified as IPv4 address prefix.
    nw_dst_mask      Integer 8bit    IP destination address mask
                                     specified as IPv4 address prefix.
    ================ =============== ==================================

    Example::

        >>> # compose
        >>> match = parser.OFPMatch(
        ...     in_port=1,
        ...     dl_type=0x0800,
        ...     dl_src='aa:bb:cc:dd:ee:ff',
        ...     nw_src='192.168.0.1')
        >>> # query
        >>> if 'nw_src' in match:
        ...     print match['nw_src']
        ...
        '192.168.0.1'
    """

    def __init__(self, wildcards=None, in_port=None, dl_src=None, dl_dst=None,
                 dl_vlan=None, dl_vlan_pcp=None, dl_type=None, nw_tos=None,
                 nw_proto=None, nw_src=None, nw_dst=None,
                 tp_src=None, tp_dst=None, nw_src_mask=32, nw_dst_mask=32):
        super(OFPMatch, self).__init__()
        wc = ofproto.OFPFW_ALL
        if in_port is None:
            self.in_port = 0
        else:
            wc &= ~ofproto.OFPFW_IN_PORT
            self.in_port = in_port

        if dl_src is None:
            self.dl_src = mac.DONTCARE
        else:
            wc &= ~ofproto.OFPFW_DL_SRC
            if (isinstance(dl_src, (six.text_type, str)) and
                    netaddr.valid_mac(dl_src)):
                dl_src = addrconv.mac.text_to_bin(dl_src)
            if dl_src == 0:
                self.dl_src = mac.DONTCARE
            else:
                self.dl_src = dl_src

        if dl_dst is None:
            self.dl_dst = mac.DONTCARE
        else:
            wc &= ~ofproto.OFPFW_DL_DST
            if (isinstance(dl_dst, (six.text_type, str)) and
                    netaddr.valid_mac(dl_dst)):
                dl_dst = addrconv.mac.text_to_bin(dl_dst)
            if dl_dst == 0:
                self.dl_dst = mac.DONTCARE
            else:
                self.dl_dst = dl_dst

        if dl_vlan is None:
            self.dl_vlan = 0
        else:
            wc &= ~ofproto.OFPFW_DL_VLAN
            self.dl_vlan = dl_vlan

        if dl_vlan_pcp is None:
            self.dl_vlan_pcp = 0
        else:
            wc &= ~ofproto.OFPFW_DL_VLAN_PCP
            self.dl_vlan_pcp = dl_vlan_pcp

        if dl_type is None:
            self.dl_type = 0
        else:
            wc &= ~ofproto.OFPFW_DL_TYPE
            self.dl_type = dl_type

        if nw_tos is None:
            self.nw_tos = 0
        else:
            wc &= ~ofproto.OFPFW_NW_TOS
            self.nw_tos = nw_tos

        if nw_proto is None:
            self.nw_proto = 0
        else:
            wc &= ~ofproto.OFPFW_NW_PROTO
            self.nw_proto = nw_proto

        if nw_src is None:
            self.nw_src = 0
        else:
            wc &= (32 - nw_src_mask) << ofproto.OFPFW_NW_SRC_SHIFT \
                | ~ofproto.OFPFW_NW_SRC_MASK
            if not isinstance(nw_src, int):
                nw_src = ip.ipv4_to_int(nw_src)
            self.nw_src = nw_src

        if nw_dst is None:
            self.nw_dst = 0
        else:
            wc &= (32 - nw_dst_mask) << ofproto.OFPFW_NW_DST_SHIFT \
                | ~ofproto.OFPFW_NW_DST_MASK
            if not isinstance(nw_dst, int):
                nw_dst = ip.ipv4_to_int(nw_dst)
            self.nw_dst = nw_dst

        if tp_src is None:
            self.tp_src = 0
        else:
            wc &= ~ofproto.OFPFW_TP_SRC
            self.tp_src = tp_src

        if tp_dst is None:
            self.tp_dst = 0
        else:
            wc &= ~ofproto.OFPFW_TP_DST
            self.tp_dst = tp_dst

        if wildcards is None:
            self.wildcards = wc
        else:
            self.wildcards = wildcards

    def __getitem__(self, name):
        if not isinstance(name, str):
            raise KeyError(name)
        elif name == 'nw_src_mask':
            _m = 32 - ((self.wildcards & ofproto.OFPFW_NW_SRC_MASK) >>
                       ofproto.OFPFW_NW_SRC_SHIFT)
            return 0 if _m < 0 else _m
        elif name == 'nw_dst_mask':
            _m = 32 - ((self.wildcards & ofproto.OFPFW_NW_DST_MASK) >>
                       ofproto.OFPFW_NW_DST_SHIFT)
            return 0 if _m < 0 else _m
        elif name == 'wildcards':
            return self.wildcards

        wc = getattr(ofproto, 'OFPFW_' + name.upper(), 0)
        if ~self.wildcards & wc:
            value = getattr(self, name)
            if name in ['dl_src', 'dl_dst']:
                value = addrconv.mac.bin_to_text(value)
            elif name in ['nw_src', 'nw_dst']:
                value = ip.ipv4_to_str(value)
            return value
        else:
            raise KeyError(name)

    def __contains__(self, name):
        wc = getattr(ofproto, 'OFPFW_' + name.upper(), 0)
        return ~self.wildcards & wc

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_MATCH_PACK_STR, buf, offset,
                      self.wildcards, self.in_port, self.dl_src,
                      self.dl_dst, self.dl_vlan, self.dl_vlan_pcp,
                      self.dl_type, self.nw_tos, self.nw_proto,
                      self.nw_src, self.nw_dst, self.tp_src, self.tp_dst)

    @classmethod
    def parse(cls, buf, offset):
        match = struct.unpack_from(ofproto.OFP_MATCH_PACK_STR,
                                   buf, offset)
        return cls(*match)

    def to_jsondict(self):
        fields = {}
        # copy values to avoid original values conversion
        for k, v in self.__dict__.items():
            if k in ['dl_src', 'dl_dst']:
                fields[k] = addrconv.mac.bin_to_text(v)
            elif k in ['nw_src', 'nw_dst']:
                fields[k] = ip.ipv4_to_str(v)
            else:
                fields[k] = v
        return {self.__class__.__name__: fields}

    @classmethod
    def from_jsondict(cls, dict_):
        return cls(**dict_)


class OFPActionHeader(StringifyMixin):
    _base_attributes = ['type', 'len']

    def __init__(self, type_, len_):
        self.type = type_
        self.len = len_

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_ACTION_HEADER_PACK_STR,
                      buf, offset, self.type, self.len)


class OFPAction(OFPActionHeader):
    _ACTION_TYPES = {}

    @staticmethod
    def register_action_type(type_, len_):
        def _register_action_type(cls):
            cls.cls_action_type = type_
            cls.cls_action_len = len_
            OFPAction._ACTION_TYPES[cls.cls_action_type] = cls
            return cls
        return _register_action_type

    def __init__(self):
        cls = self.__class__
        super(OFPAction, self).__init__(cls.cls_action_type,
                                        cls.cls_action_len)

    @classmethod
    def parser(cls, buf, offset):
        type_, len_ = struct.unpack_from(
            ofproto.OFP_ACTION_HEADER_PACK_STR, buf, offset)
        cls_ = cls._ACTION_TYPES.get(type_)
        assert cls_ is not None
        return cls_.parser(buf, offset)


@OFPAction.register_action_type(ofproto.OFPAT_OUTPUT,
                                ofproto.OFP_ACTION_OUTPUT_SIZE)
class OFPActionOutput(OFPAction):
    """
    Output action

    This action indicates output a packet to the switch port.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    port             Output port.
    max_len          Max length to send to controller.
    ================ ======================================================

    Note::
        The reason of this magic number (0xffe5)
        is because there is no good constant in of1.0.
        The same value as OFPCML_MAX of of1.2 and of1.3 is used.
    """

    def __init__(self, port, max_len=0xffe5):
        super(OFPActionOutput, self).__init__()
        self.port = port
        self.max_len = max_len

    @classmethod
    def parser(cls, buf, offset):
        type_, len_, port, max_len = struct.unpack_from(
            ofproto.OFP_ACTION_OUTPUT_PACK_STR, buf, offset)
        assert type_ == ofproto.OFPAT_OUTPUT
        assert len_ == ofproto.OFP_ACTION_OUTPUT_SIZE
        return cls(port, max_len)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_ACTION_OUTPUT_PACK_STR, buf,
                      offset, self.type, self.len, self.port, self.max_len)


@OFPAction.register_action_type(ofproto.OFPAT_SET_VLAN_VID,
                                ofproto.OFP_ACTION_VLAN_VID_SIZE)
class OFPActionVlanVid(OFPAction):
    """
    Set the 802.1q VLAN id action

    This action indicates the 802.1q VLAN id to be set.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    vlan_vid         VLAN id.
    ================ ======================================================
    """

    def __init__(self, vlan_vid):
        super(OFPActionVlanVid, self).__init__()
        self.vlan_vid = vlan_vid

    @classmethod
    def parser(cls, buf, offset):
        type_, len_, vlan_vid = struct.unpack_from(
            ofproto.OFP_ACTION_VLAN_VID_PACK_STR, buf, offset)
        assert type_ == ofproto.OFPAT_SET_VLAN_VID
        assert len_ == ofproto.OFP_ACTION_VLAN_VID_SIZE
        return cls(vlan_vid)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_ACTION_VLAN_VID_PACK_STR,
                      buf, offset, self.type, self.len, self.vlan_vid)


@OFPAction.register_action_type(ofproto.OFPAT_SET_VLAN_PCP,
                                ofproto.OFP_ACTION_VLAN_PCP_SIZE)
class OFPActionVlanPcp(OFPAction):
    """
    Set the 802.1q priority action

    This action indicates the 802.1q priority to be set.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    vlan_pcp         VLAN priority.
    ================ ======================================================
    """

    def __init__(self, vlan_pcp):
        super(OFPActionVlanPcp, self).__init__()
        self.vlan_pcp = vlan_pcp

    @classmethod
    def parser(cls, buf, offset):
        type_, len_, vlan_pcp = struct.unpack_from(
            ofproto.OFP_ACTION_VLAN_PCP_PACK_STR, buf, offset)
        assert type_ == ofproto.OFPAT_SET_VLAN_PCP
        assert len_ == ofproto.OFP_ACTION_VLAN_PCP_SIZE
        return cls(vlan_pcp)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_ACTION_VLAN_PCP_PACK_STR,
                      buf, offset, self.type, self.len, self.vlan_pcp)


@OFPAction.register_action_type(ofproto.OFPAT_STRIP_VLAN,
                                ofproto.OFP_ACTION_HEADER_SIZE)
class OFPActionStripVlan(OFPAction):
    """
    Strip the 802.1q header action

    This action indicates the 802.1q priority to be striped.
    """

    def __init__(self):
        super(OFPActionStripVlan, self).__init__()

    @classmethod
    def parser(cls, buf, offset):
        type_, len_ = struct.unpack_from(
            ofproto.OFP_ACTION_HEADER_PACK_STR, buf, offset)
        assert type_ == ofproto.OFPAT_STRIP_VLAN
        assert len_ == ofproto.OFP_ACTION_HEADER_SIZE
        return cls()


class OFPActionDlAddr(OFPAction):
    def __init__(self, dl_addr):
        super(OFPActionDlAddr, self).__init__()
        if (isinstance(dl_addr, (six.text_type, str)) and
                netaddr.valid_mac(dl_addr)):
            dl_addr = addrconv.mac.text_to_bin(dl_addr)
        self.dl_addr = dl_addr

    @classmethod
    def parser(cls, buf, offset):
        type_, len_, dl_addr = struct.unpack_from(
            ofproto.OFP_ACTION_DL_ADDR_PACK_STR, buf, offset)
        assert type_ in (ofproto.OFPAT_SET_DL_SRC,
                         ofproto.OFPAT_SET_DL_DST)
        assert len_ == ofproto.OFP_ACTION_DL_ADDR_SIZE
        return cls(dl_addr)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_ACTION_DL_ADDR_PACK_STR,
                      buf, offset, self.type, self.len, self.dl_addr)

    def to_jsondict(self):
        body = {"dl_addr": addrconv.mac.bin_to_text(self.dl_addr)}
        return {self.__class__.__name__: body}

    @classmethod
    def from_jsondict(cls, dict_):
        return cls(**dict_)


@OFPAction.register_action_type(ofproto.OFPAT_SET_DL_SRC,
                                ofproto.OFP_ACTION_DL_ADDR_SIZE)
class OFPActionSetDlSrc(OFPActionDlAddr):
    """
    Set the ethernet source address action

    This action indicates the ethernet source address to be set.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    dl_addr          Ethernet address.
    ================ ======================================================
    """

    def __init__(self, dl_addr):
        super(OFPActionSetDlSrc, self).__init__(dl_addr)


@OFPAction.register_action_type(ofproto.OFPAT_SET_DL_DST,
                                ofproto.OFP_ACTION_DL_ADDR_SIZE)
class OFPActionSetDlDst(OFPActionDlAddr):
    """
    Set the ethernet destination address action

    This action indicates the ethernet destination address to be set.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    dl_addr          Ethernet address.
    ================ ======================================================
    """

    def __init__(self, dl_addr):
        super(OFPActionSetDlDst, self).__init__(dl_addr)


class OFPActionNwAddr(OFPAction):
    def __init__(self, nw_addr):
        super(OFPActionNwAddr, self).__init__()
        if not isinstance(nw_addr, int):
            nw_addr = ip.ipv4_to_int(nw_addr)
        self.nw_addr = nw_addr

    @classmethod
    def parser(cls, buf, offset):
        type_, len_, nw_addr = struct.unpack_from(
            ofproto.OFP_ACTION_NW_ADDR_PACK_STR, buf, offset)
        assert type_ in (ofproto.OFPAT_SET_NW_SRC,
                         ofproto.OFPAT_SET_NW_DST)
        assert len_ == ofproto.OFP_ACTION_NW_ADDR_SIZE
        return cls(nw_addr)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_ACTION_NW_ADDR_PACK_STR,
                      buf, offset, self.type, self.len, self.nw_addr)

    def to_jsondict(self):
        body = {"nw_addr": ip.ipv4_to_str(self.nw_addr)}
        return {self.__class__.__name__: body}

    @classmethod
    def from_jsondict(cls, dict_):
        return cls(**dict_)


@OFPAction.register_action_type(ofproto.OFPAT_SET_NW_SRC,
                                ofproto.OFP_ACTION_NW_ADDR_SIZE)
class OFPActionSetNwSrc(OFPActionNwAddr):
    """
    Set the IP source address action

    This action indicates the IP source address to be set.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    nw_addr          IP address.
    ================ ======================================================
    """

    def __init__(self, nw_addr):
        super(OFPActionSetNwSrc, self).__init__(nw_addr)


@OFPAction.register_action_type(ofproto.OFPAT_SET_NW_DST,
                                ofproto.OFP_ACTION_NW_ADDR_SIZE)
class OFPActionSetNwDst(OFPActionNwAddr):
    """
    Set the IP destination address action

    This action indicates the IP destination address to be set.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    nw_addr          IP address.
    ================ ======================================================
    """

    def __init__(self, nw_addr):
        super(OFPActionSetNwDst, self).__init__(nw_addr)


@OFPAction.register_action_type(ofproto.OFPAT_SET_NW_TOS,
                                ofproto.OFP_ACTION_NW_TOS_SIZE)
class OFPActionSetNwTos(OFPAction):
    """
    Set the IP ToS action

    This action indicates the IP ToS (DSCP field, 6 bits) to be set.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    tos              IP ToS (DSCP field, 6 bits).
    ================ ======================================================
    """

    def __init__(self, tos):
        super(OFPActionSetNwTos, self).__init__()
        self.tos = tos

    @classmethod
    def parser(cls, buf, offset):
        type_, len_, tos = struct.unpack_from(
            ofproto.OFP_ACTION_NW_TOS_PACK_STR, buf, offset)
        assert type_ == ofproto.OFPAT_SET_NW_TOS
        assert len_ == ofproto.OFP_ACTION_NW_TOS_SIZE
        return cls(tos)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_ACTION_NW_TOS_PACK_STR,
                      buf, offset, self.type, self.len, self.tos)


class OFPActionTpPort(OFPAction):
    def __init__(self, tp):
        super(OFPActionTpPort, self).__init__()
        self.tp = tp

    @classmethod
    def parser(cls, buf, offset):
        type_, len_, tp = struct.unpack_from(
            ofproto.OFP_ACTION_TP_PORT_PACK_STR, buf, offset)
        assert type_ in (ofproto.OFPAT_SET_TP_SRC,
                         ofproto.OFPAT_SET_TP_DST)
        assert len_ == ofproto.OFP_ACTION_TP_PORT_SIZE
        return cls(tp)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_ACTION_TP_PORT_PACK_STR,
                      buf, offset, self.type, self.len, self.tp)


@OFPAction.register_action_type(ofproto.OFPAT_SET_TP_SRC,
                                ofproto.OFP_ACTION_TP_PORT_SIZE)
class OFPActionSetTpSrc(OFPActionTpPort):
    """
    Set the TCP/UDP source port action

    This action indicates the TCP/UDP source port to be set.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    tp               TCP/UDP port.
    ================ ======================================================
    """

    def __init__(self, tp):
        super(OFPActionSetTpSrc, self).__init__(tp)


@OFPAction.register_action_type(ofproto.OFPAT_SET_TP_DST,
                                ofproto.OFP_ACTION_TP_PORT_SIZE)
class OFPActionSetTpDst(OFPActionTpPort):
    """
    Set the TCP/UDP destination port action

    This action indicates the TCP/UDP destination port to be set.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    tp               TCP/UDP port.
    ================ ======================================================
    """

    def __init__(self, tp):
        super(OFPActionSetTpDst, self).__init__(tp)


@OFPAction.register_action_type(ofproto.OFPAT_ENQUEUE,
                                ofproto.OFP_ACTION_ENQUEUE_SIZE)
class OFPActionEnqueue(OFPAction):
    """
    Output to queue action

    This action indicates send packets to given queue on port.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    port             Port that queue belongs.
    queue_id         Where to enqueue the packets.
    ================ ======================================================
    """

    def __init__(self, port, queue_id):
        super(OFPActionEnqueue, self).__init__()
        self.port = port
        self.queue_id = queue_id

    @classmethod
    def parser(cls, buf, offset):
        type_, len_, port, queue_id = struct.unpack_from(
            ofproto.OFP_ACTION_ENQUEUE_PACK_STR, buf, offset)
        assert type_ == ofproto.OFPAT_ENQUEUE
        assert len_ == ofproto.OFP_ACTION_ENQUEUE_SIZE
        return cls(port, queue_id)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_ACTION_ENQUEUE_PACK_STR, buf, offset,
                      self.type, self.len, self.port, self.queue_id)


@OFPAction.register_action_type(ofproto.OFPAT_VENDOR, 0)
class OFPActionVendor(OFPAction):
    """
    Vendor action

    This action is an extensible action for the vendor.
    """
    _ACTION_VENDORS = {}

    @staticmethod
    def register_action_vendor(vendor):
        def _register_action_vendor(cls):
            cls.cls_vendor = vendor
            OFPActionVendor._ACTION_VENDORS[cls.cls_vendor] = cls
            return cls
        return _register_action_vendor

    def __init__(self, vendor=None):
        super(OFPActionVendor, self).__init__()
        self.type = ofproto.OFPAT_VENDOR
        self.len = None

        if vendor is None:
            self.vendor = self.cls_vendor
        else:
            self.vendor = vendor

    @classmethod
    def parser(cls, buf, offset):
        type_, len_, vendor = struct.unpack_from(
            ofproto.OFP_ACTION_VENDOR_HEADER_PACK_STR, buf, offset)

        data = buf[(offset + ofproto.OFP_ACTION_VENDOR_HEADER_SIZE
                    ): offset + len_]

        if vendor == ofproto_common.NX_EXPERIMENTER_ID:
            obj = NXAction.parse(data)  # noqa
        else:
            cls_ = cls._ACTION_VENDORS.get(vendor, None)

            if cls_ is None:
                obj = OFPActionVendorUnknown(vendor, data)
            else:
                obj = cls_.parser(buf, offset)

        obj.len = len_
        return obj

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_ACTION_VENDOR_HEADER_PACK_STR,
                      buf, offset, self.type, self.len, self.vendor)


# OpenFlow1.2 or later compatible
OFPActionExperimenter = OFPActionVendor


class OFPActionVendorUnknown(OFPActionVendor):
    def __init__(self, vendor, data=None, type_=None, len_=None):
        super(OFPActionVendorUnknown,
              self).__init__(vendor=vendor)
        self.data = data

    def serialize(self, buf, offset):
        # fixup
        data = self.data
        if data is None:
            data = bytearray()
        self.len = (utils.round_up(len(data), 8) +
                    ofproto.OFP_ACTION_VENDOR_HEADER_SIZE)
        super(OFPActionVendorUnknown, self).serialize(buf, offset)
        msg_pack_into('!%ds' % len(self.data),
                      buf,
                      offset + ofproto.OFP_ACTION_VENDOR_HEADER_SIZE,
                      self.data)



class OFPDescStats(ofproto_parser.namedtuple('OFPDescStats', (
        'mfr_desc', 'hw_desc', 'sw_desc', 'serial_num', 'dp_desc'))):

    _TYPE = {
        'ascii': [
            'mfr_desc',
            'hw_desc',
            'sw_desc',
            'serial_num',
            'dp_desc',
        ]
    }

    @classmethod
    def parser(cls, buf, offset):
        desc = struct.unpack_from(ofproto.OFP_DESC_STATS_PACK_STR,
                                  buf, offset)
        desc = list(desc)
        desc = [x.rstrip(b'\0') for x in desc]
        stats = cls(*desc)
        stats.length = ofproto.OFP_DESC_STATS_SIZE
        return stats


class OFPVendorStats(ofproto_parser.namedtuple('OFPVendorStats',
                                               ('specific_data'))):
    @classmethod
    def parser(cls, buf, offset):
        stats = cls(buf[offset:])
        stats.length = len(stats.specific_data)
        return stats





@_register_parser
@_set_msg_type(ofproto.OFPT_HELLO)
class OFPHello(MsgBase):
    """
    Hello message

    When connection is started, the hello message is exchanged between a
    switch and a controller.

    This message is handled by the Ryu framework, so the Ryu application
    do not need to process this typically.
    """

    def __init__(self, datapath):
        super(OFPHello, self).__init__(datapath)


@_register_parser
@_set_msg_type(ofproto.OFPT_ERROR)
class OFPErrorMsg(MsgBase):
    """
    Error message

    The switch notifies controller of problems by this message.

    ========== =========================================================
    Attribute  Description
    ========== =========================================================
    type       High level type of error
    code       Details depending on the type
    data       Variable length data depending on the type and code
    ========== =========================================================

    ``type`` attribute corresponds to ``type_`` parameter of __init__.

    Types and codes are defined in ``ryu.ofproto.ofproto``.

    =========================== ===========
    Type                        Code
    =========================== ===========
    OFPET_HELLO_FAILED          OFPHFC_*
    OFPET_BAD_REQUEST           OFPBRC_*
    OFPET_BAD_ACTION            OFPBAC_*
    OFPET_FLOW_MOD_FAILED       OFPFMFC_*
    OFPET_PORT_MOD_FAILED       OFPPMFC_*
    OFPET_QUEUE_OP_FAILED       OFPQOFC_*
    =========================== ===========

    Example::

        @set_ev_cls(ofp_event.EventOFPErrorMsg,
                    [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
        def error_msg_handler(self, ev):
            msg = ev.msg

            self.logger.debug('OFPErrorMsg received: type=0x%02x code=0x%02x '
                              'message=%s',
                              msg.type, msg.code, utils.hex_array(msg.data))
    """

    def __init__(self, datapath, type_=None, code=None, data=None):
        super(OFPErrorMsg, self).__init__(datapath)
        self.type = type_
        self.code = code
        if isinstance(data, six.string_types):
            data = data.encode('ascii')
        self.data = data

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPErrorMsg, cls).parser(datapath, version, msg_type,
                                             msg_len, xid, buf)
        msg.type, msg.code = struct.unpack_from(
            ofproto.OFP_ERROR_MSG_PACK_STR, msg.buf,
            ofproto.OFP_HEADER_SIZE)
        msg.data = msg.buf[ofproto.OFP_ERROR_MSG_SIZE:]
        return msg

    def _serialize_body(self):
        assert self.data is not None
        msg_pack_into(ofproto.OFP_ERROR_MSG_PACK_STR, self.buf,
                      ofproto.OFP_HEADER_SIZE, self.type, self.code)
        self.buf += self.data


@_register_parser
@_set_msg_type(ofproto.OFPT_ECHO_REQUEST)
class OFPEchoRequest(MsgBase):
    """
    Echo request message

    This message is handled by the Ryu framework, so the Ryu application
    do not need to process this typically.

    ========== =========================================================
    Attribute  Description
    ========== =========================================================
    data       An arbitrary length data.
    ========== =========================================================

    Example::

        def send_echo_request(self, datapath, data):
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPEchoRequest(datapath, data)
            datapath.send_msg(req)
    """

    def __init__(self, datapath, data=None):
        super(OFPEchoRequest, self).__init__(datapath)
        self.data = data

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPEchoRequest, cls).parser(datapath, version, msg_type,
                                                msg_len, xid, buf)
        msg.data = msg.buf[ofproto.OFP_HEADER_SIZE:]
        return msg

    def _serialize_body(self):
        if self.data is not None:
            self.buf += self.data


@_register_parser
@_set_msg_type(ofproto.OFPT_ECHO_REPLY)
class OFPEchoReply(MsgBase):
    """
    Echo reply message

    This message is handled by the Ryu framework, so the Ryu application
    do not need to process this typically.

    ========== =========================================================
    Attribute  Description
    ========== =========================================================
    data       An arbitrary length data.
    ========== =========================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPEchoReply,
                    [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
        def echo_reply_handler(self, ev):
            self.logger.debug('OFPEchoReply received: data=%s',
                              utils.hex_array(ev.msg.data))
    """

    def __init__(self, datapath, data=None):
        super(OFPEchoReply, self).__init__(datapath)
        self.data = data

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPEchoReply, cls).parser(datapath, version, msg_type,
                                              msg_len, xid, buf)
        msg.data = msg.buf[ofproto.OFP_HEADER_SIZE:]
        return msg

    def _serialize_body(self):
        assert self.data is not None
        self.buf += self.data


@_register_parser
@_set_msg_type(ofproto.OFPT_VENDOR)
class OFPVendor(MsgBase):
    """
    Vendor message

    The controller send this message to send the vendor-specific
    information to a switch.
    """
    _VENDORS = {}

    @staticmethod
    def register_vendor(id_):
        def _register_vendor(cls):
            OFPVendor._VENDORS[id_] = cls
            return cls
        return _register_vendor

    def __init__(self, datapath):
        super(OFPVendor, self).__init__(datapath)
        self.data = None
        self.vendor = None

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPVendor, cls).parser(datapath, version, msg_type,
                                           msg_len, xid, buf)
        (msg.vendor,) = struct.unpack_from(
            ofproto.OFP_VENDOR_HEADER_PACK_STR, msg.buf,
            ofproto.OFP_HEADER_SIZE)

        cls_ = cls._VENDORS.get(msg.vendor)
        if cls_:
            msg.data = cls_.parser(datapath, msg.buf, 0)
        else:
            msg.data = msg.buf[ofproto.OFP_VENDOR_HEADER_SIZE:]

        return msg

    def serialize_header(self):
        msg_pack_into(ofproto.OFP_VENDOR_HEADER_PACK_STR,
                      self.buf, ofproto.OFP_HEADER_SIZE, self.vendor)

    def _serialize_body(self):
        assert self.data is not None
        self.serialize_header()
        self.buf += self.data


@_register_parser
@_set_msg_type(ofproto.OFPT_FEATURES_REPLY)
class OFPSwitchFeatures(MsgBase):
    """
    Features reply message

    The switch responds with a features reply message to a features
    request.

    This message is handled by the Ryu framework, so the Ryu application
    do not need to process this typically.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    datapath_id      Datapath unique ID.
    n_buffers        Max packets buffered at once.
    n_tables         Number of tables supported by datapath.
    capabilities     Bitmap of capabilities flag.

                     | OFPC_FLOW_STATS
                     | OFPC_TABLE_STATS
                     | OFPC_PORT_STATS
                     | OFPC_STP
                     | OFPC_RESERVED
                     | OFPC_IP_REASM
                     | OFPC_QUEUE_STATS
                     | OFPC_ARP_MATCH_IP
    actions          Bitmap of supported OFPAT_*.
    ports            List of ``OFPPhyPort`` instances.
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
        def switch_features_handler(self, ev):
            msg = ev.msg

            self.logger.debug('OFPSwitchFeatures received: '
                              'datapath_id=0x%016x n_buffers=%d '
                              'n_tables=%d capabilities=0x%08x ports=%s',
                              msg.datapath_id, msg.n_buffers, msg.n_tables,
                              msg.capabilities, msg.ports)
    """

    def __init__(self, datapath, datapath_id=None, n_buffers=None,
                 n_tables=None, capabilities=None, actions=None, ports=None):
        super(OFPSwitchFeatures, self).__init__(datapath)
        self.datapath_id = datapath_id
        self.n_buffers = n_buffers
        self.n_tables = n_tables
        self.capabilities = capabilities
        self.actions = actions
        self.ports = ports

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPSwitchFeatures, cls).parser(datapath, version, msg_type,
                                                   msg_len, xid, buf)
        (msg.datapath_id,
         msg.n_buffers,
         msg.n_tables,
         msg.capabilities,
         msg.actions) = struct.unpack_from(
            ofproto.OFP_SWITCH_FEATURES_PACK_STR, msg.buf,
            ofproto.OFP_HEADER_SIZE)

        msg.ports = {}
        n_ports = ((msg_len - ofproto.OFP_SWITCH_FEATURES_SIZE) //
                   ofproto.OFP_PHY_PORT_SIZE)
        offset = ofproto.OFP_SWITCH_FEATURES_SIZE
        for _i in range(n_ports):
            port = OFPPhyPort.parser(msg.buf, offset)
            # print 'port = %s' % str(port)
            msg.ports[port.port_no] = port
            offset += ofproto.OFP_PHY_PORT_SIZE

        return msg


@_register_parser
@_set_msg_type(ofproto.OFPT_PORT_STATUS)
class OFPPortStatus(MsgBase):
    """
    Port status message

    The switch notifies controller of change of ports.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    reason           One of the following values.

                     | OFPPR_ADD
                     | OFPPR_DELETE
                     | OFPPR_MODIFY
    desc             instance of ``OFPPhyPort``
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
        def port_status_handler(self, ev):
            msg = ev.msg
            dp = msg.datapath
            ofp = dp.ofproto

            if msg.reason == ofp.OFPPR_ADD:
                reason = 'ADD'
            elif msg.reason == ofp.OFPPR_DELETE:
                reason = 'DELETE'
            elif msg.reason == ofp.OFPPR_MODIFY:
                reason = 'MODIFY'
            else:
                reason = 'unknown'

            self.logger.debug('OFPPortStatus received: reason=%s desc=%s',
                              reason, msg.desc)
    """

    def __init__(self, datapath, reason=None, desc=None):
        super(OFPPortStatus, self).__init__(datapath)
        self.reason = reason
        self.desc = desc

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPPortStatus, cls).parser(datapath, version, msg_type,
                                               msg_len, xid, buf)
        msg.reason = struct.unpack_from(
            ofproto.OFP_PORT_STATUS_PACK_STR,
            msg.buf, ofproto.OFP_HEADER_SIZE)[0]
        msg.desc = OFPPhyPort.parser(msg.buf,
                                     ofproto.OFP_PORT_STATUS_DESC_OFFSET)
        return msg


@_register_parser
@_set_msg_type(ofproto.OFPT_PACKET_IN)
class OFPPacketIn(MsgBase):
    """
    Packet-In message

    The switch sends the packet that received to the controller by this
    message.

    ============= =========================================================
    Attribute     Description
    ============= =========================================================
    buffer_id     ID assigned by datapath.
    total_len     Full length of frame.
    in_port       Port on which frame was received.
    reason        Reason packet is being sent.

                  | OFPR_NO_MATCH
                  | OFPR_ACTION
                  | OFPR_INVALID_TTL
    data          Ethernet frame.
    ============= =========================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
        def packet_in_handler(self, ev):
            msg = ev.msg
            dp = msg.datapath
            ofp = dp.ofproto

            if msg.reason == ofp.OFPR_NO_MATCH:
                reason = 'NO MATCH'
            elif msg.reason == ofp.OFPR_ACTION:
                reason = 'ACTION'
            elif msg.reason == ofp.OFPR_INVALID_TTL:
                reason = 'INVALID TTL'
            else:
                reason = 'unknown'

            self.logger.debug('OFPPacketIn received: '
                              'buffer_id=%x total_len=%d in_port=%d, '
                              'reason=%s data=%s',
                              msg.buffer_id, msg.total_len, msg.in_port,
                              reason, utils.hex_array(msg.data))
    """

    def __init__(self, datapath, buffer_id=None, total_len=None, in_port=None,
                 reason=None, data=None):
        super(OFPPacketIn, self).__init__(datapath)
        self.buffer_id = buffer_id
        self.total_len = total_len
        self.in_port = in_port
        self.reason = reason
        self.data = data

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPPacketIn, cls).parser(datapath, version, msg_type,
                                             msg_len, xid, buf)
        (msg.buffer_id,
         msg.total_len,
         msg.in_port,
         msg.reason) = struct.unpack_from(
            ofproto.OFP_PACKET_IN_PACK_STR,
            msg.buf, ofproto.OFP_HEADER_SIZE)
        msg.data = msg.buf[ofproto.OFP_PACKET_IN_SIZE:]
        if msg.total_len < len(msg.data):
            # discard padding for 8-byte alignment of OFP packet
            msg.data = msg.data[:msg.total_len]
        return msg


@_register_parser
@_set_msg_type(ofproto.OFPT_BARRIER_REPLY)
class OFPBarrierReply(MsgBase):
    """
    Barrier reply message

    The switch responds with this message to a barrier request.

    Example::

        @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
        def barrier_reply_handler(self, ev):
            self.logger.debug('OFPBarrierReply received')
    """

    def __init__(self, datapath):
        super(OFPBarrierReply, self).__init__(datapath)



@_register_parser
@_set_msg_type(ofproto.OFPT_FLOW_MOD)
class OFPFlowMod(MsgBase):
    """
    Modify Flow entry message

    The controller sends this message to modify the flow table.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    match            Instance of ``OFPMatch``.
    cookie           Opaque controller-issued identifier.
    command          One of the following values.

                     | OFPFC_ADD
                     | OFPFC_MODIFY
                     | OFPFC_MODIFY_STRICT
                     | OFPFC_DELETE
                     | OFPFC_DELETE_STRICT
    idle_timeout     Idle time before discarding (seconds).
    hard_timeout     Max time before discarding (seconds).
    priority         Priority level of flow entry.
    buffer_id        Buffered packet to apply to (or 0xffffffff).
                     Not meaningful for OFPFC_DELETE*.
    out_port         For OFPFC_DELETE* commands, require
                     matching entries to include this as an
                     output port. A value of OFPP_NONE
                     indicates no restriction.
    flags            One of the following values.

                     | OFPFF_SEND_FLOW_REM
                     | OFPFF_CHECK_OVERLAP
                     | OFPFF_EMERG
    actions          List of ``OFPAction*`` instance.
    ================ ======================================================

    Example::

        def send_flow_mod(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            match = ofp_parser.OFPMatch(in_port=1)
            cookie = 0
            command = ofp.OFPFC_ADD
            idle_timeout = hard_timeout = 0
            priority = 32768
            buffer_id = 0xffffffff
            out_port = ofproto.OFPP_NONE
            flags = 0
            actions = [ofp_parser.OFPActionOutput(ofp.OFPP_NORMAL, 0)]
            req = ofp_parser.OFPFlowMod(
                datapath, match, cookie, command, idle_timeout, hard_timeout,
                priority, buffer_id, out_port, flags, actions)
            datapath.send_msg(req)
    """

    def __init__(self, datapath, match=None, cookie=0,
                 command=ofproto.OFPFC_ADD,
                 idle_timeout=0, hard_timeout=0,
                 priority=ofproto.OFP_DEFAULT_PRIORITY,
                 buffer_id=0xffffffff, out_port=ofproto.OFPP_NONE,
                 flags=0, actions=None):
        super(OFPFlowMod, self).__init__(datapath)
        self.match = OFPMatch() if match is None else match
        self.cookie = cookie
        self.command = command
        self.idle_timeout = idle_timeout
        self.hard_timeout = hard_timeout
        self.priority = priority
        self.buffer_id = buffer_id
        self.out_port = out_port
        self.flags = flags
        self.actions = [] if actions is None else actions

    def _serialize_body(self):
        offset = ofproto.OFP_HEADER_SIZE
        self.match.serialize(self.buf, offset)

        offset += ofproto.OFP_MATCH_SIZE
        msg_pack_into(ofproto.OFP_FLOW_MOD_PACK_STR0, self.buf, offset,
                      self.cookie, self.command,
                      self.idle_timeout, self.hard_timeout,
                      self.priority, self.buffer_id, self.out_port,
                      self.flags)

        offset = ofproto.OFP_FLOW_MOD_SIZE
        if self.actions is not None:
            for a in self.actions:
                a.serialize(self.buf, offset)
                offset += a.len

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPFlowMod, cls).parser(
            datapath, version, msg_type, msg_len, xid, buf)
        offset = ofproto.OFP_HEADER_SIZE

        msg.match = OFPMatch.parse(msg.buf, offset)
        offset += ofproto.OFP_MATCH_SIZE

        (msg.cookie, msg.command, msg.idle_timeout, msg.hard_timeout,
         msg.priority, msg.buffer_id, msg.out_port,
         msg.flags) = struct.unpack_from(
            ofproto.OFP_FLOW_MOD_PACK_STR0, msg.buf, offset)
        offset = ofproto.OFP_FLOW_MOD_SIZE

        actions = []
        while offset < msg_len:
            a = OFPAction.parser(buf, offset)
            actions.append(a)
            offset += a.len
        msg.actions = actions

        return msg


@_set_msg_type(ofproto.OFPT_PORT_MOD)
class OFPPortMod(MsgBase):
    """
    Port modification message

    The controller send this message to modify the behavior of the port.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    port_no          Port number to modify.
    hw_addr          The hardware address that must be the same as hw_addr
                     of ``OFPPhyPort`` of ``OFPSwitchFeatures``.
    config           Bitmap of configuration flags.

                     | OFPPC_PORT_DOWN
                     | OFPPC_NO_STP
                     | OFPPC_NO_RECV
                     | OFPPC_NO_RECV_STP
                     | OFPPC_NO_FLOOD
                     | OFPPC_NO_FWD
                     | OFPPC_NO_PACKET_IN
    mask             Bitmap of configuration flags above to be changed
    advertise        Bitmap of the following flags.

                     | OFPPF_10MB_HD
                     | OFPPF_10MB_FD
                     | OFPPF_100MB_HD
                     | OFPPF_100MB_FD
                     | OFPPF_1GB_HD
                     | OFPPF_1GB_FD
                     | OFPPF_10GB_FD
                     | OFPPF_COPPER
                     | OFPPF_FIBER
                     | OFPPF_AUTONEG
                     | OFPPF_PAUSE
                     | OFPPF_PAUSE_ASYM
    ================ ======================================================

    Example::

        def send_port_mod(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            port_no = 3
            hw_addr = 'fa:c8:e8:76:1d:7e'
            config = 0
            mask = (ofp.OFPPC_PORT_DOWN | ofp.OFPPC_NO_RECV |
                    ofp.OFPPC_NO_FWD | ofp.OFPPC_NO_PACKET_IN)
            advertise = (ofp.OFPPF_10MB_HD | ofp.OFPPF_100MB_FD |
                         ofp.OFPPF_1GB_FD | ofp.OFPPF_COPPER |
                         ofp.OFPPF_AUTONEG | ofp.OFPPF_PAUSE |
                         ofp.OFPPF_PAUSE_ASYM)
            req = ofp_parser.OFPPortMod(datapath, port_no, hw_addr, config,
                                        mask, advertise)
            datapath.send_msg(req)
    """
    _TYPE = {
        'ascii': [
            'hw_addr',
        ]
    }

    def __init__(self, datapath, port_no=0, hw_addr='00:00:00:00:00:00',
                 config=0, mask=0, advertise=0):
        super(OFPPortMod, self).__init__(datapath)
        self.port_no = port_no
        self.hw_addr = hw_addr
        self.config = config
        self.mask = mask
        self.advertise = advertise

    def _serialize_body(self):
        msg_pack_into(ofproto.OFP_PORT_MOD_PACK_STR,
                      self.buf, ofproto.OFP_HEADER_SIZE,
                      self.port_no, addrconv.mac.text_to_bin(self.hw_addr),
                      self.config, self.mask, self.advertise)


@_set_msg_reply(OFPBarrierReply)
@_set_msg_type(ofproto.OFPT_BARRIER_REQUEST)
class OFPBarrierRequest(MsgBase):
    """
    Barrier request message

    The controller sends this message to ensure message dependencies have
    been met or receive notifications for completed operations.

    Example::

        def send_barrier_request(self, datapath):
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPBarrierRequest(datapath)
            datapath.send_msg(req)
    """

    def __init__(self, datapath):
        super(OFPBarrierRequest, self).__init__(datapath)


class OFPStatsRequest(MsgBase):
    def __init__(self, datapath, flags):
        assert flags == 0       # none yet defined

        super(OFPStatsRequest, self).__init__(datapath)
        self.type = self.__class__.cls_stats_type
        self.flags = flags

    def _serialize_stats_body(self):
        pass

    def _serialize_body(self):
        msg_pack_into(ofproto.OFP_STATS_MSG_PACK_STR,
                      self.buf, ofproto.OFP_HEADER_SIZE,
                      self.type, self.flags)
        self._serialize_stats_body()


class OFPFlowStatsRequestBase(OFPStatsRequest):
    def __init__(self, datapath, flags, match, table_id, out_port):
        super(OFPFlowStatsRequestBase, self).__init__(datapath, flags)
        self.match = match
        self.table_id = table_id
        self.out_port = out_port

    def _serialize_stats_body(self):
        offset = ofproto.OFP_STATS_MSG_SIZE
        self.match.serialize(self.buf, offset)

        offset += ofproto.OFP_MATCH_SIZE
        msg_pack_into(ofproto.OFP_FLOW_STATS_REQUEST_ID_PORT_STR,
                      self.buf, offset, self.table_id, self.out_port)


nx_actions.generate(
    'ryu.ofproto.ofproto_v1_0',
    'ryu.ofproto.ofproto_v1_0_parser'
)
