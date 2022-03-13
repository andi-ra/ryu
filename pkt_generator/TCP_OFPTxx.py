"""Questo è il file che mi serve per testare in TCP la riuscita della connessione """
import copy
import random
from threading import Thread

import dataclasses
import socket
from time import sleep

from pyof.foundation.basic_types import UBInt32, UBInt16, UBInt8, UBInt64, DPID
from pyof.utils import unpack, validate_packet
from pyof.v0x04.asynchronous.packet_in import PacketIn
from pyof.v0x01.common.action import ActionType
from pyof.v0x04.common.header import Header
from pyof.v0x04.controller2switch.features_reply import FeaturesReply
from pyof.v0x01.controller2switch.features_reply import Capabilities
from pyof.v0x04.asynchronous.packet_in import PacketInReason
from pyof.v0x04.controller2switch.flow_mod import FlowMod
from pyof.v0x04.symmetric.echo_reply import EchoReply
from pyof.v0x04.symmetric.echo_request import EchoRequest
from pyof.v0x04.symmetric.hello import Hello
from scapy.config import conf
from scapy.layers.inet import IP, ICMP, TCP
from scapy.layers.l2 import Ether, ARP
from scapy.packet import Raw, Padding
from scapy.sendrecv import sr1
from scapy.supersocket import StreamSocket
from scapy.utils import rdpcap


# sniff(prn=lambda x:unpack(bytes(x.payload.load)), filter="tcp", lfilter = lambda x: x[TCP].flags !="A")

@dataclasses.dataclass
class TLV:
    """
    Formato generico di rappresentazione dei parametri di rete, tutti sono in questo modo
    """
    type: int
    length: int
    value: bytes
    subtype: int = None


class LLDP(object):
    """
    Questa classe rappresenta il pacchetto LLDP come da `RFC 4957 <https://datatracker.ietf.org/doc/html/rfc4957>`_. Una
    delle "references" lì punta allo standard `IEEE-802.1ab <https://standards.ieee.org/standard/802_1AB-2016.html>`_.
    Troviamo in quello standard la descrizione del LLDPDU per la segnalazione dei dispositivi sulla rete.

    =========  ========  ========
    Chassis    Port      TTL
    =========  ========  ========
    Type       Type      Type
    Subtype    Subtype   Subtype
    Length     Length    Length
    Value      Value     Value
    =========  ========  ========

    """

    def __init__(self, raw_str):
        self._raw = bytes(raw_str)

    @property
    def chassis(self):
        return TLV(
            type=int(bytes.hex(self._raw[0:1]), 16) >> 1,
            length=int(bytes.hex(self._raw[1:2]), 16),
            subtype=int(bytes.hex(self._raw[2:3]), 16),
            value=self._raw[3:24],
        )

    @property
    def port(self):
        return TLV(
            type=int(bytes.hex(self._raw[24:25]), 16) >> 1,
            length=int(bytes.hex(self._raw[25:26]), 16),
            subtype=int(bytes.hex(self._raw[26:27]), 16),
            value=self._raw[27:31]
        )

    @property
    def TTL(self):
        return TLV(
            type=bytes.hex(self._raw[31:32]),
            length=bytes.hex(self._raw[32:33]),
            value=bytes.hex(self._raw[33:35]),
        )


def echo_loop(stream_sock, packet):
    j = 0
    first_request = copy.deepcopy(packet)
    header = unpack(bytes(first_request.res[0].answer)).header
    while j < 10:
        result, _ = stream_sock.sr(Raw(EchoReply(xid=header.xid).pack()))
        reply_packet = unpack(bytes(result.res[0].answer))
        print(reply_packet.header)
        header = reply_packet.header
        j += 1


TIMEOUT = 2
conf.verb = 0
if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("ip", help="ip address of peer")
    args = parser.parse_args()
    print(args.ip)
    sleep(1) #Facilita l'esecuzione
    ip = args.ip
    print("Starting TCP sender OpenFlow packet forging...")
    packet = IP(dst=str(ip), ttl=20) / ICMP()
    reply = sr1(packet, timeout=TIMEOUT)
    if not (reply is None):
        print(ip, "is online")
    else:
        print("Timeout waiting for %s" % packet[IP].dst)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    pkt_list = rdpcap("openflow.pcapng")
    # Connect the socket to the port where the server is listening
    server_address = (str(ip), 6653)
    print('connecting to %s port %s' % server_address)
    sock.connect(server_address)
    mystream = StreamSocket(sock)
    fake_pkt = Ether(pkt_list[11])
    print(fake_pkt.payload)
    try:
        print('sending ')
        payload = Hello()
        scapy_pkt = Raw(payload.pack())
        ans = mystream.sr1(scapy_pkt)
        print(ans.payload)
        # print(unpack(bytes(ans.answer)))

        packet = FeaturesReply(xid=UBInt8(1), datapath_id=DPID(str('00:00:00:00:00:00:02:01')),
                               n_buffers=UBInt32(1), n_tables=UBInt8(0), capabilities=Capabilities.OFPC_ARP_MATCH_IP,
                               auxiliary_id=UBInt8(1), reserved=UBInt32(0), )
        ans, _ = mystream.sr(Raw(packet.pack()))
        print(unpack(bytes(ans.res[0].answer)))
        echo_packet = EchoRequest(xid=random.Random(), data=b'Ciao')
        ans, _ = mystream.sr(Raw(packet.pack()))
        response = unpack(bytes(ans.res[0].answer))
        pkt_header = response.header
        print("Starting echo loop")
        ans, _ = mystream.sr(Raw(EchoReply(xid=pkt_header.xid).pack()))
        response = unpack(bytes(ans.res[0].answer))
        print(response.header)
        packet = FeaturesReply(xid=UBInt8(1), datapath_id=DPID(str('00:00:00:00:00:00:02:01')),
                               n_buffers=UBInt32(1), n_tables=UBInt8(0), capabilities=Capabilities.OFPC_ARP_MATCH_IP,
                               auxiliary_id=UBInt8(1), reserved=UBInt32(0), )
        response, _ = mystream.sr(Raw(packet.pack()))
        print(unpack(bytes(response.res[0].answer)))
        t = Thread(target=echo_loop, args=(mystream, response))
        t.start()
        i = 0
        while i < 3:
            print("Sending PACKET_IN")
            packet_in = PacketIn(buffer_id=int(1), total_len=int(len(b"Bobi! Bobi!")),
                                 reason=PacketInReason.OFPR_INVALID_TTL, data=b"Bobi! Bobi!",
                                 table_id=UBInt8(0), cookie=UBInt64(random.randint(0, 100)))
            mystream.send(Raw(packet_in.pack()))
            sleep(1)
            i += 1

        t.join()

    finally:
        print('closing socket')
        sock.close()
