"""
The main component of OpenFlow client_server.

- Handle connections from switches
- Generate and route events to appropriate entities like Ryu applications

"""

import contextlib
import csv
import ipaddress
import logging
import random
import ssl
from socket import IPPROTO_TCP
from socket import SHUT_WR
from socket import TCP_NODELAY
from socket import timeout as SocketTimeout

from scapy.arch import read_routes
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp

import ryu.base.app_manager
from ryu import cfg
from ryu.controller import ofp_event
from ryu.controller.handler import HANDSHAKE_DISPATCHER, DEAD_DISPATCHER
from ryu.lib import hub
from ryu.lib.dpid import dpid_to_str
from ryu.lib.hub import spawn
from ryu.ofproto import nx_match
from ryu.ofproto import ofproto_common
from ryu.ofproto import ofproto_parser
from ryu.ofproto import ofproto_protocol
from ryu.ofproto import ofproto_v1_0

LOG = logging.getLogger('ryu.controller.bobi_controller')

DEFAULT_OFP_HOST = '0.0.0.0'
DEFAULT_OFP_SW_CON_INTERVAL = 1
LISTEN_CONNECT_PORT = 6653
CONF = cfg.CONF
CFG_FILE_PEERS = '/root/ryu/peers.csv'


class ClientOpenFlowPeer(object):
    def __init__(self):
        LOG.debug('Initialization')
        super(ClientOpenFlowPeer, self).__init__()
        self.addr = []
        if not CONF.ofp_tcp_listen_port and not CONF.ofp_ssl_listen_port:
            self.ofp_tcp_listen_port = ofproto_common.OFP_TCP_PORT
            self.ofp_ssl_listen_port = ofproto_common.OFP_SSL_PORT
            # For the backward compatibility, we spawn a server loop
            # listening on the old OpenFlow listen port 6633.
        else:
            self.ofp_tcp_listen_port = CONF.ofp_tcp_listen_port
            self.ofp_ssl_listen_port = CONF.ofp_ssl_listen_port
        with open(CFG_FILE_PEERS, newline='') as csvfile:
            spamreader = csv.reader(csvfile, delimiter=' ', quotechar='|')
            for row in spamreader:
                for address in row:
                    self.addr.append(ipaddress.IPv4Address(address))

        # Example:
        # self._clients = {
        #     ('127.0.0.1', 6653): <instance of StreamClient>,
        # }
        # self.clients ?? il dictionary dei client che hanno un client loop
        # ?? diverso da self.addr poich?? quest'ultima ?? solo la lista degli
        # ip che sono raggiungibili dal mio client OpenFlow switch peer
        self._clients = {}
        spawn(self._update_network)
        spawn(self._monitor_network)
        spawn(self._align_clients_addr)

    def _stop(self):
        print("Scheduling stop in 5 seconds....")
        hub.sleep(5)
        raise hub.TaskExit

    def _update_network(self):
        LOG.debug("Spawning network status checker thread")
        while True:
            LOG.debug("Checking network status")
            local_ips = {line[4] for line in read_routes() if not ipaddress.IPv4Address(line[4]).is_loopback}
            default_br_gw = [f"192.168.{num}.1" for num in range(0, 254)]
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.0.0/29"), timeout=2)
            nw_dst = {snd[ARP].pdst for snd, rcv, in ans if
                      snd[ARP].pdst not in local_ips and snd[ARP].pdst not in default_br_gw}
            with open(CFG_FILE_PEERS, "w", newline='') as csvfile:
                fieldnames = ["Dest_Addr"]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                for addr in nw_dst:
                    writer.writerow({"Dest_Addr": str(addr)})
            hub.sleep(1)

    def _monitor_network(self):
        LOG.debug("Spawning network status updater thread")
        while True:
            with open(CFG_FILE_PEERS, newline='') as csvfile:
                spamreader = csv.reader(csvfile, delimiter=' ', quotechar='|')
                for row in spamreader:
                    for address in row:
                        if address not in self.addr:
                            self.addr.append(ipaddress.IPv4Address(address))
            hub.sleep(1)

    def _align_clients_addr(self):
        LOG.debug("Spawning aligner thread")
        while True:
            for address in self.addr:
                index = (str(address), LISTEN_CONNECT_PORT)
                if self._clients.get(index) is None:
                    LOG.debug("New peer in cfg file found, connecting now...")
                    self.spawn_client_loop((str(address), LISTEN_CONNECT_PORT))
            hub.sleep(1)

    # entry point
    def __call__(self):
        LOG.debug('call')
        for address in self.addr:
            self.spawn_client_loop((str(address), LISTEN_CONNECT_PORT))

    def spawn_client_loop(self, addr, interval=None):
        interval = interval or CONF.ofp_switch_connect_interval
        client = hub.StreamClient(addr)
        hub.spawn(client.connect_loop, datapath_connection_factory, interval)
        LOG.debug("New client connected")
        self._clients[addr] = client

    def stop_client_loop(self, addr):
        client = self._clients.get(addr, None)
        if client is not None:
            client.stop()


def _deactivate(method):
    def deactivate(self):
        try:
            method(self)
        finally:
            try:
                self.socket.close()
            except IOError:
                pass

    return deactivate


class Datapath(ofproto_protocol.ProtocolDesc):
    """
    A class to describe an OpenFlow switch connected to this client_server.

    An instance has the following attributes.

    .. tabularcolumns:: |l|L|

    ==================================== ======================================
    Attribute                            Description
    ==================================== ======================================
    id                                   64-bit OpenFlow Datapath ID.
                                         Only available for
                                         ryu.client_server.handler.MAIN_DISPATCHER
                                         phase.
    ofproto                              A module which exports OpenFlow
                                         definitions, mainly constants appeared
                                         in the specification, for the
                                         negotiated OpenFlow version.  For
                                         example, ryu.ofproto.ofproto_v1_0 for
                                         OpenFlow 1.0.
    ofproto_parser                       A module which exports OpenFlow wire
                                         message encoder and decoder for the
                                         negotiated OpenFlow version.
                                         For example,
                                         ryu.ofproto.ofproto_v1_0_parser
                                         for OpenFlow 1.0.
    ofproto_parser.OFPxxxx(datapath,...) A callable to prepare an OpenFlow
                                         message for the given switch.  It can
                                         be sent with Datapath.send_msg later.
                                         xxxx is a name of the message.  For
                                         example OFPFlowMod for flow-mod
                                         message.  Arguemnts depend on the
                                         message.
    set_xid(self, msg)                   Generate an OpenFlow XID and put it
                                         in msg.xid.
    send_msg(self, msg)                  Queue an OpenFlow message to send to
                                         the corresponding switch.  If msg.xid
                                         is None, set_xid is automatically
                                         called on the message before queueing.
    send_packet_out                      deprecated
    send_flow_mod                        deprecated
    send_flow_del                        deprecated
    send_delete_all_flows                deprecated
    send_barrier                         Queue an OpenFlow barrier message to
                                         send to the switch.
    send_nxt_set_flow_format             deprecated
    is_reserved_port                     deprecated
    ==================================== ======================================
    """

    def __init__(self, socket, address):
        super(Datapath, self).__init__()

        self.socket = socket
        self.socket.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        self.socket.settimeout(CONF.socket_timeout)
        self.address = address
        self.is_active = True

        # The limit is arbitrary. We need to limit queue size to
        # prevent it from eating memory up.
        self.send_q = hub.Queue(16)
        self._send_q_sem = hub.BoundedSemaphore(self.send_q.maxsize)

        self.echo_request_interval = 1  # CONF.echo_request_interval
        # Todo: Questo max unreplied rompe le scatole...
        self.max_unreplied_echo_requests = 15  # CONF.maximum_unreplied_echo_requests
        self.unreplied_echo_requests = []

        self.xid = random.randint(0, self.ofproto.MAX_XID)
        self.id = None  # datapath_id is unknown yet
        self._ports = None
        self.flow_format = ofproto_v1_0.NXFF_OPENFLOW10
        self.ofp_brick = ryu.base.app_manager.lookup_service_brick('ofp_event')
        self.state = None  # for pylint
        self.set_state(HANDSHAKE_DISPATCHER)

    def _close_write(self):
        # Note: Close only further sends in order to wait for the switch to
        # disconnect this connection.
        try:
            self.socket.shutdown(SHUT_WR)
        except (EOFError, IOError):
            pass

    def close(self):
        self.set_state(DEAD_DISPATCHER)
        self._close_write()

    def set_state(self, state):
        if self.state == state:
            return
        self.state = state
        ev = ofp_event.EventOFPStateChange(self)
        ev.state = state
        if self.ofp_brick is not None:
            self.ofp_brick.send_event_to_observers(ev, state)

    # Low level socket handling layer
    @_deactivate
    def _recv_loop(self):
        buf = bytearray()
        count = 0
        min_read_len = remaining_read_len = ofproto_common.OFP_HEADER_SIZE

        while self.state != DEAD_DISPATCHER:
            try:
                read_len = min_read_len
                if remaining_read_len > min_read_len:
                    read_len = remaining_read_len
                ret = self.socket.recv(read_len)
            except SocketTimeout:
                continue
            except ssl.SSLError:
                # eventlet throws SSLError (which is a subclass of IOError)
                # on SSL socket read timeout; re-try the loop in this case.
                continue
            except (EOFError, IOError):
                break

            if not ret:
                break

            buf += ret
            buf_len = len(buf)
            while buf_len >= min_read_len:
                (version, msg_type, msg_len, xid) = ofproto_parser.header(buf)
                if msg_len < min_read_len:
                    # Someone isn't playing nicely; log it, and try something sane.
                    LOG.debug("Message with invalid length %s received from switch at address %s",
                              msg_len, self.address)
                    msg_len = min_read_len
                if buf_len < msg_len:
                    remaining_read_len = (msg_len - buf_len)
                    break

                msg = ofproto_parser.msg(
                    self, version, msg_type, msg_len, xid, buf[:msg_len])
                LOG.debug('queue msg %s cls %s', msg, msg.__class__)
                if msg:
                    ev = ofp_event.ofp_msg_to_ev(msg)
                    if self.ofp_brick is not None:
                        self.ofp_brick.send_event_to_observers(ev, self.state)

                        def dispatchers(x):
                            return x.callers[ev.__class__].dispatchers

                        handlers = [handler for handler in
                                    self.ofp_brick.get_handlers(ev) if
                                    self.state in dispatchers(handler)]
                        for handler in handlers:
                            handler(ev)

                buf = buf[msg_len:]
                buf_len = len(buf)
                remaining_read_len = min_read_len

                # We need to schedule other greenlets. Otherwise, ryu
                # can't accept new switches or handle the existing
                # switches. The limit is arbitrary. We need the better
                # approach in the future.
                count += 1
                if count > 2048:
                    count = 0
                    hub.sleep(0)

    def _send_loop(self):
        try:
            while self.state != DEAD_DISPATCHER:
                buf, close_socket = self.send_q.get()
                self._send_q_sem.release()
                self.socket.sendall(buf)
                if close_socket:
                    break
        except SocketTimeout:
            LOG.debug("Socket timed out while sending data to switch at address %s",
                      self.address)
        except IOError as ioe:
            # Convert ioe.errno to a string, just in case it was somehow set to None.
            errno = "%s" % ioe.errno
            LOG.debug("Socket error while sending data to switch at address %s: [%s] %s",
                      self.address, errno, ioe.strerror)
        finally:
            q = self.send_q
            # First, clear self.send_q to prevent new references.
            self.send_q = None
            # Now, drain the send_q, releasing the associated semaphore for each entry.
            # This should release all threads waiting to acquire the semaphore.
            try:
                while q.get(block=False):
                    self._send_q_sem.release()
            except hub.QueueEmpty:
                pass
            # Finally, disallow further sends.
            self._close_write()

    def send(self, buf, close_socket=False):
        msg_enqueued = False
        self._send_q_sem.acquire()
        if self.send_q:
            self.send_q.put((buf, close_socket))
            msg_enqueued = True
        else:
            self._send_q_sem.release()
        if not msg_enqueued:
            LOG.debug('Datapath in process of terminating; send() to %s discarded.',
                      self.address)
        return msg_enqueued

    def set_xid(self, msg):
        self.xid += 1
        self.xid &= self.ofproto.MAX_XID
        msg.set_xid(self.xid)
        return self.xid

    def send_msg(self, msg, close_socket=False):
        assert isinstance(msg, self.ofproto_parser.MsgBase)
        if msg.xid is None:
            self.set_xid(msg)
        msg.serialize()
        # LOG.debug('send_msg %s', msg)
        return self.send(msg.buf, close_socket=close_socket)

    def _echo_request_loop(self):
        if not self.max_unreplied_echo_requests:
            return
        while (self.send_q and
               (len(self.unreplied_echo_requests) <= self.max_unreplied_echo_requests)):
            echo_req = self.ofproto_parser.OFPEchoRequest(self)
            self.unreplied_echo_requests.append(self.set_xid(echo_req))
            self.send_msg(echo_req)
            hub.sleep(self.echo_request_interval)
        self.close()

    def acknowledge_echo_reply(self, xid):
        try:
            self.unreplied_echo_requests.remove(xid)
        except ValueError:
            pass

    def serve(self):
        send_thr = hub.spawn(self._send_loop)

        # send hello message immediately
        hello = self.ofproto_parser.OFPHello(self)
        self.send_msg(hello)
        socket = self.socket
        echo_thr = hub.spawn(self._echo_request_loop)

        try:
            self._recv_loop()
        finally:
            hub.kill(send_thr)
            hub.kill(echo_thr)
            hub.joinall([send_thr, echo_thr])
            self.is_active = False

    #
    # Utility methods for convenience
    #
    def send_packet_out(self, buffer_id=0xffffffff, in_port=None,
                        actions=None, data=None):
        if in_port is None:
            in_port = self.ofproto.OFPP_NONE
        packet_out = self.ofproto_parser.OFPPacketOut(
            self, buffer_id, in_port, actions, data)
        self.send_msg(packet_out)

    def send_flow_mod(self, rule, cookie, command, idle_timeout, hard_timeout,
                      priority=None, buffer_id=0xffffffff,
                      out_port=None, flags=0, actions=None):
        if priority is None:
            priority = self.ofproto.OFP_DEFAULT_PRIORITY
        if out_port is None:
            out_port = self.ofproto.OFPP_NONE
        flow_format = rule.flow_format()
        assert (flow_format == ofproto_v1_0.NXFF_OPENFLOW10 or
                flow_format == ofproto_v1_0.NXFF_NXM)
        if self.flow_format < flow_format:
            self.send_nxt_set_flow_format(flow_format)
        if flow_format == ofproto_v1_0.NXFF_OPENFLOW10:
            match_tuple = rule.match_tuple()
            match = self.ofproto_parser.OFPMatch(*match_tuple)
            flow_mod = self.ofproto_parser.OFPFlowMod(
                self, match, cookie, command, idle_timeout, hard_timeout,
                priority, buffer_id, out_port, flags, actions)
        else:
            flow_mod = self.ofproto_parser.NXTFlowMod(
                self, cookie, command, idle_timeout, hard_timeout,
                priority, buffer_id, out_port, flags, rule, actions)
        self.send_msg(flow_mod)

    def send_flow_del(self, rule, cookie, out_port=None):
        self.send_flow_mod(rule=rule, cookie=cookie,
                           command=self.ofproto.OFPFC_DELETE,
                           idle_timeout=0, hard_timeout=0, priority=0,
                           out_port=out_port)

    def send_delete_all_flows(self):
        rule = nx_match.ClsRule()
        self.send_flow_mod(
            rule=rule, cookie=0, command=self.ofproto.OFPFC_DELETE,
            idle_timeout=0, hard_timeout=0, priority=0, buffer_id=0,
            out_port=self.ofproto.OFPP_NONE, flags=0, actions=None)

    def send_barrier(self):
        barrier_request = self.ofproto_parser.OFPBarrierRequest(self)
        return self.send_msg(barrier_request)

    def is_reserved_port(self, port_no):
        return port_no > self.ofproto.OFPP_MAX


def datapath_connection_factory(socket, address):
    LOG.debug('connected socket:%s address:%s', socket, address)
    with contextlib.closing(Datapath(socket, address)) as datapath:
        try:

            datapath.serve()
        except:
            # Something went wrong.
            # Especially malicious switch can send malformed packet,
            # the parser raise exception.
            # Can we do anything more graceful?
            if datapath.id is None:
                dpid_str = "%s" % datapath.id
            else:
                dpid_str = dpid_to_str(datapath.id)
            LOG.error("Error in the datapath %s from %s", dpid_str, address)
            raise
