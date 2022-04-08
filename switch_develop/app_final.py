import ipaddress
import signal

import sys
import os
import time
from random import random
from subprocess import Popen

from scapy.interfaces import get_if_list
from scapy.layers.inet import UDP
from scapy.packet import Raw
from scapy.sendrecv import sniff, send, sendp, AsyncSniffer
from scapy.supersocket import L3RawSocket

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
sys.path.append("/root/")

from scapy.config import conf

from ryu.app.simple_monitor_13 import *

global app_mgr
conf.verb = 2
x = 0
hub.patch(thread=False)
state = "client"
global ctrl_addr


def timeout_handler(num, stack):
    # global app_mgr
    print("Received SIGALRM")
    app_mgr.close()


def long_running_function(app_manager, app_list):
    print("Launching apps")
    app_manager.run_apps(app_list)


def examine_ch_packet(packet):
    global ctrl_addr
    payload = packet[Raw].decode()
    try:
        address = ipaddress.IPv4Address(payload)
    except:
        return
    print(address)
    ctrl_addr = address


if __name__ == '__main__':
    ctrl_addr = None
    print("Lancio l'applicazione principale...")
    signal.signal(signal.SIGALRM, timeout_handler)
    CONF(project='ryu', version='simple-switch 4', )
    log.init_log()
    # app_lists = ["ryu.app.simple_monitor_13",
    #              'ryu.controller.client_bobi_handler']
    app_lists = ['ryu.clusterhead.rest_clusterhead',
                 'ryu.app.ofctl.service',
                 'ryu.controller.ofp_handler',
                 'ryu.app.ofctl_rest']
    app_mgr = app_manager.AppManager.get_instance()
    # app_mgr.run_apps(app_lists)
    while x < 10:
        if random() < 0.3:
            print("Announcing myself as clusterhead")
            for iface in [interface for interface in get_if_list()
                          if "lo" not in interface
                             and "ovs" not in interface]:
                sendp(UDP(dport=6969) / (Raw("172.15.69.23".encode())), iface=iface)
            signal.alarm(3)
            try:
                long_running_function(app_mgr, app_lists)
            except hub.TaskExit:
                pass
            except Exception as e:
                print(e)
        else:
            print("Listening for clusterhead announce")
            t = AsyncSniffer(filter="udp", lfilter=lambda x: x[UDP].dport == 6969, timeout=3, count=1)
            t.start()
            print("Starting base leaf node operation")
            t.join()
            results = t.results
            print(results)
            print(f"ovs-vsctl set-controller {ctrl_addr}")
            # hub.sleep(3)
        x += 1
    signal.alarm(0)
    app_mgr.close()
