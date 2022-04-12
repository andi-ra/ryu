import ipaddress
import re
import signal
import subprocess

import sys
import os
import time
from random import random
from subprocess import Popen

from scapy.arch import get_if_addr
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
conf.verb = 0
x = 0
hub.patch(thread=False)
state = "client"
global ctrl_addr
mode = "Cycle"
if len(sys.argv) > 1:
    mode = sys.argv[1]


def timeout_handler(num, stack):
    # global app_mgr
    print("Received SIGALRM")
    app_mgr.close()


def long_running_function(app_manager, app_list):
    print("Launching apps")
    app_manager.run_apps(app_list)


def clusterhead_operation(app_mgr, app_lists):
    try:
        long_running_function(app_mgr, app_lists)
    except hub.TaskExit:
        pass
    except Exception as e:
        print(e)


def client_operation():
    print("Listening for clusterhead announce")
    t = AsyncSniffer(filter="udp", lfilter=lambda x: x[UDP].dport == 6969, timeout=6, count=1, iface="eth0")
    t.start()
    print("Starting base leaf node operation")
    t.join()
    results = t.results
    print(results)
    try:
        ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', str(bytes(results[0].payload)))
    except IndexError:
        print("No packet received...")
        return
    try:
        address = ipaddress.IPv4Address(str(ip[0]))
    except ipaddress.AddressValueError:
        address = ipaddress.IPv4Address('192.168.0.'+str(ip[0]).split(".")[3])
    out = subprocess.run(f"ovs-vsctl set-controller br0 tcp:{str(address)}:6653", shell=True)
    print(out)
    time.sleep(5)


if __name__ == '__main__':
    print("Lancio l'applicazione principale...")
    log.init_log()
    app_lists = ['ryu.clusterhead.rest_clusterhead',
                 'ryu.app.ofctl.service',
                 'ryu.app.shortest_path',
                 'ryu.controller.ofp_handler',
                 'ryu.app.ofctl_rest',]
    app_mgr = app_manager.AppManager.get_instance()
    while x < 100:
        signal.signal(signal.SIGALRM, timeout_handler)
        if "ctrl" in mode:
            clusterhead_operation(app_mgr, app_lists)
        elif "client" in mode:
            client_operation()
        else:
            if random() < 0.3:
                signal.alarm(10)
                clusterhead_operation(app_mgr, app_lists)
            else:
                client_operation()
        x += 1
    app_mgr.close()


#  pkt=Ether(dst="FF:FF:FF:FF:FF:FF")/IP(dst="192.168.2.255")/Padding("XXXXX")