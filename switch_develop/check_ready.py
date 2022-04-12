import csv
import ipaddress
import os
import sys
import time

from scapy.config import conf

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
sys.path.append("/root/")

try:
    from ryu.base import app_manager
except ModuleNotFoundError:
    from base import app_manager
import logging

try:
    from ryu.app import simple_switch_13
except ModuleNotFoundError:
    from app import simple_switch_13

try:
    from ryu.controller.handler import DEAD_DISPATCHER
except:
    from controller.handler import DEAD_DISPATCHER

try:
    from ryu.controller import bobi_event
except ModuleNotFoundError:
    from controller import bobi_event

from oslo_config import cfg

try:
    from ryu.lib import hub
except ModuleNotFoundError:
    from lib import hub
try:
    from ryu import log
except ModuleNotFoundError:
    import hub
from ryu import log
from ryu.base import app_manager

hub.patch(thread=True)
CONF = cfg.CONF
log.early_init_log(logging.DEBUG)
from scapy.arch import read_routes, get_if_addr
from scapy.interfaces import get_if_list
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp

conf.verbose = 0
if __name__ == '__main__':
    print("Checking network status")
    local_ips = {line[4] for line in read_routes() if not ipaddress.IPv4Address(line[4]).is_loopback}
    iface_macs = [get_if_addr(i) for i in get_if_list()]
    print(f"Local ifaces: {local_ips}")
    default_br_gw = [f"192.168.{num}.1" for num in range(0, 254)]
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.0.0/29"), timeout=2)
    for snd, rcv, in ans:
        print(f"{rcv[Ether].src} --> {rcv[ARP].pdst}")
        print(f"{snd[Ether].src} --> {snd[ARP].pdst}")
    nw_dst = {snd[ARP].pdst for snd, rcv, in ans if
              snd[ARP].pdst not in local_ips and snd[ARP].pdst not in default_br_gw}
    print(f"Responding ips: {nw_dst}")
    with open('/root/ryu/peers.csv', "w", newline='') as csvfile:
        fieldnames = ["Dest_Addr"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        for addr in nw_dst:
            writer.writerow({"Dest_Addr": str(addr)})
    CONF(project='ryu', version='simple-switch 4', )
    log.init_log()
    app_lists = ['ryu.controller.client_bobi_handler',
                 "ryu.app.simple_monitor_13",
                 "ryu.app.simple_switch_13", ]
    app_mgr = app_manager.AppManager.get_instance()
    app_mgr.run_apps(app_lists)

    time.sleep(999)

    app_mgr.close()
