import sys
import os
import time
from random import random

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
sys.path.append("/root/")

from scapy.config import conf

from ryu.app.simple_monitor_13 import *

conf.verb = 0
x = 0
hub.patch(thread=False)
if __name__ == '__main__':
    print("Lancio l'applicazione principale...")
    CONF(project='ryu', version='simple-switch 4', )
    log.init_log()
    # app_lists = ["ryu.app.simple_monitor_13",
    #              'ryu.controller.client_bobi_handler']
    app_lists = ['ryu.clusterhead.rest_clusterhead',
                 'ryu.app.ofctl.service',
                 'ryu.controller.ofp_handler',
                 'ryu.app.ofctl_rest']
    app_mgr = app_manager.AppManager.get_instance()
    app_mgr.run_apps(app_lists)
    time.sleep(20000)
    # while x < 4:
    #     if random() < 0.3:
    #         print("Starting clusterhead operation")
    #         app_mgr.run_apps(app_lists)
    #         print("Exiting clusterhead behavior")
    #         app_mgr.close()
    #     else:
    #         print("Starting base leaf node operation")
    #         print("ovs-vsctl set-controller ipaddr")
    #     hub.sleep(3)
    #     x += 1
    app_mgr.close()
