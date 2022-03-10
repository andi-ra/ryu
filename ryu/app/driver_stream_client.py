import os
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
sys.path.append("/root/")

try:
    from ryu.base import app_manager
except ModuleNotFoundError:
    from base import app_manager
import logging

from app import simple_switch_13

try:
    from ryu.controller import bobi_event
except ModuleNotFoundError:
    from controller import bobi_event

from lib import hub
from oslo_config import cfg

try:
    from ryu.lib import hub
except ModuleNotFoundError:
    from lib import hub
try:
    from ryu import log
except ModuleNotFoundError:
    import hub

hub.patch(thread=True)
CONF = cfg.CONF
log.early_init_log(logging.DEBUG)

if __name__ == '__main__':
    print("Starting ryu in client mode")
    CONF(project='ryu', version='simple-switch 4', )
    log.init_log()
    app_lists = ['ryu.controller.client_bobi_handler',]
    app_mgr = app_manager.AppManager.get_instance()
    app_mgr.run_apps(app_lists)
    time.sleep(999)

    app_mgr.close()
