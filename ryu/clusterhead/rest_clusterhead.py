# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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

import json

from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import Response
from ryu.app.wsgi import route
from ryu.app.wsgi import WSGIApplication
from ryu.base import app_manager
from ryu.lib import dpid as dpid_lib, hub
import ryu.app.ofctl.api as ofctl_api


# REST API for switch configuration
#
# get all the switches
# GET /v1.0/topology/get_datapath
#
# where
# <dpid>: datapath id in 16 hex


class TopologyAPI(app_manager.RyuApp):
    _CONTEXTS = {
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(TopologyAPI, self).__init__(*args, **kwargs)

        wsgi = kwargs['wsgi']
        wsgi.register(ClusterHeadController, {'clusterhead_api_app': self})

    def close(self):
        """
        L3Rawsocket.sr1(iface=)
        """
        print("Exiting clusterhead service")
        raise hub.TaskExit


class ClusterHeadController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(ClusterHeadController, self).__init__(req, link, data, **config)
        self.topology_api_app = data['clusterhead_api_app']

    @route('topology', '/v1.0/topology/get_datapath',
           methods=['GET'])
    def list_switches(self, req, **kwargs):
        return self._switches(req, **kwargs)

    def _switches(self, req, **kwargs):
        dpid = None
        if 'dpid' in kwargs:
            dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        switches = ofctl_api.get_datapath(self.topology_api_app)
        body = json.dumps([switch.id for switch in switches])
        return Response(content_type='application/json', body=body)
