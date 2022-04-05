# Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2014 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

# client for ryu.app.ofctl.service
import ryu.app.ofctl.api as ofctl_api
from ryu.base import app_manager


class MyApp(app_manager.RyuApp):

    def _my_handler(self, ev):
        # Get all datapath objects
        result = ofctl_api.get_datapath(self)

        # Get the datapath object which has the given dpid
        result = ofctl_api.get_datapath(self, dpid=1)

    def _my_handler(self, ev):
        # ...(snip)...
        msg = parser.OFPPortDescStatsRequest(datapath=datapath)
        result = ofctl_api.send_msg(
            self, msg,
            reply_cls=parser.OFPPortDescStatsReply,
            reply_multi=True)
        self.logger.debug("Modified version!!")
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
