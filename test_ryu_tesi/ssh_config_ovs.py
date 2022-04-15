"""Questo file lo uso per la configurazione senza controller dello switch"""
# REST API for switch configuration
#
# get all the switches
# GET /v1.0/topology/switches
#
# get the switch
# GET /v1.0/topology/switches/<dpid>
#
# get all the links
# GET /v1.0/topology/hosts
#
# get the links of a switch
# GET /v1.0/topology/links/<dpid>
#
# get all the hosts
# GET /v1.0/topology/hosts
#
# get the hosts of a switch
# GET /v1.0/topology/hosts/<dpid>
#
# where
# <dpid>: datapath id in 16 hex
import copy
import ipaddress
import json
import re
import shlex
import subprocess
from collections import OrderedDict
from random import randint
from time import sleep
from typing import List

import macaddress as macaddress
import matplotlib.pyplot as plt
import networkx as nx
import requests
from dataclasses import dataclass
from paramiko.client import SSHClient, AutoAddPolicy
from scapy.layers.inet import UDP
from scapy.layers.l2 import arping, ARP
from scapy.sendrecv import AsyncSniffer

from ryu.ofproto.ofproto_v1_3_parser import OFPPort
from ryu.topology.switches import Link, Port


class LinkNet(Link):

    def __init__(self, src, dst):
        super(LinkNet, self).__init__(src=src, dst=dst)
        self.link_data = {"loss_rate": "0", "delay": "0", "jitter": "0"}

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__,
                          sort_keys=True, indent=4)

    def __hash__(self):
        return hash(self.src) ^ hash(self.dst)

    def __eq__(self, other):
        return (hash(self.dst) == hash(other.src)) and (hash(other.dst) == hash(self.src))


class API_Port(Port):
    def __init__(self, elem):
        port = OFPPort(
            port_no=elem["port_no"],
            hw_addr=elem["hw_addr"],
            name=elem['name'],
            config=None,
            state=None,
            curr=None,
            advertised=None,
            supported=None,
            peer=None,
            curr_speed=None,
            max_speed=None)
        super(API_Port, self).__init__(dpid=elem['dpid'], ofpport=port, ofproto="1.3")

    def __str__(self):
        return f'Port<dpid={self.dpid}, port_no={self.port_no}, hw_addr:{self.hw_addr}>'

    def __hash__(self):
        return hash(self.dpid) ^ hash(self.port_no) ^ hash(self.hw_addr)

    def __eq__(self, other):
        return self.__hash__() == hash(other)


def NetworkToJson(linkset: LinkNet) -> str:
    json_string = ","
    json_string = json_string.join([link.toJSON() for link in list(linkset)])
    json_string = "[" + json_string + "]"
    return json_string


class RouteDict:
    def __init__(self, route_dict):
        self.route_dict = route_dict

    def __iter__(self):
        return RouteDictIterator(self.route_dict)


class RouteDictIterator:
    def __init__(self, route_dict: OrderedDict):
        self.dict_route = route_dict

    def __next__(self):
        try:
            (key, lista) = self.dict_route.popitem(last=False)
        except KeyError:
            raise StopIteration()
        return (key, lista)

    def __iter__(self):
        return self


@dataclass
class iface:
    ip_addr: ipaddress.IPv4Address
    hw_addr: str = str(macaddress.MAC('01-23-45-67-89-ab'))  # fake default!


@dataclass
class coppia_origine_destinazione:
    origine: iface
    destinazione: iface


@dataclass
class port:
    port_number: int
    port_name: str
    hw_addr: str = str(macaddress.MAC('01-23-45-67-89-ab'))  # fake default, duplicate...


@dataclass
class switch:
    address: ipaddress.IPv4Address
    controller: ipaddress.IPv4Address = ipaddress.ip_address("0.0.0.0")
    switch_ports: List[port] = None


list_of_commands = [
    'ovs-vsctl set Bridge br0 stp_enable=true',
    'ovs-vsctl set-controller br0 tcp:192.168.0.9:6633',
    'ovs-ofctl del-flows br0',
]

list_of_switches = []
list_of_datapaths = []

lista_oppie_origine_destinazione = [
    coppia_origine_destinazione(
        origine=iface(ip_addr=ipaddress.ip_address("192.168.1.2"),
                      hw_addr=str(macaddress.MAC("08:00:00:00:00:01")).replace('-', ':')),
        destinazione=iface(ip_addr=ipaddress.ip_address("192.168.1.3"),
                           hw_addr=str(macaddress.MAC("08:00:00:00:00:02")).replace('-', ':'))
    ),
]

list_file_template = [
    "../config_ovs/templates/forward_route",
    # "../config_ovs/templates/group_routes",
]


def execute_command(cmd: str, client_param) -> str:
    # Optionally, send data via STDIN, and shutdown when done
    global stdin, stdout, stderr
    client = client_param
    stdin, stdout, stderr = client.exec_command(cmd)
    response = ""
    sleep(0.1)
    if stdout.channel.recv_exit_status() == 0:
        response += str(f'STDOUT: {stdout.read().decode("utf8")}')
    else:
        response += str(f'STDERR: {stderr.read().decode("utf8")}')
    stdin.close()
    stdout.close()
    stderr.close()
    return response


def get_config_switch(ip_addr: ipaddress.IPv4Address) -> switch:
    client = SSHClient()
    client.load_host_keys("/home/gns3/.ssh/known_hosts")
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(str(ip_addr), username="root")
    result_string = execute_command("ovs-vsctl get-controller br0", client)
    try:
        ctrl_addr = ipaddress.ip_address((result_string.strip("STDOUT: tcp:")).split(":")[0])
    except ValueError:
        print(RuntimeWarning("Non connected to controller..."))
        ctrl_addr = ipaddress.ip_address("0.0.0.0")
    list_of_ports = []
    result_string = execute_command('ovs-ofctl -O OpenFlow13 dump-ports-desc br0', client)
    chunks = result_string.split("\n")
    for row in chunks:
        if ": addr:" in row:
            port_iface = row.split(": addr:")[0]
            port_mac_addr = row.split(": addr:")[1]
            port_number = (port_iface.split("(")[0]).strip(" ")
            port_name = (port_iface.split("(")[1]).strip(")")
            list_of_ports.append(
                port(port_number=port_number,
                     port_name=port_name,
                     hw_addr=str(macaddress.MAC(port_mac_addr)).replace('-', ':'))
            )
    datapath_switch = switch(address=ip_addr, controller=ctrl_addr, switch_ports=list_of_ports)
    client.close()
    del client
    return datapath_switch


# def set_flow_rule(ip_addr: ipaddress.IPv4Address, source, destination, output_iface: str):
#     client.connect(str(ip_addr), username="root")
#
#     output_port = [port.port_number
#                    for port in list_of_switches[datapath].switch_ports if port.port_name == output_iface]
#     cmd_string = f"ovs-ofctl -O OpenFlow13add-flow br0 dl_src={source}," \
#                  f"dl_dst={destination},actions=output:{str(output_port).strip('[]')}"
#     result_string = execute_command(cmd_string)
#     print(cmd_string)
#     client.close()

def start_simulation(list_of_args):
    ip_addr = list_of_args[0]
    mode = list_of_args[1]
    print(f"Starting simulation for {ip_addr} in mode: {mode}")
    cmd = shlex.split(
        f'nohup sshpass -p "root" ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root@{ip_addr} ": ; python3 /root/ryu/app_final.py {mode}"')
    output = subprocess.Popen(cmd)
    output.wait(160)


def reset_to_intial_config(ip_addr: ipaddress.IPv4Address):
    client = SSHClient()
    client.load_host_keys("/home/gns3/.ssh/known_hosts")
    client.load_system_host_keys()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(str(ip_addr), username="root")
    print(f"\tResetting {str(ip_addr)}")
    result_string = execute_command("ovs-ofctl -O OpenFlow13 del-flows br0", client)
    result_string = execute_command("ovs-vsctl emer-reset", client)
    result_string = execute_command("ovs-vsctl --if-exists del-port  br0 eth0", client)
    result_string = execute_command("ifconfig br0 up", client)
    result_string = execute_command("ovs-vsctl set bridge br0 protocols=OpenFlow13", client)
    result_string = execute_command('ovs-vsctl set Bridge br0 stp_enable=true', client)
    result_string = execute_command('ovs-vsctl list-ports br0 ', client)
    for i in range(1, 16):
        result_string = execute_command(f"ovs-vsctl add-port  br0 eth{i}", client)
        print(result_string)
    client.close()
    del client


# def route_builder(route_dict_iterator):
#     result_string = "ovs-ofctl -O OpenFlow13"
#     while True:
#         try:
#             key, lista = next(route_dict_iterator)
#             if "actions" == key:
#                 result_string += "," + "=".join(
#                     [key, ''.join(",%s" % ':'.join(map(str, x)) for x in lista).lstrip(",")])
#             elif "ip_params" == key:
#                 result_string += "," + ''.join(",%s" % '='.join(map(str, x)) for x in lista).lstrip(",")
#             elif "eth_params" == key:
#                 result_string += " " + ''.join(",%s" % '='.join(map(str, x)) for x in lista).lstrip(",")
#             elif "addr_params" == key:
#                 result_string += "," + ''.join(",%s" % '='.join(map(str, x)) for x in lista).lstrip(",")
#             elif "bridge_name" == key:
#                 result_string += " " + str(lista)
#             elif "route_type" == key:
#                 result_string += " " + str(lista)
#             elif "datapath" == key:
#                 datapath = lista
#             elif "_comment" == key:
#                 pass
#             elif "group_id" == key:
#                 result_string += " " + str(lista)
#             else:
#                 raise NotImplementedError()
#         except StopIteration:
#             break
#     # print(result_string)
#     return datapath, result_string


# def set_flow_rule_from_json(path_file):
#     # Forse questa è da rifare ed estrarre il pezzo che si occupa dell'estrazione della rule
#     with open(path_file, 'r') as json_file:
#         result = OrderedDict(json.load(json_file))
#     for route in result["routes"]:
#         route_dic_iterable = RouteDict(OrderedDict(route))
#         route_dict_iterator = iter(route_dic_iterable)
#         datapath, cli_flow_rule = route_builder(route_dict_iterator)
#         try:
#             datapath = list_of_switches[datapath]
#             if "output" in cli_flow_rule:
#                 output_iface = cli_flow_rule.split("output:")[1]
#                 output_port = [port.port_number for port in datapath.switch_ports if port.port_name == output_iface]
#                 cli_flow_rule = cli_flow_rule.replace(output_iface, str(output_port).strip("[]'"))
#                 cli_flow_rule = re.sub(r'\WNone', '', cli_flow_rule)
#
#             elif "group" in cli_flow_rule:
#                 output_iface = cli_flow_rule.split("group:")[1]
#         except:
#             continue
#         client.connect(str(datapath.address), username="root")
#         execute_command(cli_flow_rule)
#         client.close()
#         print(cli_flow_rule)


if __name__ == '__main__':
    t = AsyncSniffer(filter="udp", lfilter=lambda x: x[UDP].dport == 6969, timeout=6, count=1, iface="ens4")
    t.start()

    result = arping("192.168.0.0/24")
    for item in result[0]:
        print(f"\tConfiguring {item[0][0][ARP].pdst}")
        list_of_switches.append(switch(item[0][0][ARP].pdst))
    t.join()
    results = t.results
    print(results)
    try:
        ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', str(bytes(results[0].payload)))
    except IndexError:
        print("No packet received...")
    try:
        address = ipaddress.IPv4Address(str(ip[0]))
    except ipaddress.AddressValueError:
        address = ipaddress.IPv4Address('192.168.0.' + str(ip[0]).split(".")[3])
    print(address)
    response = requests.get(f"http://{address}:8080/v1.0/topology/switches")
    switches = json.loads(response.text)
    for dpid in switches:
        dpid.update({"ofctl_dpid": int(dpid['dpid'].lstrip("0000"), base=16)})

    r = requests.get(f"http://{address}:8080/v1.0/topology/links")
    # print(r.text)
    links = []
    for elem in r.json():
        links.append(LinkNet(src=API_Port(elem["src"]), dst=API_Port(elem["dst"])))
    unique_dpids = {link.src.dpid for link in links}
    G = nx.Graph()
    for node in unique_dpids:
        G.add_node(node)
    # links = set(links)
    links_dictionary = json.loads(NetworkToJson(links))
    for link in links_dictionary:
        G.add_edge(link["src"]["dpid"], link["dst"]["dpid"])
    r = requests.get(f"http://{address}:8080/v1.0/topology/hosts")
    for port in r.json():
        if "192.168.1.2" in port['ipv4']:
            src_host = port
            G.add_edge(
                src_host["ipv4"][0],  # Attenzione i miei hosts hanno un solo ip per interfaccia!
                src_host["port"]["dpid"],
                delay="0",
                jitter="0",
                loss_rate=int("0")
            )
        elif "192.168.1.3" in port['ipv4']:
            dst_host = port
            G.add_edge(
                dst_host["ipv4"][0],
                dst_host["port"]["dpid"],
                delay="0",  # Questi li ho messi semplicemente per uniformare i vari link
                jitter="0",
                loss_rate=int("0")
            )
        else:
            continue
    pos = nx.circular_layout(G)
    nx.draw(G, with_labels=True)
    plt.show()
    plt.close()
