"""Questo file lo uso per la configurazione senza controller dello switch"""
import concurrent
import ipaddress
import json
import random
import re
import select
import shlex
import subprocess
import sys
import threading
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from time import sleep
from typing import List

import macaddress as macaddress
from dataclasses import dataclass

from paramiko.client import SSHClient, AutoAddPolicy
from scapy.layers.inet import UDP
from scapy.layers.l2 import arping, ARP
from scapy.sendrecv import AsyncSniffer


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
    # print("Starting from GNS3 ubuntu machine")
    # cmd = shlex.split("bash /tmp/pycharm_project_764/test_ryu_tesi/configure.sh ")
    # output = subprocess.Popen(cmd)
    # output.wait(360)
    t = AsyncSniffer(filter="udp", lfilter=lambda x: x[UDP].dport == 6969, timeout=6, count=1, iface="ens1")
    t.start()

    result = arping("192.168.0.0/24")
    for item in result[0]:
        print(f"\tConfiguring {item[0][0][ARP].pdst}")
        list_of_switches.append(switch(item[0][0][ARP].pdst))
    t.join()
    # print("Resetting to initial settings")
    # with concurrent.futures.ProcessPoolExecutor() as executor:
    #     future = {executor.submit(reset_to_intial_config, datapath.address): datapath for datapath in list_of_switches}
    #     for fut in concurrent.futures.as_completed(future):
    #         result = future[fut]
    #         print(result)

    # print("Creating list of datapaths")
    # with concurrent.futures.ProcessPoolExecutor() as executor:
    #     future = {executor.submit(get_config_switch, datapath.address): datapath for datapath in list_of_switches}
    #     for fut in concurrent.futures.as_completed(future):
    #         dp = future[fut]
    #         list_of_datapaths.append(dp)
    #         print(f"switch is \n{dp}")
    #
    # print("Starting with simulations")
    # with concurrent.futures.ProcessPoolExecutor() as executor:
    #     ctrl_datapath = random.choice(list_of_datapaths)
    #     list_of_datapaths.remove(ctrl_datapath)
    #     future = {executor.submit(start_simulation, [datapath.address, "client"]): datapath for datapath in
    #               list_of_switches}
    #     start_simulation([ctrl_datapath.address, "ctrl"])


    print("Closing connection and cleaning up...")
