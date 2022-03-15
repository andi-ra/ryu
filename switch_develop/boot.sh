#!/bin/sh
#
# Copyright (C) 2015 GNS3 Technologies Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
NO_BRIDGE=false
NO_IFACE=true
NO_MANAGEMENT_IFACE=$(uname -r | grep -c '5.13.0-35-generic')

iface_list=$(netstat -i | grep -o "eth[0-9]*")
iface_num=$(echo $iface_list | wc -w)
echo "Number of interfaces seen: $iface_num"

#exit $?

if [ ! -f "/etc/openvswitch/conf.db" ]; then

  echo "No db conf file founf creating one..."
  echo "Purging old configuration"
  ovsdb-tool create /etc/openvswitch/conf.db /usr/share/openvswitch/vswitch.ovsschema
  ovs-ofctl show br0 &>/tmp/tmp_file
  result=$(</tmp/tmp_file)
  occurrences=$(echo "$result" | grep -c "br0 is not a bridge")
  if [ "$occurrences" -ne 0 ]; then
    NO_BRIDGE=true
  else
    echo "Bridge br0 is a valid datapath"
  fi
  if [ $NO_BRIDGE = false ]; then
    # Se non è partito tutto il sistema questo non funziona...
    ovs-vsctl del-br br0 &>/tmp/tmp_file
    result=$(</tmp/tmp_file)
    occurrences=$(echo "$result" | grep -c "br0")
    if [ "$occurrences" -ne 0 ]; then
      echo "Something went wrong reinitializing the configuration"
      #          exit 1
    fi
  else
    echo "No bridge found proceeding with initialization"
  fi
  sudo /usr/share/openvswitch/scripts/ovs-ctl stop
  sudo /usr/share/openvswitch/scripts/ovs-ctl start
  #  echo "starting remote OVSDB server"
  #  sudo ovsdb-server --detach --remote=punix:/var/run/openvswitch/db.sock
  #  echo "Starting daemon"
  #  sudo ovs-vswitchd --detach
  #  echo "Finalizing configuration"
  #  sudo ovs-vsctl --no-wait init
  echo "Committing configuration"
  sudo ovs-vsctl add-br br0
  sudo ovs-vsctl set bridge br0 datapath_type=netdev
  echo "Starting first initialization"
  x=1
  until [ $x -eq $iface_num ]; do
    ovs-vsctl add-port br0 eth$x
    x=$((x + 1))
  done
  echo "Finished first initialization"
else
  timeout 2 ovsdb-server --detach --remote=punix:/var/run/openvswitch/db.sock
  case $? in
  124)
    echo 'Command timed out maybe is already running'
    echo 'Restarting ovsdb-server'
    /usr/share/openvswitch/scripts/ovs-ctl restart
    ;;
  2)
    echo 'Command ovsdb-server not found... Check installation'
    exit $?
    ;;
  1)
    echo 'Uncaught error'
    exit $?
    ;;
  0)
    echo 'Server OVSDB protocol [OK]'
    ;;
  esac
  timeout 2 ovs-vswitchd --detach
  case $? in
  124)
    echo 'Command: ovs-vswitchd timed out deaemon already running'
    exit $?
    ;;
  2)
    echo 'Command ovs-vswitchd not found... Check installation'
    exit $?
    ;;
  1)
    echo 'Uncaught error'
    exit $?
    ;;
  0)
    echo 'Daemon [OK]'
    ;;
  esac
fi

ip link set dev br0 up

#ovs-ofctl -O OpenFlow13 del-flows br0
mkdir -p -m0755 /var/run/sshd && /usr/sbin/sshd
sudo /usr/share/openvswitch/scripts/ovs-ctl stop
sudo /usr/share/openvswitch/scripts/ovs-ctl start

if [ $? -eq 0 ]; then
  echo "Finalized Config"
else
  echo "Error setting STP be careful with ARP storms..."
fi
echo "Check of config success"
result=$(ovs-ofctl show br0 | grep -o 'dpid\:\w*')
code=$(($? & 0xf))
case $code in
0)
  echo "Successfully created bridge br0 with $result"
  ;;
1)
  echo "Did not create bridge br0, error: $result"
  echo "Trying to reinitializing the configuration"
  ovs-vsctl del-br br0
  echo "Recreating back again bridge"
  ovs-vsctl add-br br0
  echo "Adding interfaces"
  if [ $NO_MANAGEMENT_IFACE -eq 1 ]; then
    x=0
  else
    x=1
  fi
  until [ $x -eq $iface_num ]; do
    ovs-vsctl add-port br0 eth$x
    x=$((x + 1))
  done
  echo "Checking result"
  result=$(ovs-ofctl show br0 | grep -o 'dpid\:\w*')
  if [ $? -ne 0 ]; then
    exit 1
  else
    echo "Created bridge with $result"
  fi
  ;;
2)
  echo "Error in ovs-ofctl command, check manually"
  ;;

esac
echo "Dumping config"
ovs-ofctl dump-ports-desc br0
ovs-vsctl set bridge br0 stp_enable=true
ovs-vsctl del-controller br0
tail /var/log/openvswitch/ovs-vswitchd.log
/bin/bash
#python3 /root/ryu/check_ready.py
