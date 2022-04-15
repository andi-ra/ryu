#!/bin/bash

result=$(python3 -c "from scapy.layers.l2 import *;arping('192.168.0.0/24')")
ip=$(echo $result | grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")
echo $ip

#for address in $ip; do
#  sshpass -p 'root' ssh-copy-id -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i /home/gns3/.ssh/id_rsa.pub root@$address
#  sshpass -p 'root' ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root@$address hostname
#done
#
#
#for address in $ip; do
#  sshpass -p 'root' ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root@$address 'for i in $(seq 15); do ovs-vsctl add-port br0 eth$i; done'
#  sshpass -p 'root' ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root@$address 'ovs-vsctl del-port br0 eth0;'
#done

ctrl=$(shuf -n1 -e $ip)
echo $ctrl

#for address in $ip; do
#  if [ $address == $ctrl ]
#  then
#    nohup sshpass -p "root" ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root@$ctrl "bash -c 'python3 /root/ryu/app_final.py ctrl' " &
#  else
#    nohup sshpass -p "root" ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root@$address "bash -c 'python3 /root/ryu/app_final.py client' " &
#  fi
#done

for address in $ip; do
#  sshpass -p 'root' ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root@$address 'ovs-vsctl set-controller br0 tcp:192.168.0.254:6653'
#  sshpass -p 'root' ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root@$address 'ovs-ofctl del-flows br0'
  sshpass -p 'root' ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root@$address 'ip neigh flush all'
#  sshpass -p 'root' ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root@$address 'ovs-ofctl add-flow br0 action=normal'
#  sshpass -p 'root' ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root@$address 'ovs-vsctl del-controller br0'
#  sshpass -p 'root' ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root@$address 'ifconfig br0 up'

done