#!/bin/bash

result=$(python3 -c "from scapy.layers.l2 import *;arping('192.168.0.0/24')")
ip=$(echo $result | grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")
echo $ip

for address in $ip; do
  sshpass -p "root" ssh-copy-id -i /home/gns3/.ssh/id_rsa.pub root@$address
  ssh root@$address hostname
done