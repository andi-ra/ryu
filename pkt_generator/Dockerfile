FROM ubuntu:bionic

RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get -y install --fix-missing telnet git \
    curl nano vim-tiny iputils-ping build-essential libssl-dev libffi-dev python3-pip python3-dev  \
    python3-setuptools net-tools python3 iptables software-properties-common libpcap-dev bash iperf3  \
    libc6-dev iptables tcpreplay
RUN rm -rf /var/lib/apt/lists/* \
    && pip3 install --no-cache-dir wheel \
    && pip3 install --no-cache-dir scapy iperf3\
    && mkdir /root/.ssh/
RUN git clone https://github.com/kytos/python-openflow.git
RUN cd python-openflow && python3 setup.py install
RUN python3 -m pip install requests dataclasses
ADD TCP_OFPTxx.py /TCP_OFPTxx.py
ADD openflow.pcapng /openflow.pcapng
CMD [ "/bin/bash" ]
