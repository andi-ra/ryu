FROM python:3.8-slim-buster


ENV HOME /root/ryu
WORKDIR /root/ryu

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    sudo \
    python3-setuptools \
    python3-pip \
    python3-eventlet \
    python3-lxml \
    python3-msgpack \
    iproute2 \
    procps \
    git \
    iputils-ping  \
    net-tools\
    lldpd \
 && rm -rf /var/lib/apt/lists/* \
 && curl -kL https://github.com/osrg/ryu/archive/master.tar.gz | tar -xvz \
 && mv ryu-master ryu \
 && cd ryu \
 && python3 -m pip install -r tools/pip-requires \
 && python3 setup.py install
RUN git clone https://github.com/kytos/python-openflow.git
RUN cd python-openflow && python3 setup.py install
RUN python3 -m pip install requests dataclasses
ADD pkt_generator/TCP_OFPTxx.py /TCP_OFPTxx.py
ADD pkt_generator/openflow.pcapng /openflow.pcapng
RUN python3 -m pip uninstall -y ryu
RUN python3 -m pip install nose eventlet==0.31.1 scapy networkx importlib-metadata
RUN apt-get update && apt-get -o Dpkg::Options::="--force-confmiss" install -y --reinstall netbase
ADD ./* /root/ryu/
