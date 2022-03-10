FROM andi95/controller

RUN apt-get update

RUN apt-get install -y openvswitch-switch nano tcpdump openssh-server net-tools && rm -rf /var/cache/apt-get/*

RUN ssh-keygen -A \
    && mkdir /root/.ssh \
    && chmod 0700 /root/.ssh \
    && echo "root:root" | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
EXPOSE 22
VOLUME ["/etc/openvswitch/", "~/.ssh"]
WORKDIR /root/ryu
ADD TCP_OFPTxx.py /TCP_OFPTxx.py
ADD openflow.pcapng /openflow.pcapng
ADD boot.sh /bin/boot.sh
CMD /bin/sh /bin/boot.sh
