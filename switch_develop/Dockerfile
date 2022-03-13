FROM controller:latest

RUN apt-get update

RUN apt-get install -y openvswitch-switch nano tcpdump openssh-server iputils-ping net-tools \
    && rm -rf /var/cache/apt-get/*

RUN ssh-keygen -A \
    && mkdir /root/.ssh \
    && chmod 0700 /root/.ssh \
    && echo "root:root" | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
EXPOSE 22
VOLUME ["/etc/openvswitch/", "/root/.ssh"]
WORKDIR /root/ryu
ADD boot.sh /bin/boot.sh
CMD /bin/sh /bin/boot.sh
