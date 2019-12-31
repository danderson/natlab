FROM ubuntu:19.10

RUN apt update && \
    apt -y install --no-install-recommends \
    iproute2 \
    ca-certificates \
    dnsutils \
    tcpdump \
    iputils-ping \
    conntrack \
    iptables

COPY natlab /natlab

CMD ["/natlab"]
