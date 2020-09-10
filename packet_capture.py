from socket import *
import socket
import os
import struct

def pack_ipheader(data):
    ipheader = struct.unpack('!BBHHHBBH4s4s', data[:20])
    return ipheader

def get_payload(data):
    payload = data[20:]
    return payload

def get_version(ipheader):
    version = (ipheader[0] >> 4) & 0x0f
    if version == 4:
        return "IPv4"
    else:
        return "IPv6"
def get_ihl(ipheader):
    ip_header_length = ipheader[0] & 0x0f
    return ip_header_length * 4

def get_tos(ipheader):
    tos = ipheader[1]
    return tos

def get_id(ipheader):
    id = ipheader[3]
    return id

def get_ttl(ipheader):
    ttl = ipheader[5]
    return ttl

def get_protocol(ipheader):
    protocols = {1:'ICMP', 2:'IGCMP', 6:'TCP', 9:'IGRP', 17:'UDP', 47:'GRE', 50:'ESP', 51:'AH', 57:'SKIP', 88:'EIGRP',
                 89:'OSPF', 115:'L2TP'}
    protocol = ipheader[6]

    if protocol in protocols:
        return protocols[protocol]
    else:
        return 'Other Protocol'

def get_size(ipheader):
    total_size = ipheader[2]
    return total_size

def get_ip(ipheader):
    src_ip = inet_ntoa(ipheader[8])
    dst_ip = inet_ntoa(ipheader[9])
    return (src_ip, dst_ip)

def pack_udpheader(data):
    udpheader = struct.unpack('!HHHH', data[:8])
    return udpheader

def pack_tcpheader(data):
    tcpheader = struct.unpack('!HHLLBBHH2s', data[:20])
    return tcpheader

def get_port(header):
    src_port = header[0]
    dst_port = header[1]
    return (src_port, dst_port)

def recv_data(sock):
    data = ''
    try:
        data = sock.recvfrom(65565)
    except timeout:
        data = ''
    return data[0]

def sniffing(host):
    if os.name == 'nt':
        sock_protocol = IPPROTO_IP
    else:
        sock_protocol = IPPROTO_ICMP

    sniffer = socket.socket(AF_INET, SOCK_RAW, sock_protocol)
    sniffer.bind((host, 0))
    sniffer.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)

    if os.name == 'nt':
        sniffer.ioctl(SIO_RCVALL, RCVALL_ON)

    cnt = 1
    try:
        while True:
            data = recv_data(sniffer)
            ip_header = pack_ipheader(data[:20])
            version = get_version(ip_header)
            ip_header_length = get_ihl(ip_header)
            tos = get_tos(ip_header)
            data_size = get_size(ip_header)
            id = get_id(ip_header)
            protocol = get_protocol(ip_header)
            ttl = get_ttl(ip_header)
            src_ip = get_ip(ip_header)[0]
            dst_ip = get_ip(ip_header)[1]
            payload = get_payload(data)

            if protocol == 'UDP':
                udp_header = pack_udpheader(payload)
                src_port, dst_port = get_port(udp_header)
            elif protocol == 'TCP':
                tcp_header = pack_tcpheader(payload)
                src_port, dst_port = get_port(tcp_header)

            print("======== SNIFFER [%d] ======== " % cnt)
            print("┌ Version : %s" % str(version))
            print("│ IHL : %s" % str(ip_header_length))
            print("│ Type of Service : %s" % str(tos))
            print("│ Total Length : %s Bytes" % str(data_size))
            print("│ Identification : %s" % str(id))
            print("│ TTL : %s" % str(ttl))
            print("│ Protocol : %s" % str(protocol))
            print("│ Source IP : %s" % str(src_ip))
            print("│ Destination IP : %s" % str(dst_ip))
            print("│ Source Port : %s" % str(src_port))
            print("│ Destination Port : %s" % str(dst_port))
            print("└ Payload : %s" % str(payload))
            cnt += 1
    except KeyboardInterrupt:
        if os.name == 'nt':
            sniffer.ioctl(SIO_RCVALL, RCVALL_OFF)

def packet_info():
    print("="*20 + "INFO" + "="*20)
    print("OS NAME : %s" % os.name)
    print("PROTOCOL : %s" % IPPROTO_IP)
    sniffer = socket.socket(AF_INET, SOCK_RAW, IPPROTO_IP)
    print(sniffer)

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    host = s.getsockname()[0]
    print('START SNIFF [%s]' % host)
    sniffing(host)

if __name__=='__main__':
    main()