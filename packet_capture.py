from socket import *
# import socket
import os
import struct
import binascii


def pack_ethernet(data):
    eth_header = struct.unpack('!6s6sH', data[:14])
    return eth_header


def get_mac(eth_header):
    raw_mac = binascii.hexlify(eth_header)
    str_mac = raw_mac.decode('utf-8')
    mac = '%02s:%02s:%02s:%02s:%02s:%02s' % \
          (str_mac[:2], str_mac[2:4], str_mac[4:6], str_mac[6:8], str_mac[8:10], str_mac[10:12])
    return mac


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
    protocols = {1: 'ICMP', 2: 'IGCMP', 6: 'TCP', 9: 'IGRP', 17: 'UDP', 47: 'GRE', 50: 'ESP', 51: 'AH', 57: 'SKIP',
                 88: 'EIGRP',
                 89: 'OSPF', 115: 'L2TP'}
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


def get_seq(header):
    seq_num = header[3]
    ack_num = header[4]
    return (seq_num, ack_num)


def get_flags(header):
    flags = header[5]
    return flags


def udp_checksum(header):
    checksum = header[3]
    return checksum


def udp_len(header):
    length = header[2]
    return length


def tcp_checksum(header):
    checksum = header[7]
    return checksum


def recv_data(sock):
    data = ''
    try:
        data = sock.recvfrom(65535)
    except timeout:
        data = ''
    return data[0]


def sniffing(host):
    if os.name == 'nt':
        sock_protocol = IPPROTO_IP
    else:
        sock_protocol = IPPROTO_ICMP

    sniffer = socket(AF_INET, SOCK_RAW, sock_protocol)
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

            print("======== SNIFFER [%d] ======== " % cnt)
            print("======== [IP Header] ========")
            print("┌ Version : %s" % str(version))
            print("│ IHL : %s" % str(ip_header_length))
            print("│ Type of Service : %s" % str(tos))
            print("│ Total Length : %s Bytes" % str(data_size))
            print("│ Identification : %s" % str(id))
            print("│ TTL : %s" % str(ttl))
            print("│ Protocol : %s" % str(protocol))
            print("│ Source IP : %s" % str(src_ip))
            print("└ Destination IP : %s" % str(dst_ip))

            if protocol == 'UDP':
                udp_header = pack_udpheader(payload)
                src_port, dst_port = get_port(udp_header)
                udp_length = udp_len(udp_header)
                checksum = udp_checksum(udp_header)

                if src_port == 7 or dst_port == 7:
                    protocol = 'Echo'
                elif src_port == 53 or dst_port == 53:
                    protocol = 'DNS'
                elif src_port == 67 or dst_port == 67:
                    protocol = 'DHCP'
                elif src_port == 69 or dst_port == 69:
                    protocol = 'TFTP'
                elif src_port == 111 or dst_port == 111:
                    protocol = 'RPC'

                print("======== [UDP Header] ========")
                print("┌ Source Port : %s" % str(src_port))
                print("│ Destination Port : %s" % str(dst_port))
                print("│ Checksum : %s" % str(hex(checksum)))
                print("│ Length : %s" % str(udp_length))
                print("└ Payload : %s" % str(payload[8:]))

            elif protocol == 'TCP':
                tcp_header = pack_tcpheader(payload)
                src_port, dst_port = get_port(tcp_header)
                seq_num, ack_num = get_seq(tcp_header)
                checksum = tcp_checksum(tcp_header)
                tcp_flags = get_flags(tcp_header)

                if src_port == 20 or src_port == 21 or dst_port == 20 or dst_port == 21:
                    protocol = 'FTP'
                elif src_port == 22 or dst_port == 22:
                    protocol = 'SSH'
                elif src_port == 23 or dst_port == 23:
                    protocol = 'Telnet'
                elif src_port == 25 or dst_port == 25:
                    protocol = 'SMTP'
                elif src_port == 80 or dst_port == 80:
                    protocol = 'HTTP'
                elif src_port == 110 or dst_port == 110:
                    protocol = 'POP3'
                elif src_port == 143 or dst_port == 143:
                    protocol = 'IMAP'
                elif src_port == 443 or dst_port == 443:
                    protocol = 'HTTPS'
                elif src_port == 443:
                    protocol = 'TLSv1.2'
                print("======== [TCP Header] ========")
                print("┌ Source Port : %s" % str(src_port))
                print("│ Destination Port : %s" % str(dst_port))
                print("│ Checksum : %s" % str(hex(checksum)))
                print("│ Sequence Number : %s" % str(seq_num))
                print("│ Acknowledgment Number : %s" % str(ack_num))
                print("│ TCP Flags : %s" % str(tcp_flags))
                print("└ Payload : %s" % str(payload))


                if protocol == 'HTTP':
                    print("====== [%s Header] ======" % protocol)
                    print("%s" % payload[20:])

            cnt += 1
    except KeyboardInterrupt:
        if os.name == 'nt':
            sniffer.ioctl(SIO_RCVALL, RCVALL_OFF)


def eth_packet_info(host):
    print("=" * 20 + "INFO" + "=" * 20)

    raw = socket(AF_INET, SOCK_RAW, IPPROTO_IP)
    raw.bind((host, 0))
    raw.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
    raw.ioctl(SIO_RCVALL, RCVALL_ON)
    data = raw.recv(65565)

    eth = pack_ethernet(data)
    dst_mac = get_mac(eth[:6])
    print(dst_mac)


def main():
    s = socket(AF_INET, SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    host = s.getsockname()[0]
    print('START SNIFF [%s]' % host)
    sniffing(host)
    # eth_packet_info(host)


if __name__ == '__main__':
    main()
