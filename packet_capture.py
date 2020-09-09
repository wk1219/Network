from socket import *
import socket
import os
import struct

def pack_ipheader(data):
    ipheader = struct.unpack('!BBHHHBBH4s4s', data[:20])
    return ipheader

def get_protocol(ipheader):
    protocols = {1:'ICMP', 6:'TCP', 17:'UDP'}
    protocol = ipheader[6]

    if protocol in protocols:
        return protocols[protocol]
    else:
        return 'Other Protocol'

def get_ip(ipheader):
    src_ip = inet_ntoa(ipheader[8])
    dst_ip = inet_ntoa(ipheader[9])
    return (src_ip, dst_ip)

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
    sniffer.bind((host, 80))
    sniffer.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)

    if os.name == 'nt':
        sniffer.ioctl(SIO_RCVALL, RCVALL_ON)

    cnt = 1
    try:
        while True:
            data = recv_data(sniffer)
            ip_header = pack_ipheader(data[:20])
            data_size = ip_header[2]
            protocol = get_protocol(ip_header)
            src_ip = get_ip(ip_header)[0]
            dst_ip = get_ip(ip_header)[1]
            print("======== SNIFFER [%d] ======== " % cnt)
            print("Data Size : %s Bytes" % str(data_size))
            print("Protocol : %s" % str(protocol))
            print("Source IP : %s" % str(src_ip))
            print("Destination IP : %s" % str(dst_ip))
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
    # while True:
    #     if cnt == 100:
    #         break
    #     sniffing(host, cnt)
    #     cnt += 1

    # packet_info()

if __name__=='__main__':
    main()