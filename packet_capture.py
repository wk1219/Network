from socket import *
import socket
import os

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
    packet = sniffer.recvfrom(65565)
    print(packet)

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
    packet_info()


if __name__=='__main__':
    main()