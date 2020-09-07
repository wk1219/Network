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

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    # host = gethostbyname(gethostname())
    host = s.getsockname()[0]
    print('START SNIFF [%s]' % host)
    sniffing(host)

if __name__=='__main__':
    main()