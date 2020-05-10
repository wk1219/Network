import socket

host = socket.gethostname()
mac = socket.gethostbyaddr(host)
ip = socket.gethostbyname(host)
all = socket.getaddrinfo(host, 80)
host_ip = socket.gethostbyname_ex(host)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8",80))

print(host)
print(mac)
print(ip)
print(all)
print(host_ip)
print(s.getsockname())