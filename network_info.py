import socket

host = socket.gethostname()
mac = socket.gethostbyaddr(host)
ip = socket.gethostbyname(host)
all = socket.getaddrinfo(host, 80)
host_ip = socket.gethostbyname_ex(host)

print(host)
print(mac)
print(ip)
print(all)
print(host_ip)