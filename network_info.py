import socket
import sys

host = socket.gethostname()
mac = socket.gethostbyaddr(host)
ip = socket.gethostbyname(host)
all = socket.getaddrinfo(host, 80)
host_ip = socket.gethostbyname_ex(host)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8",80))


# print(sys.argv[0])
#t = sys.argv[1]
#print("http://" + t)

print(type(mac))
print("Host : %s" % host)
print("MAC address :" + str(mac))
print("IP address : %s" % ip)
for i in range(0, len(all)):
    print(all[i])
print("INFO : " + str(host_ip))
print("IP address : %s" % s.getsockname()[0])
url = "http://%s/Upload" % s.getsockname()[0]
print(url)