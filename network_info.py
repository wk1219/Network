import socket
import sys
from requests import get

host = socket.gethostname()
mac = socket.gethostbyaddr(host)
other_ip = socket.gethostbyname(host)
all = socket.getaddrinfo(host, 80)
info = socket.gethostbyname_ex(host)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8",80))
host_ip = s.getsockname()[0]
ext_ip = get('https://api.ipify.org').text

# print(sys.argv[0])
#t = sys.argv[1]
#print("http://" + t)

print("Host : %s" % host)
print("MAC address :" + str(mac))
for i in range(0, len(all)):
    print(all[i])
print("INFO : " + str(info))
print("IP address : %s" % host_ip)
print("External IP : %s" % ext_ip)
print("Other IP address : %s" % other_ip)
url = "http://%s/Upload" % s.getsockname()[0]
print(url)