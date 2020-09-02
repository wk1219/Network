from kivy.app import App
from kivy.lang import Builder
from kivy.uix.screenmanager import Screen, ScreenManager
import socket
import urllib
from getmac import get_mac_address as gma
import shutil
import math
import platform
import psutil
import os
import geocoder
import sys
from requests import get

class InfoWidget(Screen):
    label_text = ''
    host = ''
    ext_ip = ''
    ip = ''
    info = ''
    mac = ''

    def host_info(self):
        self.host = socket.gethostname()
        return self.host

    def ip_info(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        self.ip = s.getsockname()[0]
        return self.ip

    def ext_ip_info(self):
        # self.ext_ip = get('https://api.ipify.org').text
        self.ext_ip = urllib.request.urlopen('https://ident.me').read().decode('utf8')
        return self.ext_ip

    def mac_info(self):
        self.mac = gma()
        return self.mac

    def get_wps(self):
        g = geocoder.ip('me')
        loc = g.state + " " + g.city
        return loc

    def get_netmask(self):
        addrs = psutil.net_if_addrs()
        return addrs['Wi-Fi'][1][2]

class MyPC_Disk(Screen):
    drive = 'C:'
    GB = 1024*1024*1024
    total_size = ''
    used_size = ''
    free_size = ''
    volume_dict = dict()
    used_per = ''

    def volume(self):
        self.volume_dict = dict([x for x in zip(['total', 'used', 'free'], shutil.disk_usage(self.drive))])
        return self.volume_dict

    def total(self):
        v = self.volume_dict
        self.total_size = math.trunc(v['total']/self.GB)
        return self.total_size

    def used(self):
        v = self.volume()
        self.used_size = math.trunc(v['used']/self.GB)
        return self.used_size

    def free(self):
        v = self.volume()
        self.free_size = math.trunc(v['free']/self.GB)
        return self.free_size

    def partition_used(self):
        u = self.used()
        t = self.total()
        self.used_per = math.trunc((u/t)*100)
        return self.used_per

class MyPC_Info(Screen):
    def os_name(self):
        return platform.system()

    def os_version(self):
        return platform.version()

    def process_info(self):
        return platform.processor()

    def process_archi(self):
        return platform.machine()

    def ram_size(self):
        return round(psutil.virtual_memory().total / (1024.0 ** 3))

    def login_id(self):
        return os.getlogin()

class WindowManager(ScreenManager):
    pass


class InfoApp(App):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.info = InfoWidget()
        self.mypc_disk = MyPC_Disk()
        self.mypc_info = MyPC_Info()

    def build(self):
        sm = ScreenManager()
        sm.add_widget(self.info)
        sm.add_widget(self.mypc_disk)
        sm.add_widget(self.mypc_info)
        return sm


ui = Builder.load_file("info.kv")

if __name__ == "__main__":
    InfoApp().run()
