from kivy.app import App
from kivy.lang import Builder
from kivy.uix.screenmanager import Screen, ScreenManager
import socket
import sys
from requests import get

class InfoWidget(Screen):
    label_text = ''
    host = ''
    mac = ''
    ip = ''

    def host_info(self):
        self.host = socket.gethostname()
        return 'Host : ' + str(self.host)

    def ip_info(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        self.ip = s.getsockname()[0]
        return 'IP : ' + str(self.ip)


class WindowManager(ScreenManager):
    pass


class InfoApp(App):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.info = InfoWidget()

    def build(self):
        sm = ScreenManager()
        sm.add_widget(self.info)
        return sm


ui = Builder.load_file("info.kv")

if __name__ == "__main__":
    InfoApp().run()