#!/usr/bin/python
"""
Build Your Own Botnet
github.com/colental/byob
Copyright (c) 2018 Daniel Vega-Myhre
"""
from __future__ import print_function
import Queue
import datetime
import threading
import mysql.connector


class Database(mysql.connector.MySQLConnection):
    """
    Database handler for BYOB (Build Your Own Botnet)
    """
    def __init__(self, tasks, **kwargs):
        super(Database, self).__init__(**kwargs)
        self.config(**kwargs)
        self.types  = types
        self.query  = self.cursor(named_tuple=True)
        self.queue  = Queue.Queue()


    def _reconnect(self):
        try:
            self.reconnect()
            self.query = self.cursor(named_tuple=True)
            return "{}@{} reconnected".format(self.database.user, self.database.server_host)
        except Exception as e:
            self._error("{} error: {}".format(self.database_reconnect.func_name, str(e)))


    def _handle_query(self, cursor, query):
        try:
            result  = []
            cmd, _, action = str(query).partition(' ')
            self.query.execute(query)
            output = self.query.fetchall()
            result = []
            if output and isinstance(output, list):
                for row in output:
                    row = row._asdict()
                    for attr in [key for key,value in row.items() if key in ('last_update','issued','completed','timestamp')]:
                        if isinstance(value, datetime.datetime):
                            row[key] = value.ctime()
                    result.append(row)
            return result
        except Exception as e:
            return "{} error: {}".format(self._handle_query.func_name, str(e))


    def new_task(self, task):
        try:
            if isinstance(task, dict):
                if len(filter(task.get, ['client','session','task'])) == 3:
                    cmd, _, __  = bytes(task.get('task')).partition(' ')
                    if cmd in self.tasks:
                        values = [task['client'], task['session'], task['task'], '@task']
                        self.execute_stored_procedure('sp_addTask', args=values, display=False)
                        task = self.execute_query('SELECT @task', display=False)
                        return task
                else:
                    self._error("{} error: missing one or more arguments ('client','session','task')".format(self.execute_stored_procedure.func_name))
            else:
                self._error("{} error: invalid input type (expected {}, received {})".format(self.new_task.func_name, dict, type(task)))
        except Exception as e:
            self._error("{} error: {}".format(self.new_task.func_name, str(e)))


    def save_task_results(self, task_id, result):
        try:
            self.execute_query("UPDATE tbl_tasks SET result='{}' WHERE id='{}'".format(result, task_id), display=False)
        except Exception as e:
            self._error("{} error: {}".format(self.add_result.func_name, str(e)))


    def show_session_results(self, session_id=None):
        try:
            return self.execute_query("SELECT * FROM tbl_tasks WHERE session='{}'".format(session_id).replace("Array\n(", "").replace("\n)", ""), display=False)
        except Exception as e:
            self._error("{} error: {}".format(self.show_task_results.func_name, str(e)))


    def execute_query(self, query, display=False):
        try:
            if not self.is_connected():
                self._reconnect()
            result = self._handle_query(query)
            if display:
                for row in result:
                    self.display(json.dumps(row))
            return result
        except (mysql.connector.InterfaceError, mysql.connector.ProgrammingError):
            print("Error: query failed - reconnecting...")
            self.database.reconnect()
        except Exception as e:
            self._error("{} error: {}".format(self.execute_query.func_name, str(e)))


    def execute_stored_procedure(self, procedure, args=[], display=False):
        try:
            if not self.is_connected():
                self._reconnect()
            cursor = self.cursor(dictionary=True)
            cursor.callproc(procedure, args)
            result = [row for result in cursor.stored_results() for row in result.fetchall()]
            return result
        except mysql.connector.InterfaceError:
            pass

