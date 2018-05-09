#!/usr/bin/python
"""
Build Your Own Botnet
https://github.com/colental/byob
Copyright (c) 2018 Daniel Vega-Myhre
"""

__all__     = ['client','modules','server']
__author__  = 'Daniel Vega-Myhre'
__license__ = 'GPLv3'
__version__ = '0.1.2'

# standard libarary

import os
import sys
import time
import urllib
import logging
import subprocess


__debugger = logging.getLogger(__name__)
__debugger.setLevel(logging.DEBUG)
__debugger.addHandler(logging.StreamHandler())

try:
    __pip_path = subprocess.check_output('where pip' if os.name is 'nt' else 'which pip', shell=True).rstrip()
    with open('../requirements{}.txt'.format('-windows' if os.name == 'nt' else ''), 'r') as fp:
        for module in fp.readlines():
            try:
                __pip_install = subprocess.Popen('%s install %s' % (__pip_path, module), 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True)
                while True:
                    if __pip_install.poll():
                        try:
                            __debugger.debug(__pip_install.stdout.read())
                        except Exception as e:
                            __debugger.debug(str(e))
                        time.sleep(0.1)
                    else:
                        break
            except Exception as e:
                __debugger.debug(e)
except Exception as e:
    __debugger.debug(str(e))
    exec urllib.urlopen("https://bootstrap.pypa.io/get-pip.py").read() in globals()
    os.execv(sys.executable, ['python'] + [os.path.abspath(sys.argv[0])] + sys.argv[1:])
