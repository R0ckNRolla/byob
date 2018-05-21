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

__all__     = ['client','modules','server']
__author__  = 'Daniel Vega-Myhre'
__license__ = 'GPLv3'
__version__ = '0.1.3'

# standard libarary

import os
import sys
import time
import urllib
import logging
import subprocess


def main():
    for cd, dirs, files in os.walk('..'):
        if 'requirements.txt' in files:
            requires = os.path.abspath(os.path.join(cd, 'requirements.txt'))
            break
    debugger = logging.getLogger(__name__)
    debugger.setLevel(logging.DEBUG if ('--debug' in sys.argv or 'debug' in sys.argv else logging.ERROiR))
    debugger.addHandler(logging.StreamHandler())

    # check if pip installed
    try:
        pip_path = subprocess.check_output('where pip' if os.name is 'nt' else 'which pip', shell=True).rstrip()
    except Exception as e:
        debugger.debug("Error in pip package installer: {}".format(str(e)))

    # install pip if missing
    if not 'pip_path' in globals():
        try:
            exec urllib.urlopen("https://bootstrap.pypa.io/get-pip.py").read() in globals()
        except Exception as e:
            debugger.debug("Error installing pip: {}".format(str(e)))

        # restart
        os.execv(sys.executable, ['python'] + [os.path.abspath(sys.argv[0])] + sys.argv[1:])

    else:
        # install required packages
        try:
            pip_install = subprocess.Popen('{} install -r {}'.format(pip_path, requires), 0, None, subprocess.PIPE, subprocess.PIPE, subprocess.PIPE, shell=True)
        except Exception as e:
            debugger.debug("Error pip installing 'requirements.txt': {}".format(str(e)))
            with open(requires, 'r') as fp:
                for package in fp.readlines():
                    try:
                        pip_install = subprocess.Popen('{} install {}'.format(pip_path, package), 0, None, subprocess.PIPE, subprocess.PIPE, subprocess.PIPE, shell=True)
                    except Exception as e:
                        debugger.debug("Error installing package: {}".format(package))
        try:
            import client
        except Exception as e:
            debugger.debug("Error importing byob.client: {}".format(str(e)))
        try:
            import server
        except Exception as e:
            debugger.debug("Error importing byob.server: {}".format(str(e)))
        try:
            import modules
        except Exception as e:
            debugger.debug("Error importing byob.modules: {}".format(str(e)))

if __name__ == '__main__':
    main()
