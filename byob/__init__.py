#!/usr/bin/python
#!/usr/bin/python
"""
Build Your Own Botnet
https://github.com/colental/byob
Copyright (c) 2018 Daniel Vega-Myhre
"""

from __future__ import print_function

# standard libarary

import os
import sys
import logging
import subprocess

logging.basicConfig(level=logging.DEBUG, handler=logging.StreamHandler())


def main():
    pip_exe  = subprocess.check_output('where pip' if os.name is 'nt' else 'which pip', shell=True).rstrip()
    logging.info(pip_exe)
    if pip_exe:
        try:
            require = '%s install -r %s' % (pip_exe, '../requirements{}.txt'.format('-windows' if os.name == 'nt' else ''))
            logging.info(require)
            process = subprocess.Popen(require, 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True)
            while True:
                if process.poll():
                    time.sleep(0.1)
                    try:
                        logging.info(process.stdout.read())
                    except: pass
                else:
                    try:
                        logging.info(process.stdout.read())
                    except: pass
                    break
        except Exception as e:
            with open(require, 'r') as fp:
                for module in fp.readlines():
                    try:
                        install = '%s install %s' % (pip_exe, module)
                        logging.info(install)
                        process = subprocess.Popen(install, 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True)
                        while True:
                            if process.poll():
                                time.sleep(0.1)
                            else:
                                logging.info(process.stdout.read())
                                break
                    except Exception as e:
                        logging.debug(e)
        for i in ('client', 'server'):
            try:
                exec "import %s" % i in globals()
            except Exception as e:
                logging.debug(e)
    else:
        exec urllib.urlopen("https://bootstrap.pypa.io/get-pip.py").read() in globals()
        os.execv(sys.executable, ['python'] + [os.path.abspath(sys.argv[0])] + sys.argv[1:])



__all__         = ['client','server']
__author__      = 'Daniel Vega-Myhre'
__license__ 	= 'GPLv3'
__version__ 	= '0.1.2'
if __name__     == '__main__':
    main()
