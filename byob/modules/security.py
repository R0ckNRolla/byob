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
import json
import struct
import base64
import socket
import urllib
import logging
import tempfile
import cStringIO

# modules

import util

# globals

packages   = ['Crypto','Crypto.Util','Crypto.Cipher.AES','Crypto.Hash.HMAC','Crypto.Hash.MD5','Crypto.PublicKey.RSA','Crypto.Cipher.PKCS1_OAEP']
platforms  = ['win32','linux2','darwin']
util.is_compatible(platforms, __name__)
util.imports(packages)


def encrypt_aes(data, key):
    """
    AES-256-OCB encryption

    `Required`
    :param str data:    plaintext
    :param str key:     256-bit key

    """
    try:
        cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_OCB)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        output = b''.join((cipher.nonce, tag, ciphertext))
        return base64.b64encode(output)
    except Exception as e:
        print("{} error: {}".format(encrypt_aes.func_name, str(e)))



def decrypt_aes(data, key):
    """
    AES-256-OCB decryption
    
    `Required`
    :param str data:    ciphertext
    :param str key:     256-bit key
    """
    try:
        data = cStringIO.StringIO(base64.b64decode(data))
        nonce, tag, ciphertext = [ data.read(x) for x in (Crypto.Cipher.AES.block_size - 1, Crypto.Cipher.AES.block_size, -1) ]
        cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_OCB, nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except Exception as e1:
        try:
            return cipher.decrypt(ciphertext)
        except Exception as e2:
            _debugger.debug("{} error: {}".format(decrypt_aes.func_name, str(e2)))



def encrypt_xor(data, key, block_size=8, key_size=16, num_rounds=32, padding='$'):
    """
    XOR-128 encryption

    `Required`
    :param str data:        plaintext
    :param str key:         256-bit key

    `Optional`
    :param int block_size:  block size (default: 8)
    :param int key_size:    key size (default: 16)
    :param int num_rounds:  number of rounds (default: 32)
    :param str padding:     padding character (default: $)
    """
    data    = bytes(data) + (int(block_size) - len(bytes(data)) % int(block_size)) * bytes(padding)
    blocks  = [data[i * block_size:((i + 1) * block_size)] for i in range(len(data) // block_size)]
    vector  = os.urandom(8)
    result  = [vector]
    for block in blocks:
        block   = bytes().join(chr(ord(x) ^ ord(y)) for x, y in zip(vector, block))
        v0, v1  = struct.unpack("!2L", block)
        k       = struct.unpack("!4L", key[:key_size])
        sum, delta, mask = 0L, 0x9e3779b9L, 0xffffffffL
        for round in range(num_rounds):
            v0  = (v0 + (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]))) & mask
            sum = (sum + delta) & mask
            v1  = (v1 + (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[sum >> 11 & 3]))) & mask
        output  = vector = struct.pack("!2L", v0, v1)
        result.append(output)
    return base64.b64encode(bytes().join(result))



def decrypt_xor(data, key, block_size=8, key_size=16, num_rounds=32, padding='$'):
    """
    XOR-128 encryption

    `Required`
    :param str data:        ciphertext
    :param str key:         256-bit key

    `Optional`
    :param int block_size:  block size (default: 8)
    :param int key_size:    key size (default: 16)
    :param int num_rounds:  number of rounds (default: 32)
    :param str padding:     padding character (default: $)
    """
    data    = base64.b64decode(data)
    blocks  = [data[i * block_size:((i + 1) * block_size)] for i in range(len(data) // block_size)]
    vector  = blocks[0]
    result  = []
    for block in blocks[1:]:
        v0, v1 = struct.unpack("!2L", block)
        k = struct.unpack("!4L", key[:key_size])
        delta, mask = 0x9e3779b9L, 0xffffffffL
        sum = (delta * num_rounds) & mask
        for round in range(num_rounds):
            v1 = (v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[sum >> 11 & 3]))) & mask
            sum = (sum - delta) & mask
            v0 = (v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]))) & mask
        decode = struct.pack("!2L", v0, v1)
        output = str().join(chr(ord(x) ^ ord(y)) for x, y in zip(vector, decode))
        vector = block
        result.append(output)
    return str().join(result).rstrip(padding)



    
