#!/usr/bin/env python
# -*- coding: utf-8 -*-
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

'''

from Crypto.Cipher import AES
import os
import sys
import base64
import random
import requests

PADDING     = '{'
adjectives  = [i.title().replace('-','') for i in requests.get('https://raw.githubusercontent.com/hathcox/Madlibs/master/adjective.list').content.split()]
nouns       = [i.title().replace('-','') for i in requests.get('https://raw.githubusercontent.com/hathcox/Madlibs/master/nouns.list').content.split()]
random_key  = lambda n: str().join(random.choice([chr(i) for i in range(48, 123) if i not in (92,96)]) for x in range(n))
random_var  = lambda: adjectives.pop(adjectives.index(random.choice(adjectives))) + adjectives.pop(adjectives.index(random.choice(adjectives))) + nouns.pop(nouns.index(random.choice(nouns)))
get_imports = lambda text: [i.strip() for i in text.splitlines() if 'import' in i and i.strip().split()[0] in ('import','from')]
packages    = lambda code: [[q.strip(',') for q in i.split()[i.split().index('import') + 1:]][0].split(',') for i in get_imports(code)]
pad         = lambda s: str(s) + (AES.block_size - len(str(s)) % AES.block_size) * PADDING
EncodeAES   = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES   = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

def obfuscate(filename):
    code        = open(filename, 'r').read()
    output_file = 'encrypted_{}'.format(filename)
    imports     = get_imports(code)
    output      = [line for line in code.splitlines() if line not in imports]
    key         = random_key(32)
    b64var      = random_var()
    aesvar      = random_var()
    cipher      = AES.new(key)
    encrypted   = EncodeAES(cipher, '\n'.join(output))
    imports.append("from base64 import b64decode as %s" %(b64var))
    imports.append("from Crypto.Cipher import AES as %s" %(aesvar))
    random.shuffle(imports)

    with file(output_file, 'w') as fp:
        fp.write(";".join(imports) + "\n")
        fp.write("exec(%s(\"%s\"))" % (b64var,base64.b64encode("exec(%s.new(\"%s\").decrypt(%s(\"%s\")).rstrip(\"{\"))\n" %(aesvar,key,b64var,encrypted))))

    return output_file
    

def main(path=None):
    if path:
	if os.path.isfile(path):
            result = obfuscate(path)
	else:
	    result = "file '{}' not found".format(path)
	return result
    elif len(sys.argv) == 2:
	if os.path.isfile(sys.argv[1]):
	    result = obfuscate(sys.argv[1])
	else:
	    result = "file '{}' not found".format(sys.argv[1])
        print result


if __name__ == '__main__':
    main()
