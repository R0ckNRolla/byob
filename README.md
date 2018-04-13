
 
        ,adPPYYba, 8b,dPPYba,   ,adPPYb,d8 88,dPPYba,   aa       aa
        ""     `Y8 88P'   `"8a a8"    `Y88 88P'   `"8a  88       88
        ,adPPPPP88 88       88 8b       88 88           8b       88
        88,    ,88 88       88 "8a,   ,d88 88           "8a,   ,d88
        `"8bbdP"Y8 88       88  `"YbbdP"Y8 88            `"YbbdP"Y8
                                aa,    ,88               aa,    ,88
                                 "Y8bbdP"                 "Y8bbdP'
                                                       88                          ,d
                                                       88                          88
         ,adPPYba,  ,adPPYb,d8  ,adPPYb,d8 8b,dPPYba,  88 ,adPPYYba, 8b,dPPYba,    88
        a8P     88 a8"    `Y88 a8"    `Y88 88P'    "8a 88 ""     `Y8 88P'   `"8a MM88MMM
        8PP8888888 8b       88 8b       88 88       d8 88 ,adPPPPP88 88       88   88
        "8b,   ,aa "8a,   ,d88 "8a,   ,d88 88b,   ,a8" 88 88,    ,88 88       88   88
         `"Ybbd8"'  `"YbbdP"Y8  `"YbbdP"Y8 88`YbbdP"'  88 `"8bbdP"Y8 88       88   88,
                    aa,    ,88  aa,    ,88 88                                      "Y888
                     "Y8bbdP"    "Y8bbdP"  88

	Angry Eggplant is a project created as a result of exploring the malicious side of the
world of cyber security and software development and programs for educational purposes only

>  Runs on most major desktop operating systems with no configuration necessary
    - Windows
    - Mac OS X
    - Linux

> Functionality - remotely access target with reverse TCP shell
    - Keylogger       log the keystrokes, clipboard, and name of the active window	
    - Screenshot      snap screenshots of the current desktop				
    - Ransom          encrypt host files and ransom them to the user for Bitcoin
    - Root Access     bypass UAC to gain administrator privileges (Windows only)	
    - Upload          mass-upload the host's files to the server			
    - Webcam          live stream from webcam or auto-upload captured images/videos
    - Packetsniffer   monitor and capture host network traffic
    - Portscanner     explore the local network to find more hosts, open ports, etc.
    - Email           search emails for keywords, dump emails to server
    - SMS             send texts to phone numbers from host's contacts 
    
>  Portability - supports all major platforms & architectures
    - automated payload configuration
    - zero dependencies whatsoever (not even Python is required)
    - dynamically compiles unique stagers as native executables to avoid anti-virus detection
    - no downloads, no installations, no configuration, no dependencies
    
>  Security - encrypted communication, anti-forensics, firewall evasion
    - all communication is encrypted - between clients and server& between  server and database
    - AES cipher in OCB mode - secure data confidentiality, integrity, and authenticity
    - 256 bit session keys - generated via Diffie-Hellman Internet Key Exchange (IKE) - RFC 2631
    - firewall evasion - uses reverse shells for outbound connections that most firewalls allow
    - anti-anti-virus - randomized obfuscation guarantees unique hash every time
    - anti-forensics - encrypted stager executable is decrypted in memory at run-time 
    - more anti-forensics - automatic self-destruct + shutdown if virtual machine detected

> Persistence
    Windows
	- registry key - add Registry Key to always execute the program upon reboot
	- scheduled task - add Scheduled Task to execute the program at a regular interval
	- wmi object
