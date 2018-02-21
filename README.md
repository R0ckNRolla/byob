

    ,adPPYYba, 8b,dPPYba,   ,adPPYb,d8 88,dPPYba,   aa       aa
    ""     `Y8 88P'   `"8a a8"    `Y88 88P'   `"8a  88       88
    ,adPPPPP88 88       88 8b       88 88           88       88
    88,    ,88 88       88 "8a,   ,d88 88           "8a,   ,d88
    `"8bbdP"Y8 88       88  `"YbbdP"Y8 88            `"YbbdP"Y8
                            aa,    ,88 	            aa,    ,88
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



                    https://github.com/colental/ae


    - 26 payloads (keylogger, webcam, packetsniffer, screenshot, etc.)
    - End-to-end encryption
    - Runs on Windows, Mac OS X, iOS, Linux, Android
    - No dependencies 
    - No configuration
    - Pure python source
    - Compiles source into native executable format for each host
    - Multiple delivery vectors - email, websites, ssh, ftp
    - Automated host discovery


     Angry Eggplant primarily acts as a remote access tool inspired by the
     Meterpreter shell of the Metasploit Project, with some major improvements.
     It is ultra-portable - it is written in pure python, has zero dependencies,
     runs on anything, requires no manual configuration, and does not require
     any downloads or installations to run - in fact, if it can't find something
     it needs, rather than raise an error or fail to run, it automatically
     downloads/installs it silently without any user interaction. This is
     convenient for the remote access tool, but the true power of this is in
     the autonomous mode which transforms the client from a reverse tcp shell
     loaded with many payloads into something more closely resembling a worm
     than a remote access tool. Operating in this mode it autonomously discovers
     and analyzes hosts to then generate, configure, and compile a unique
     encrypted deliverable for each target which acts as a stager that gains a
     foothold and acts a stager from which to download and execute the main client
     from. The client first establishes persistence with multiple methods to ensure
     redundancy. Next it seeks to discover new host machines in its local network,
     and spread itstelf to those hosts using mulitiple payload delivery vectors,
     such as email, ssh, and ftp. It does all this from memory without leaving a
     trace of evidence on the host machine's hard disk. It never connects to a
     command & control server or exposes the attacker in any way - rather it only
     will make connections with the machine that infected it and with any machines
     it subsequently infects. Finally, and most importantly, all communication over
     any network is encrypted from end-to-end with secure modern cryptography,
     thus minimizing the amount of information exposed to potential discovery by
     security researchers.
