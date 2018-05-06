# BYOB (Build Your Own Botnet)

[![license](https://img.shields.io/github/license/mashape/apistatus.svg)](https://github.com/colental/byob/master/LICENSE)

Use simple terminal commands to build:
- __Servers__  functional Command & Control servers
- __Payloads__ clients loaded with remote-access tools and host-recreuitment features
- __Droppers__ compiled into executable binaries and disgusied as plugin updates

...*all without writing a single line of code!*

### Features
- **Ransom Files**:        encrypt host files and ransom them to the user for Bitcoin
- **Upload Files**:        automatically upload valuable data via FTP or Pastebin
- **Outlook Email**:       upload emails / send dropper links to contacts disguised as Imgur link
- **SMS/Texting**:         text dropper link to contacts disguised as a shared Imgur link
- **Webcam**:              live stream from webcam or auto-upload captured images/videos
- **Keylogger**:           log the keystrokes, clipboard, and name of the active window
- **Screenshot**:          snap screenshots of the current desktop
- **Reverse TCP Shell**:   remote access directly through a terminal with all Unix command
- **Escalate Privileges**: bypass UAC to gain administrator privileges (Windows only)
- **Packet Sniffer**:      capture logs of host network traffic
- **Port Scanner**:        scan the local network to map online hosts and open ports

### Portability
- **Pure Python**:         simple, powerful language that makes writing your own modules easy
- **Platform-Agnostic**:   python comes pre-installed most major platforms & architectures
- **Runs without Python**: no problem! clients are compiled with a standalone Python interpreter
- **Zero Dependencies**:   missing packages are loaded remotely and then dynamically imported

### Encryption
- **End-to-end**:          all communication between clients and server is encrypted on both ends
- **AES in OCB mode**:     secure data confidentiality, integrity, and authenticity
- **256 bit keys**:        Diffie-Hellman Key Exchange (RFC 2631) is safe even on monitored networks

### Security
- **Firewall evasion**   reverse TCP shells (firewalls generally allow
- **Anti-antivirus**     randomized obfuscation guarantees unique hash for every client binary
- **Anti-forensics**     client binaries are encrypted and is decrypted in memory at run-time
- **Counter-measures**   continually monitor & kill any task manager and antivirus processes

### Persistence
- **Crontab Job**:        *(Linux)*   add a crontab job that runs the client on a regular interval
- **Launch Agent**:       *(Mac OSX)* run a Bash script that adds a new Launch Agent to run client on startup
- **Scheduled Task**:     *(Windows)* add a Scheduled Task to execute the client at a regular interval
- **WMI Event**:          *(Windows)* use Powershell to make a WMI event to run client on startup
- **Startup File**:       *(Windows)* create internet shortcut to startup with local path as URL (file:///)
- **Registry Key**:       *(Windows)* modify Windows Registry by adding a 'Run' key to run client on startup
- **File Permissions**:   modify client permissions to prevent non-owners from reading/removing it
- **File Attributes**:    modify client attributes to make it hidden/system-file/read-only/etc.
- **Add New User**:       create a new username + password that is does not appear at login screen

---------------------------------------------

## Setup

### Installation
`git clone https://github.com/colental/byob`

### Configuration
Edit the [configuration](config.ini) file
to add any API Keys or login credentials
that you want to use for the following features:

- __Database__ MySQL database for clients, tasks, and results
  - host
  - user
  - password
- __FTP__ mass-upload capability
  - host
  - user
  - password
- __Pastebin__ auto-upload data/documents anonymously to Pastebin
  - api_dev_key
  - api_user_key (optional - authenticated API allows more pastes/day)
- __Imgur__ auto-upload image files anonymously to Imgur
  - api_key
- __Twilio__ automamtically send SMS/texts from an online phone
  - account_sid
  - api_key
  - secret_key
- __Bitcoin__ receive ransom payments anonymously through bitcoin
  - wallet_address  - static bitcoin wallet address for receiving payments
  - coinbase_api_key - create temporary wallets with link to a payment interface with a countdown timer

**Note**: none of this information is ever logged or saved in any way

--------------------------------------------------

## Usage 

### Create a Command & Control Server 
`server.py -p/--port <port>`

### Generate a client stager
`client.py <type> [options]`
  - **Types** filetype to generate
    - `py`  Python (stager)
    - `exe` portable executable (Windows)
    - `app` application bundle (Mac OSX)
    - `bin` executable binary (Linux)
  - **Options** optional settings for payload
    - `-i/--icon [icon]` *.ico (Windows), *.icns (Mac OSX), *.png (Linux)
    - `-n/--name [name]` file name of final executable (no extension)
    - `-o/--obfuscate` obfuscate source before compiling
    - `-e/--encrypt [key]` use key to encrypt source before compiling
