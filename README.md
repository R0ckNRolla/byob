# BYOB (Build Your Own Botnet)

[![license](https://img.shields.io/github/license/mashape/apistatus.svg)](https://github.com/colental/byob/blob/master/LICENSE)

--------------------------------------------------

## Setup
### Installation
`git clone https://github.com/colental/byob`

### Configuration
Edit the [configuration](config.ini) file
to add any API Keys or login credentials
that you want to use for the following features:

- __Database__ MySQL database for clients, tasks, and results
    - *required*: host, user, password
    - *optional*: database
- __FTP__ automated mass-upload capability
    - *required*: host, user, password
- __Pastebin__ auto-upload data/documents anonymously to Pastebin
    - *requires*: api_dev_key
    - *optional*: api_user_key
- __Imgur__ auto-upload image files anonymously to Imgur
    - *required*: imgur_api_key 
- __Twilio__ distribute client droppers via SMS text messages
    - *required*: account_sid, api_key, auth_token
- __Bitcoin__ receive ransom payments anonymously through bitcoin
    - *required*: bitcoin_wallet
    - *optional*: coinbase_api_key

--------------------------------------------------

### Server
- __Usage__
    - `server.py <-p/--port PORT> [-c/--config CONFIG] [-h/--help] [-d/--debug]` 
- __Commands__
  - `client [ID]`: interact with selected client via reverse TCP shell
  - `clients [-v/--verbose]`: list details of all online & offline clients
  - `sessions [-v/--verbose]`: list session details online client session details
  - `back`: background the current session and put the shell on standby
  - `settings <option> [VALUE]`: show/set server console display settings
  - `query [SQL]`: query the MySQL database and return output, if any
  - `exit/quit [Y/N]`: exit the server and optionally keep sessions alive
- __Database__
  - **Clients**: adds new clients, manages current clients, removes old clients
  - **Sessions**: manages active online sessions and saves offline sessions
  - **Tasks**: records issued tasks and updates entries upon receiving results

--------------------------------------------------

## Client
- __Usage__
    - `client.py <py/exe/app> [options]`
       - `py`: core python stager
       - `exe`: executable binary in native format of host platform (*Windows + Linux*)
       - `app`: bundled application (*Mac OS X*)
       - `-n/--name NAME`: filename of the generated client
       - `-i/--icon ICON`: icon image file for generated client (default: Java)
- __Modules__
    - **Ransom Files**:        encrypt host files and ransom them to the user for Bitcoin
    - **Upload Files**:        automatically upload valuable data via FTP or Pastebin
    - **Webcam**:              live stream from webcam or auto-upload captured images/videos
    - **Keylogger**:           log the keystrokes, clipboard, and name of the active window
    - **Screenshot**:          snap screenshots of the current users desktop 
    - **Escalate Privileges**: bypass UAC to gain administrator privileges (Windows platforms)
    - **Packet Sniffer**:      capture logs of host network traffic (Linux & Mac OSX)
    - **Port Scanner**:        scan the local network to map online hosts and open ports
    - **Email Distribution**:  automated mass email dropper links disguised as Google Docs invite
    - **Phone Distribution**:  automated mass text (SMS) dropper links disguised as Imgur links
- __Stealth__
    - **Firewall evasion**     reverse TCP shells use outgoing connections not filtered by firewalls
    - **Anti-antivirus**       randomized obfuscation guarantees unique hash for every client binary
    - **Anti-forensics**       client binaries are encrypted and is decrypted in memory at run-time
    - **Process Monitoring**   continually monitor & kill any task manager and antivirus processes
- __Portability__
    - **Pure Python**:         simple, powerful language that makes writing your own modules easy
    - **Platform-Agnostic**:   python comes pre-installed most major platforms & architectures
    - **Python Not Required**: client executable compiled with a standalone Python interpreter
    - **Zero Dependencies**:   missing packages are loaded remotely and then dynamically imported
    - **Disguised**:           use icons of cross-platform plugins/applications (default: Java)
- __Encryption__
    - **End-to-end**:          all communication between clients and server is encrypted on both ends
    - **256 bit keys**:        Diffie-Hellman Key Exchange (RFC 2631) is safe even on monitored networks
    - **AES in OCB mode**:     secure data confidentiality, integrity, and authenticity
    - **XOR cipher backup**:   classic XOR encryption hand-coded to ensure encryption even without PyCrypto

### Persistence
- __Windows__
    - **Scheduled Task**:     add a Scheduled Task to execute the client at a regular interval
    - **WMI Event**:          use Powershell to make a WMI event to run client on startup
    - **Startup File**:       make an internet shortcut to startup with local path as URL (file:///)
    - **Registry Key**:       modify Windows Registry by adding a 'Run' key to run client on startup
- __MacOSX__
    - **Crontab Job**:        create a crontab job that runs the client on a regular interval
- __Linux__
    - **Launch Agent**:       run a Bash script that adds a new Launch Agent to run client on startup
- __All Platforms__
    - **File Permissions**:   modify client permissions to prevent non-owners from reading/removing it
    - **File Attributes**:    modify client attributes to make it hidden/system-file/read-only/etc.
    - **Add New User**:       add a new username + password that is does not appear at login screen

---------------------------------------------