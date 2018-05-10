# BYOB (Build Your Own Botnet)

[![license](https://img.shields.io/github/license/mashape/apistatus.svg)](https://github.com/colental/byob/blob/master/LICENSE)

### Installation
- **Usage**: `git clone https://github.com/colental/byob`

### Configuration
Edit the [configuration](config.ini) file to add any API Keys or login credentials 
that you want to use for the following features:
- **MySQL**:  `host`, `user`, `password`
- **Pastebin**:  `api_dev_key`
- **Twilio**:  `account_sid`, `api_key`, `auth_token`
- **FTP**:  `host`, `user`, `password`
- **Bitcoin**:  `wallet_address`
- **Imgur**:  `api_key`

# Client
**Usage**: `client.py <py/exe/app> [-n/--name NAME] [-i/--icon ICON]`

### Modules
- **Ransom Files**  encrypt host files and ransom them to the user for Bitcoin
- **Upload Files**: automatically upload valuable data via FTP or Pastebin
- **Webcam**: live stream from webcam or auto-upload captured images/videos
- **Keylogger**: log the keystrokes, clipboard, and name of the active window
- **Screenshot**: snap screenshots of the current users desktop 
- **Privileges**: bypass UAC to gain administrator privileges (Windows platforms)
- **Packet Sniffer**: capture logs of host network traffic (Linux & Mac OSX)
- **Port Scanner**: scan the local network to map online hosts and open ports
- **Outlook**: upload all emails or only emails matching keywords or phrases
- **Email Distribution**: automated email dropper links disguised as Google Docs invite
- **Phone Distribution**: automated text (SMS) dropper links disguised as Imgur links

### Persistence
- **Scheduled Task**:     (*Windows*) add a Scheduled Task to execute the client at a regular interval
- **WMI Event**:          (*Windows*) use Powershell to make a WMI event to run client on startup
- **Startup File**:       (*Windows*) make an internet shortcut to startup with local path as URL (file:///)
- **Registry Key**:       (*Windows*) modify Windows Registry by adding a 'Run' key to run client on startup
- **Crontab Job**:        (*Linux*) create a crontab job that runs the client on a regular interval
- **Launch Agent**:       (*MacOSX*) run a Bash script that adds a new Launch Agent to run client on startup
- **File Permissions**:   modify client permissions to prevent non-owners from reading/removing it
- **File Attributes**:    modify client attributes to make it hidden/system-file/read-only/etc.
- **Add New User**:       add a new username + password that is does not appear at login screen

### Stealth
- **Firewall evasion**     reverse TCP shells use outgoing connections not filtered by firewalls
- **Anti-antivirus**       randomized obfuscation guarantees unique hash for every client binary
- **Anti-forensics**       client binaries are encrypted and is decrypted in memory at run-time
- **Process Monitoring**   continually monitor & kill any task manager and antivirus processes

### Encryption
- **End-to-end**:          all communication between clients and server is encrypted on both ends
- **256 bit keys**:        Diffie-Hellman Key Exchange (RFC 2631) is safe even on monitored networks
- **AES in OCB mode**:     secure data confidentiality, integrity, and authenticity
- **XOR backup cipher**:   classic XOR encryption hand-coded to ensure encryption even without PyCrypto package

### Portability
- **Pure Python**:         simple, powerful language that makes writing your own modules easy
- **Platform-Agnostic**:   python comes pre-installed most major platforms & architectures
- **Python Not Required**: client executable compiled with a standalone Python interpreter
- **Zero Dependencies**:   missing packages are loaded remotely and then dynamically imported
- **Disguised**:           use icons of cross-platform plugins/applications (default: Java)
---------------------------------------------

# Server
**Usage**: `server.py <-p/--port PORT> [-c/--config CONFIG] [-h/--help] [-d/--debug]` 

### Commands
- `client [ID]`: interact with selected client via reverse TCP shell
- `clients [-v/--verbose]`: list details of all online & offline clients
- `sessions [-v/--verbose]`: list session details online client session details
- `back`: background the current session and put the shell on standby
- `settings <option> [VALUE]`: show/set server console display settings
- `query [SQL]`: query the MySQL database and return output, if any
- `exit/quit [Y/N]`: exit the server and optionally keep sessions alive

### Database
- **Clients**: adds new clients, manages current clients, removes old clients
- **Sessions**: manages active online sessions and saves offline sessions
- **Tasks**: records issued tasks and updates entries upon receiving results
____________________________________________