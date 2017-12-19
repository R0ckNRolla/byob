import os
import sys
import _winreg
import psutil

HKEY_LOCAL_MACHINE  = -2147483646
KEY_READ            = 131097
process_list        = []

def get_process_list():
    return [p.name() for p in psutil.process_iter()]      

def get_existing_key(k, key):
    try:
        hkey = _winreg.OpenKey(k, key, 0, KEY_READ)
        return hkey
    except:
        return False

def check_hyper_V():
    keys = [
            'SOFTWARE\\Microsoft\\Hyper-V', 
            'SOFTWARE\\Microsoft\\VirtualMachine', 
            'HARDWARE\\ACPI\\FADT\\vrtual',
            'HARDWARE\\ACPI\\RSDT\\vrtual',
            'SYSTEM\\ControlSet001\\Services\\vmicheartbeat', 
            'SYSTEM\\ControlSet001\\Services\\vmicvss', 
            'SYSTEM\\ControlSet001\\Services\\vmicshutdown', 
            'SYSTEM\\ControlSet001\\Services\\vmiexchange', 
    ]
    for key in keys:
        h = get_existing_key(HKEY_LOCAL_MACHINE, key)
        if h:
            _winreg.CloseKey(h)
            return key
    h = get_existing_key(HKEY_LOCAL_MACHINE, 'HARDWARE\\DESCRIPTION\\System')
    if h:
        string = str(_winreg.QueryValueEx(h, 'SystemBiosVersion')[0])
        if 'vrtual' in string:
            return string
    return False

def check_VMWare():
    keys = [
            'SYSTEM\\ControlSet001\\Services\\vmdebug', 
            'SYSTEM\\ControlSet001\\Services\\vmmouse', 
            'SYSTEM\\ControlSet001\\Services\\VMTools',
            'SYSTEM\\ControlSet001\\Services\\VMMEMCTL',
    ]
    for key in keys:
        h = get_existing_key(HKEY_LOCAL_MACHINE, key)
        if h:
            _winreg.CloseKey(h)
            return True
    h = get_existing_key(HKEY_LOCAL_MACHINE, 'HARDWARE\\DESCRIPTION\\System\\BIOS')
    if h:
        string = str(_winreg.QueryValueEx(h, 'SystemManufacturer')[0])
        if 'vmware' in string:
            return True

    plist = get_process_list()
    if 'vmwareuser.exe' in plist or 'vmwaretray.exe' in plist or 'vmtoolsd.exe' in plist:
        return True

def check_Virtual_PC():
    plist = get_process_list()
    if 'vmusrvc.exe' in plist or 'vmsrvc.exe' in plist or 'vmwareuser.exe' in plist or 'vmwaretray.exe' in plist:
        return True
    keys = [
            'SYSTEM\\ControlSet001\\Services\\vpc-s3', 
            'SYSTEM\\ControlSet001\\Services\\vpcuhub', 
            'SYSTEM\\ControlSet001\\Services\\msvmmouf'
    ]
    for key in keys:
        h = get_existing_key(HKEY_LOCAL_MACHINE, key)
        if h:
            _winreg.CloseKey(h)
            return True

def check_Virtual_Box():
    plist = get_process_list()
    if 'vboxservice.exe' in plist or 'vboxtray.exe' in plist:
        return True
    keys = [
            'HARDWARE\\ACPI\\FADT\\vbox_', 
            'HARDWARE\\ACPI\\RSDT\\vbox_', 
            'SYSTEM\\ControlSet001\\Services\\VBoxMouse',
            'SYSTEM\\ControlSet001\\Services\\VBoxGuest', 
            'SYSTEM\\ControlSet001\\Services\\VBoxService', 
            'SYSTEM\\ControlSet001\\Services\\VBoxSF', 
    ]
    for key in keys:
        h = get_existing_key(HKEY_LOCAL_MACHINE, key)
        if h:
            _winreg.CloseKey(h)
            return True
    h = get_existing_key(HKEY_LOCAL_MACHINE, 'HARDWARE\\DESCRIPTION\\System')
    if h:
        string = str(_winreg.QueryValueEx(h, 'SystemBiosVersion')[0])
        if 'vbox' in string:
            return True

def check_xen():
    plist = get_process_list()
    if 'xenservice.exe' in plist:
        return True
    keys = [
            'HARDWARE\\ACPI\\FADT\\xen', 
            'HARDWARE\\ACPI\\DSDT\\xen', 
            'HARDWARE\\ACPI\\RSDT\\xen',
            'SYSTEM\\ControlSet001\\Services\\xenevtchn',
            'SYSTEM\\ControlSet001\\Services\\xennet', 
            'SYSTEM\\ControlSet001\\Services\\xennet6', 
            'SYSTEM\\ControlSet001\\Services\\xensvc', 
            'SYSTEM\\ControlSet001\\Services\\xenvdb', 
    ]
    for key in keys:
        h = get_existing_key(HKEY_LOCAL_MACHINE, key)
        if h:
            _winreg.CloseKey(h)
            return True

def check_qemu():
    h = get_existing_key(HKEY_LOCAL_MACHINE, 'HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0')
    if h:
        string = str(_winreg.QueryValueEx(h, 'ProcessorNameString')[0])
        if 'vmware' in string:
            return True

def run(*args, **kwargs):
    try:
        return any([globals()[i]() for i in globals() if i.startswith('check')])
    except Exception as e:
        return str(e)
