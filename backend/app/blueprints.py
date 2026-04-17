from typing import Dict, List

TECHNIQUE_BLUEPRINTS: Dict[str, List[Dict]] = {
    "T1566.001": [
        {"name": "Phishing attachment via Office macro", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.parentImage", "contains", "WINWORD"), ("win.eventdata.image", "endswith", "cmd.exe")]},
        {"name": "Phishing - PowerShell spawned from Office", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.parentImage", "contains", "WINWORD"), ("win.eventdata.image", "endswith", "powershell.exe")]},
    ],
    "T1566.002": [
        {"name": "Phishing link - browser spawning script", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.parentImage", "contains", "chrome"), ("win.eventdata.image", "endswith", "powershell.exe")]},
    ],
    "T1190": [
        {"name": "Exploit public app - web shell spawn", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.parentImage", "contains", "w3wp"), ("win.eventdata.image", "endswith", "cmd.exe")]},
    ],
    "T1133": [
        {"name": "External remote service - VPN/RDP inbound", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "3389")]},
    ],
    "T1078": [
        {"name": "Valid account logon anomaly", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "net.exe"), ("win.eventdata.commandLine", "contains", "use")]},
    ],
    "T1204.001": [
        {"name": "User execution - malicious link via browser", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.parentImage", "contains", "chrome"), ("win.eventdata.image", "endswith", "mshta.exe")]},
    ],
    "T1204.002": [
        {"name": "User execution - malicious Office macro", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.parentImage", "contains", "EXCEL"), ("win.eventdata.image", "endswith", "cmd.exe")]},
    ],
    "T1059.001": [
        {"name": "PowerShell execution (generic)", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "powershell.exe")]},
        {"name": "PowerShell encoded command", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "powershell.exe"), ("win.eventdata.commandLine", "contains", "-enc")]},
        {"name": "PowerShell download cradle", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "powershell.exe"), ("win.eventdata.commandLine", "contains", "DownloadString")]},
        {"name": "PowerShell IEX in-memory", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "powershell.exe"), ("win.eventdata.commandLine", "contains", "IEX")]},
    ],
    "T1059.003": [
        {"name": "CMD suspicious execution", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "cmd.exe"), ("win.eventdata.commandLine", "contains", "/c")]},
        {"name": "CMD spawned from Office", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.parentImage", "contains", "WINWORD"), ("win.eventdata.image", "endswith", "cmd.exe")]},
    ],
    "T1059.005": [
        {"name": "VBScript execution via cscript", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "cscript.exe"), ("win.eventdata.commandLine", "contains", ".vbs")]},
        {"name": "VBScript execution via wscript", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "wscript.exe")]},
    ],
    "T1059.006": [
        {"name": "Python script execution", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "contains", "python"), ("win.eventdata.commandLine", "contains", ".py")]},
    ],
    "T1059.007": [
        {"name": "JavaScript via wscript/cscript", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "wscript.exe"), ("win.eventdata.commandLine", "contains", ".js")]},
    ],
    "T1047": [
        {"name": "WMI process creation", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "wmic.exe"), ("win.eventdata.commandLine", "contains", "process call create")]},
        {"name": "WMI remote execution", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "wmic.exe"), ("win.eventdata.commandLine", "contains", "/node:")]},
    ],
    "T1053.005": [
        {"name": "Scheduled task creation", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "schtasks.exe"), ("win.eventdata.commandLine", "contains", "/create")]},
        {"name": "Scheduled task remote", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "schtasks.exe"), ("win.eventdata.commandLine", "contains", "/s ")]},
    ],
    "T1053.002": [
        {"name": "At.exe scheduled task", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "at.exe")]},
    ],
    "T1218.005": [
        {"name": "Mshta remote script", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "mshta.exe"), ("win.eventdata.commandLine", "contains", "http")]},
        {"name": "Mshta vbscript inline", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "mshta.exe"), ("win.eventdata.commandLine", "contains", "vbscript")]},
    ],
    "T1218.010": [
        {"name": "Regsvr32 suspicious usage", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "regsvr32.exe")]},
        {"name": "Regsvr32 loading remote SCT", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "regsvr32.exe"), ("win.eventdata.commandLine", "contains", "http")]},
    ],
    "T1218.011": [
        {"name": "Rundll32 suspicious usage", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "rundll32.exe")]},
        {"name": "Rundll32 from AppData", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "rundll32.exe"), ("win.eventdata.commandLine", "contains", "\\AppData\\")]},
    ],
    "T1105": [
        {"name": "Remote file download via PowerShell", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "powershell.exe"), ("win.eventdata.commandLine", "contains", "DownloadString")]},
        {"name": "Remote file download via certutil", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "certutil.exe"), ("win.eventdata.commandLine", "contains", "urlcache")]},
        {"name": "Remote file download via bitsadmin", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "bitsadmin.exe"), ("win.eventdata.commandLine", "contains", "/transfer")]},
        {"name": "Remote file download via curl", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "curl.exe"), ("win.eventdata.commandLine", "contains", "http")]},
    ],
    "T1547.001": [
        {"name": "Registry Run key write", "logsource": ("windows", "registry_event"),
         "conditions": [("win.eventdata.targetObject", "contains", "CurrentVersion\\Run")]},
        {"name": "Registry RunOnce key write", "logsource": ("windows", "registry_event"),
         "conditions": [("win.eventdata.targetObject", "contains", "CurrentVersion\\RunOnce")]},
    ],
    "T1547.004": [
        {"name": "Winlogon registry modification", "logsource": ("windows", "registry_event"),
         "conditions": [("win.eventdata.targetObject", "contains", "Winlogon"), ("win.eventdata.targetObject", "contains", "Userinit")]},
    ],
    "T1543.003": [
        {"name": "New Windows service registered", "logsource": ("windows", "registry_event"),
         "conditions": [("win.eventdata.targetObject", "contains", "CurrentControlSet\\Services")]},
    ],
    "T1546.012": [
        {"name": "IFEO Debugger hijack", "logsource": ("windows", "registry_event"),
         "conditions": [("win.eventdata.targetObject", "contains", "Image File Execution Options"), ("win.eventdata.details", "contains", "Debugger")]},
    ],
    "T1574.001": [
        {"name": "DLL search order hijack - AppData write", "logsource": ("windows", "file_event"),
         "conditions": [("win.eventdata.targetFilename", "contains", "\\AppData\\"), ("win.eventdata.targetFilename", "endswith", ".dll")]},
    ],
    "T1574.002": [
        {"name": "DLL side-loading suspicious path", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "contains", "\\AppData\\"), ("win.eventdata.commandLine", "contains", ".dll")]},
    ],
    "T1136.001": [
        {"name": "Local account creation via net", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "net.exe"), ("win.eventdata.commandLine", "contains", "user /add")]},
    ],
    "T1055": [
        {"name": "Process injection - PowerShell", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "powershell.exe"), ("win.eventdata.commandLine", "contains", "VirtualAlloc")]},
    ],
    "T1055.001": [
        {"name": "DLL injection via rundll32", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "rundll32.exe"), ("win.eventdata.commandLine", "contains", "\\Temp\\")]},
    ],
    "T1055.012": [
        {"name": "Process hollowing indicators", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "NtUnmapViewOfSection")]},
    ],
    "T1068": [
        {"name": "Exploit privilege escalation via service", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.parentImage", "endswith", "services.exe"), ("win.eventdata.image", "endswith", "cmd.exe")]},
    ],
    "T1134.001": [
        {"name": "Token impersonation via PowerShell", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "powershell.exe"), ("win.eventdata.commandLine", "contains", "ImpersonateLoggedOnUser")]},
    ],
    "T1134.002": [
        {"name": "Create process with token", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "CreateProcessWithToken")]},
    ],
    "T1027": [
        {"name": "Encoded command indicators", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "-enc")]},
        {"name": "Base64 in command line", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "base64")]},
        {"name": "Reversed string execution", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "-join")]},
    ],
    "T1036": [
        {"name": "Masquerading - svchost from wrong parent", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "contains", "svchost"), ("win.eventdata.parentImage", "endswith", "cmd.exe")]},
    ],
    "T1140": [
        {"name": "Deobfuscation via certutil decode", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "certutil.exe"), ("win.eventdata.commandLine", "contains", "-decode")]},
    ],
    "T1562.001": [
        {"name": "Disable Windows Defender via PowerShell", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "powershell.exe"), ("win.eventdata.commandLine", "contains", "Set-MpPreference")]},
        {"name": "Disable firewall via netsh", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "netsh.exe"), ("win.eventdata.commandLine", "contains", "off")]},
    ],
    "T1070.001": [
        {"name": "Event log cleared via wevtutil", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "wevtutil.exe"), ("win.eventdata.commandLine", "contains", "cl")]},
    ],
    "T1070.004": [
        {"name": "File deletion via cmd del", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "cmd.exe"), ("win.eventdata.commandLine", "contains", " del ")]},
        {"name": "File deletion via PowerShell", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "powershell.exe"), ("win.eventdata.commandLine", "contains", "Remove-Item")]},
    ],
    "T1497.001": [
        {"name": "Virtualization check via WMI", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "wmic.exe"), ("win.eventdata.commandLine", "contains", "computersystem")]},
    ],
    "T1003.001": [
        {"name": "LSASS access via command", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "lsass")]},
        {"name": "Mimikatz sekurlsa", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "sekurlsa")]},
        {"name": "Mimikatz reference", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "mimikatz")]},
    ],
    "T1003.002": [
        {"name": "SAM hive save via reg.exe", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "reg.exe"), ("win.eventdata.commandLine", "contains", "save")]},
    ],
    "T1003.003": [
        {"name": "NTDS.dit access via ntdsutil", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "ntdsutil.exe")]},
    ],
    "T1110.001": [
        {"name": "Password brute force via net", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "net.exe"), ("win.eventdata.commandLine", "contains", "use")]},
    ],
    "T1110.003": [
        {"name": "Password spraying via PowerShell", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "powershell.exe"), ("win.eventdata.commandLine", "contains", "Invoke-Spray")]},
    ],
    "T1555.003": [
        {"name": "Browser credential theft", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "Login Data")]},
    ],
    "T1056.001": [
        {"name": "Keylogging via PowerShell", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "powershell.exe"), ("win.eventdata.commandLine", "contains", "GetAsyncKeyState")]},
    ],
    "T1539": [
        {"name": "Cookie theft via browser process", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "Cookies")]},
    ],
    "T1082": [
        {"name": "System info enumeration", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "systeminfo.exe")]},
    ],
    "T1046": [
        {"name": "Network scan via PowerShell", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "powershell.exe"), ("win.eventdata.commandLine", "contains", "Test-NetConnection")]},
        {"name": "Network scan via nmap", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "nmap")]},
    ],
    "T1087.001": [
        {"name": "Local account enumeration", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "net.exe"), ("win.eventdata.commandLine", "contains", "user")]},
    ],
    "T1087.002": [
        {"name": "Domain account enumeration", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "net.exe"), ("win.eventdata.commandLine", "contains", "domain")]},
    ],
    "T1083": [
        {"name": "File enumeration via dir", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "cmd.exe"), ("win.eventdata.commandLine", "contains", "dir /s")]},
    ],
    "T1057": [
        {"name": "Process discovery via tasklist", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "tasklist.exe")]},
        {"name": "Process discovery via PowerShell", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "powershell.exe"), ("win.eventdata.commandLine", "contains", "Get-Process")]},
    ],
    "T1135": [
        {"name": "Network share enumeration", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "net.exe"), ("win.eventdata.commandLine", "contains", "view")]},
    ],
    "T1069.001": [
        {"name": "Local group enumeration", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "net.exe"), ("win.eventdata.commandLine", "contains", "localgroup")]},
    ],
    "T1069.002": [
        {"name": "Domain group enumeration", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "net.exe"), ("win.eventdata.commandLine", "contains", "group /domain")]},
    ],
    "T1016": [
        {"name": "Network config discovery via ipconfig", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "ipconfig.exe")]},
        {"name": "Network config via PowerShell", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "powershell.exe"), ("win.eventdata.commandLine", "contains", "Get-NetIPAddress")]},
    ],
    "T1033": [
        {"name": "Current user discovery via whoami", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "whoami.exe")]},
    ],
    "T1018": [
        {"name": "Remote system discovery via ping", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "ping.exe"), ("win.eventdata.commandLine", "contains", "-n")]},
        {"name": "Remote system discovery via nslookup", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "nslookup.exe")]},
    ],
    "T1021.001": [
        {"name": "Outbound RDP connection", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "3389")]},
    ],
    "T1021.002": [
        {"name": "SMB lateral movement", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "445")]},
    ],
    "T1021.006": [
        {"name": "WinRM lateral movement", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "5985")]},
    ],
    "T1550.002": [
        {"name": "Pass the hash via wmic", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "wmic.exe"), ("win.eventdata.commandLine", "contains", "/node:")]},
    ],
    "T1570": [
        {"name": "Lateral tool transfer via SMB", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "445"), ("win.eventdata.image", "endswith", "cmd.exe")]},
    ],
    "T1534": [
        {"name": "Internal spearphishing via Outlook", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.parentImage", "contains", "OUTLOOK"), ("win.eventdata.image", "endswith", "powershell.exe")]},
    ],
    "T1080": [
        {"name": "Taint shared content - write to share", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "\\\\"), ("win.eventdata.commandLine", "contains", "copy")]},
    ],
    "T1560.001": [
        {"name": "Archive via 7zip or WinRAR", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "contains", "7z"), ("win.eventdata.commandLine", "contains", " a ")]},
        {"name": "Archive via PowerShell compress", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "powershell.exe"), ("win.eventdata.commandLine", "contains", "Compress-Archive")]},
    ],
    "T1005": [
        {"name": "Local data collection via xcopy", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "xcopy.exe")]},
        {"name": "Local data collection via robocopy", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "robocopy.exe")]},
    ],
    "T1074.001": [
        {"name": "Local data staged in temp folder", "logsource": ("windows", "file_event"),
         "conditions": [("win.eventdata.targetFilename", "contains", "\\Temp\\")]},
    ],
    "T1113": [
        {"name": "Screenshot via PowerShell", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "powershell.exe"), ("win.eventdata.commandLine", "contains", "CopyFromScreen")]},
    ],
    "T1115": [
        {"name": "Clipboard access via PowerShell", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "powershell.exe"), ("win.eventdata.commandLine", "contains", "Get-Clipboard")]},
    ],
    "T1071.001": [
        {"name": "Outbound HTTPS from PowerShell", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "443"), ("win.eventdata.image", "endswith", "powershell.exe")]},
        {"name": "Outbound HTTP from PowerShell", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "80"), ("win.eventdata.image", "endswith", "powershell.exe")]},
    ],
    "T1071.004": [
        {"name": "Suspicious DNS query", "logsource": ("windows", "dns_query"),
         "conditions": [("win.eventdata.queryName", "contains", ".onion")]},
    ],
    "T1090": [
        {"name": "Proxy connection via netsh", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "netsh.exe"), ("win.eventdata.commandLine", "contains", "portproxy")]},
    ],
    "T1090.003": [
        {"name": "Tor exit node network connection", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "9050")]},
    ],
    "T1095": [
        {"name": "Non-standard protocol raw socket", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "4444")]},
    ],
    "T1571": [
        {"name": "Non-standard port 8080", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "8080")]},
        {"name": "Non-standard port 8443", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "8443")]},
    ],
    "T1573": [
        {"name": "Encrypted channel via HTTPS", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "443"), ("win.eventdata.image", "endswith", "powershell.exe")]},
    ],
    "T1573.001": [
        {"name": "Symmetric encryption C2", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "AES")]},
    ],
    "T1573.002": [
        {"name": "Asymmetric encryption C2", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "RSA")]},
    ],
    "T1132": [
        {"name": "Data encoding via certutil", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "certutil.exe"), ("win.eventdata.commandLine", "contains", "-encode")]},
    ],
    "T1001": [
        {"name": "Data obfuscation in traffic", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "base64"), ("win.eventdata.image", "endswith", "powershell.exe")]},
    ],
    "T1008": [
        {"name": "Fallback C2 channel", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "80"), ("win.eventdata.image", "endswith", "powershell.exe")]},
    ],
    "T1041": [
        {"name": "Exfil over C2 HTTPS", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "443"), ("win.eventdata.image", "endswith", "powershell.exe")]},
    ],
    "T1567": [
        {"name": "Exfil to web service via PowerShell", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "443"), ("win.eventdata.image", "endswith", "powershell.exe")]},
    ],
    "T1567.002": [
        {"name": "Cloud storage exfiltration via PowerShell", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "443"), ("win.eventdata.image", "endswith", "powershell.exe")]},
        {"name": "Cloud storage upload via cmd", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "upload"), ("win.eventdata.image", "endswith", "cmd.exe")]},
    ],
    "T1048": [
        {"name": "Exfil over alternative protocol", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "21")]},
    ],
    "T1048.003": [
        {"name": "Exfil over unencrypted protocol", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "21"), ("win.eventdata.image", "endswith", "ftp.exe")]},
    ],
    "T1490": [
        {"name": "Shadow copy deletion via vssadmin", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "vssadmin.exe"), ("win.eventdata.commandLine", "contains", "delete")]},
        {"name": "BCDedit recovery disabled", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "bcdedit.exe"), ("win.eventdata.commandLine", "contains", "recoveryenabled")]},
    ],
    "T1486": [
        {"name": "Ransomware file extension indicator", "logsource": ("windows", "file_event"),
         "conditions": [("win.eventdata.targetFilename", "contains", ".encrypted")]},
        {"name": "Mass file modification pattern", "logsource": ("windows", "file_event"),
         "conditions": [("win.eventdata.targetFilename", "contains", ".locked")]},
    ],
    "T1489": [
        {"name": "Service stop via net stop", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "net.exe"), ("win.eventdata.commandLine", "contains", "stop")]},
        {"name": "Service stop via sc.exe", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "sc.exe"), ("win.eventdata.commandLine", "contains", "stop")]},
    ],
    "T1491.001": [
        {"name": "Local defacement - wallpaper change", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "Wallpaper")]},
    ],

    # =========================================
    # CREDENTIAL ACCESS — ADDITIONAL
    # =========================================
    "T1003": [
        {"name": "OS credential dumping (generic)", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "lsass")]},
    ],
    "T1003.004": [
        {"name": "LSA Secrets dump via reg", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "reg.exe"), ("win.eventdata.commandLine", "contains", "SECURITY")]},
    ],
    "T1003.005": [
        {"name": "Cached domain credentials via reg", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "reg.exe"), ("win.eventdata.commandLine", "contains", "Cache")]},
    ],
    "T1003.006": [
        {"name": "DCSync via mimikatz lsadump", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "lsadump")]},
    ],
    "T1003.007": [
        {"name": "Proc filesystem credential access", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "/proc/")]},
    ],
    "T1003.008": [
        {"name": "/etc/passwd and /etc/shadow access", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "/etc/shadow")]},
    ],
    "T1110.002": [
        {"name": "Password cracking via hashcat", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "hashcat")]},
    ],
    "T1110.004": [
        {"name": "Credential stuffing via tool", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "Invoke-CredentialStuffing")]},
    ],
    "T1212": [
        {"name": "Credential access via exploit", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "exploit"), ("win.eventdata.parentImage", "endswith", "services.exe")]},
    ],
    "T1528": [
        {"name": "Application access token theft", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "access_token")]},
    ],
    "T1552.001": [
        {"name": "Credentials in files - password search via findstr", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "findstr"), ("win.eventdata.commandLine", "contains", "password")]},
        {"name": "Credentials in files via PowerShell", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "powershell.exe"), ("win.eventdata.commandLine", "contains", "Get-Content")]},
    ],
    "T1552.002": [
        {"name": "Credentials in registry via reg query", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "reg.exe"), ("win.eventdata.commandLine", "contains", "password")]},
        {"name": "Autologon credentials in registry", "logsource": ("windows", "registry_event"),
         "conditions": [("win.eventdata.targetObject", "contains", "Winlogon"), ("win.eventdata.details", "contains", "DefaultPassword")]},
    ],
    "T1552.004": [
        {"name": "Private key search via cmd", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", ".pem"), ("win.eventdata.image", "endswith", "cmd.exe")]},
        {"name": "Private key access via PowerShell", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", ".key"), ("win.eventdata.image", "endswith", "powershell.exe")]},
    ],
    "T1552.006": [
        {"name": "Group policy preference credentials", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "cpassword")]},
    ],
    "T1555.001": [
        {"name": "Keychain access", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "security find-generic-password")]},
    ],
    "T1555.004": [
        {"name": "Windows Credential Manager access via cmdkey", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "cmdkey.exe")]},
        {"name": "Credential manager via PowerShell", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "CredentialManager")]},
    ],
    "T1555.005": [
        {"name": "Password manager access (KeePass)", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "keepass")]},
    ],
    "T1557.001": [
        {"name": "LLMNR/NBT-NS poisoning via Responder", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "Responder")]},
    ],
    "T1557.002": [
        {"name": "ARP cache poisoning", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "arp.exe"), ("win.eventdata.commandLine", "contains", "-s")]},
    ],
    "T1558.001": [
        {"name": "Golden ticket via mimikatz", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "kerberos::golden")]},
    ],
    "T1558.002": [
        {"name": "Silver ticket via mimikatz", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "kerberos::silver")]},
    ],
    "T1558.003": [
        {"name": "Kerberoasting via PowerShell", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "Invoke-Kerberoast")]},
        {"name": "Kerberoasting via Rubeus", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "Rubeus"), ("win.eventdata.commandLine", "contains", "kerberoast")]},
    ],
    "T1558.004": [
        {"name": "AS-REP Roasting via PowerShell", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "Get-ASREPHash")]},
        {"name": "AS-REP Roasting via Rubeus", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "asreproast")]},
    ],

    # =========================================
    # DEFENSE EVASION — ADDITIONAL
    # =========================================
    "T1027.004": [
        {"name": "Compile-after-delivery via csc.exe", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "csc.exe"), ("win.eventdata.commandLine", "contains", ".cs")]},
    ],
    "T1027.006": [
        {"name": "HTML smuggling via msSaveBlob", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "msSaveBlob")]},
    ],
    "T1027.009": [
        {"name": "Embedded payload in Office document", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.parentImage", "contains", "WINWORD"), ("win.eventdata.image", "endswith", "powershell.exe")]},
    ],
    "T1027.010": [
        {"name": "Command obfuscation with carets", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "^p^o^w^e^r")]},
    ],
    "T1027.011": [
        {"name": "Fileless storage via registry run key", "logsource": ("windows", "registry_event"),
         "conditions": [("win.eventdata.targetObject", "contains", "CurrentVersion\\Run"), ("win.eventdata.details", "contains", "powershell")]},
    ],
    "T1027.013": [
        {"name": "Encrypted/encoded file execution", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", ".enc"), ("win.eventdata.image", "endswith", "powershell.exe")]},
    ],
    "T1036.003": [
        {"name": "Renamed legitimate utility from Temp", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "contains", "\\Temp\\"), ("win.eventdata.image", "endswith", "svchost.exe")]},
    ],
    "T1036.004": [
        {"name": "Masquerade scheduled task as svchost", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "schtasks.exe"), ("win.eventdata.commandLine", "contains", "svchost")]},
    ],
    "T1036.007": [
        {"name": "Double file extension .pdf.exe", "logsource": ("windows", "file_event"),
         "conditions": [("win.eventdata.targetFilename", "contains", ".pdf.exe")]},
    ],
    "T1036.008": [
        {"name": "Masquerade file type .doc.exe", "logsource": ("windows", "file_event"),
         "conditions": [("win.eventdata.targetFilename", "contains", ".doc.exe")]},
    ],
    "T1070.002": [
        {"name": "Clear Linux/Mac system logs", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "rm /var/log")]},
    ],
    "T1070.003": [
        {"name": "Clear PowerShell command history", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "Clear-History")]},
        {"name": "Delete PowerShell history file", "logsource": ("windows", "file_event"),
         "conditions": [("win.eventdata.targetFilename", "contains", "ConsoleHost_history.txt")]},
    ],
    "T1070.005": [
        {"name": "Network share connection removal", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "net.exe"), ("win.eventdata.commandLine", "contains", "use /delete")]},
    ],
    "T1070.006": [
        {"name": "Timestomp via PowerShell", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "powershell.exe"), ("win.eventdata.commandLine", "contains", "LastWriteTime")]},
    ],
    "T1070.007": [
        {"name": "Clear network connection history via netsh", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "netsh.exe"), ("win.eventdata.commandLine", "contains", "delete")]},
    ],
    "T1070.009": [
        {"name": "Clear persistence via reg delete", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "reg.exe"), ("win.eventdata.commandLine", "contains", "delete")]},
    ],
    "T1127.001": [
        {"name": "MSBuild proxy execution", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "MSBuild.exe"), ("win.eventdata.commandLine", "contains", ".xml")]},
    ],
    "T1197": [
        {"name": "BITS job creation", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "bitsadmin.exe"), ("win.eventdata.commandLine", "contains", "/create")]},
        {"name": "BITS job resume for download", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "bitsadmin.exe"), ("win.eventdata.commandLine", "contains", "/resume")]},
    ],
    "T1202": [
        {"name": "Indirect execution via pcalua", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "pcalua.exe")]},
        {"name": "Indirect execution via forfiles", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "forfiles.exe")]},
    ],
    "T1211": [
        {"name": "Defense evasion via kernel exploit", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "SeDebugPrivilege")]},
    ],
    "T1216.001": [
        {"name": "PubPrn script proxy execution", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "PubPrn.vbs")]},
    ],
    "T1218.001": [
        {"name": "CHM compiled HTML file execution", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "hh.exe")]},
    ],
    "T1218.002": [
        {"name": "Control panel item execution (.cpl)", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", ".cpl")]},
    ],
    "T1218.003": [
        {"name": "CMSTP UAC bypass", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "cmstp.exe")]},
    ],
    "T1218.004": [
        {"name": "InstallUtil proxy execution", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "InstallUtil.exe")]},
    ],
    "T1218.007": [
        {"name": "Msiexec quiet proxy execution", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "msiexec.exe"), ("win.eventdata.commandLine", "contains", "/q")]},
    ],
    "T1218.008": [
        {"name": "Odbcconf proxy execution", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "odbcconf.exe")]},
    ],
    "T1218.009": [
        {"name": "Regasm proxy execution", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "regasm.exe")]},
    ],
    "T1218.012": [
        {"name": "Verclsid proxy execution", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "verclsid.exe")]},
    ],
    "T1218.013": [
        {"name": "Mavinject proxy execution", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "mavinject.exe")]},
    ],
    "T1218.014": [
        {"name": "MMC proxy execution via .msc", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "mmc.exe"), ("win.eventdata.commandLine", "contains", ".msc")]},
    ],
    "T1220": [
        {"name": "XSL script processing via wmic", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "wmic.exe"), ("win.eventdata.commandLine", "contains", ".xsl")]},
        {"name": "XSL script processing via msxsl", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "msxsl.exe")]},
    ],
    "T1480.001": [
        {"name": "Environmental keying check via PowerShell", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "COMPUTERNAME"), ("win.eventdata.image", "endswith", "powershell.exe")]},
    ],
    "T1484.001": [
        {"name": "Group policy modification via gpupdate", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "gpupdate.exe")]},
        {"name": "Group policy modification via PowerShell", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "powershell.exe"), ("win.eventdata.commandLine", "contains", "Set-GPRegistryValue")]},
    ],
    "T1484.002": [
        {"name": "Trust modification via netdom", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "netdom.exe"), ("win.eventdata.commandLine", "contains", "trust")]},
    ],
    "T1548.002": [
        {"name": "UAC bypass via fodhelper", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "fodhelper.exe")]},
        {"name": "UAC bypass via eventvwr", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "eventvwr.exe")]},
        {"name": "UAC bypass via sdclt", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "sdclt.exe")]},
    ],
    "T1550.001": [
        {"name": "Application access token abuse", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "Bearer ")]},
    ],
    "T1550.003": [
        {"name": "Pass the ticket via Rubeus", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "Rubeus")]},
        {"name": "Pass the ticket via mimikatz kerberos::ptt", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "kerberos::ptt")]},
    ],
    "T1550.004": [
        {"name": "Web session cookie reuse", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "Set-Cookie")]},
    ],
    "T1553.002": [
        {"name": "Code signing bypass via self-signed cert", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "New-SelfSignedCertificate")]},
    ],
    "T1553.004": [
        {"name": "Root certificate installed via certutil", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "certutil.exe"), ("win.eventdata.commandLine", "contains", "-addstore")]},
    ],
    "T1553.005": [
        {"name": "Mark-of-the-Web bypass via Unblock-File", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "Unblock-File")]},
    ],
    "T1562.002": [
        {"name": "Disable Windows event logging via wevtutil", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "wevtutil.exe"), ("win.eventdata.commandLine", "contains", "sl")]},
    ],
    "T1562.003": [
        {"name": "Impair command history logging via PSReadline", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "Set-PSReadlineOption"), ("win.eventdata.commandLine", "contains", "SaveNothing")]},
    ],
    "T1562.004": [
        {"name": "Disable Windows firewall via netsh", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "netsh.exe"), ("win.eventdata.commandLine", "contains", "firewall"), ("win.eventdata.commandLine", "contains", "off")]},
    ],
    "T1562.006": [
        {"name": "Indicator blocking via firewall block rule", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "netsh.exe"), ("win.eventdata.commandLine", "contains", "add rule"), ("win.eventdata.commandLine", "contains", "block")]},
    ],
    "T1562.009": [
        {"name": "Safe mode boot modification via bcdedit", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "bcdedit.exe"), ("win.eventdata.commandLine", "contains", "safeboot")]},
    ],
    "T1562.010": [
        {"name": "PowerShell v2 downgrade attack", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "powershell.exe"), ("win.eventdata.commandLine", "contains", "-Version 2")]},
    ],
    "T1564.001": [
        {"name": "Hidden file via attrib +h", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "attrib.exe"), ("win.eventdata.commandLine", "contains", "+h")]},
    ],
    "T1564.003": [
        {"name": "Hidden window via WindowStyle Hidden", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "WindowStyle Hidden")]},
        {"name": "Hidden window via VBScript", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "wscript.exe"), ("win.eventdata.commandLine", "contains", "Hidden")]},
    ],
    "T1564.004": [
        {"name": "NTFS ADS alternate data stream", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "type"), ("win.eventdata.commandLine", "contains", ":zone")]},
    ],

    # =========================================
    # PERSISTENCE — ADDITIONAL
    # =========================================
    "T1078.001": [
        {"name": "Default account usage", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "Administrator"), ("win.eventdata.image", "endswith", "net.exe")]},
    ],
    "T1078.002": [
        {"name": "Domain account abuse via runas", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "runas"), ("win.eventdata.commandLine", "contains", "/domain")]},
    ],
    "T1078.003": [
        {"name": "Local account abuse via runas", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "runas"), ("win.eventdata.commandLine", "contains", "/user")]},
    ],
    "T1098.001": [
        {"name": "Additional cloud credentials added", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "New-AzureADServicePrincipalKeyCredential")]},
    ],
    "T1098.004": [
        {"name": "SSH authorized keys modification", "logsource": ("windows", "file_event"),
         "conditions": [("win.eventdata.targetFilename", "contains", "authorized_keys")]},
    ],
    "T1136.002": [
        {"name": "Domain account creation via net", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "net.exe"), ("win.eventdata.commandLine", "contains", "/add /domain")]},
    ],
    "T1136.003": [
        {"name": "Cloud account creation via CLI", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "New-AzureADUser")]},
    ],
    "T1197": [
        {"name": "BITS job creation for download", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "bitsadmin.exe"), ("win.eventdata.commandLine", "contains", "/create")]},
        {"name": "BITS job resume", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "bitsadmin.exe"), ("win.eventdata.commandLine", "contains", "/resume")]},
    ],
    "T1505.003": [
        {"name": "Web shell dropped to inetpub", "logsource": ("windows", "file_event"),
         "conditions": [("win.eventdata.targetFilename", "contains", "\\inetpub\\"), ("win.eventdata.targetFilename", "endswith", ".aspx")]},
        {"name": "Web shell executed via IIS worker process", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.parentImage", "contains", "w3wp"), ("win.eventdata.image", "endswith", "cmd.exe")]},
    ],
    "T1505.004": [
        {"name": "IIS module installed via appcmd", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "appcmd.exe"), ("win.eventdata.commandLine", "contains", "install")]},
    ],
    "T1543.002": [
        {"name": "Systemd service file creation", "logsource": ("windows", "file_event"),
         "conditions": [("win.eventdata.targetFilename", "contains", "/etc/systemd/system/"), ("win.eventdata.targetFilename", "endswith", ".service")]},
    ],
    "T1546.001": [
        {"name": "Change default file association via registry", "logsource": ("windows", "registry_event"),
         "conditions": [("win.eventdata.targetObject", "contains", "\\shell\\open\\command")]},
    ],
    "T1546.002": [
        {"name": "Screensaver hijack via registry", "logsource": ("windows", "registry_event"),
         "conditions": [("win.eventdata.targetObject", "contains", "Control Panel\\Desktop"), ("win.eventdata.details", "contains", "SCRNSAVE")]},
    ],
    "T1546.003": [
        {"name": "WMI event subscription persistence", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "wmic.exe"), ("win.eventdata.commandLine", "contains", "EventFilter")]},
    ],
    "T1546.007": [
        {"name": "Netsh helper DLL persistence", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "netsh.exe"), ("win.eventdata.commandLine", "contains", "add helper")]},
    ],
    "T1546.008": [
        {"name": "Accessibility feature hijack - sethc replacement", "logsource": ("windows", "file_event"),
         "conditions": [("win.eventdata.targetFilename", "endswith", "sethc.exe")]},
        {"name": "Accessibility feature hijack - utilman replacement", "logsource": ("windows", "file_event"),
         "conditions": [("win.eventdata.targetFilename", "endswith", "utilman.exe")]},
    ],
    "T1546.009": [
        {"name": "AppCert DLL persistence via registry", "logsource": ("windows", "registry_event"),
         "conditions": [("win.eventdata.targetObject", "contains", "AppCertDlls")]},
    ],
    "T1546.010": [
        {"name": "AppInit DLL persistence via registry", "logsource": ("windows", "registry_event"),
         "conditions": [("win.eventdata.targetObject", "contains", "AppInit_DLLs")]},
    ],
    "T1546.011": [
        {"name": "Application shimming via sdbinst", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "sdbinst.exe")]},
    ],
    "T1546.015": [
        {"name": "COM object hijacking via HKCU CLSID", "logsource": ("windows", "registry_event"),
         "conditions": [("win.eventdata.targetObject", "contains", "HKCU\\Software\\Classes\\CLSID")]},
    ],
    "T1547.002": [
        {"name": "Authentication package registered in LSA", "logsource": ("windows", "registry_event"),
         "conditions": [("win.eventdata.targetObject", "contains", "Authentication Packages")]},
    ],
    "T1547.003": [
        {"name": "Time providers DLL persistence", "logsource": ("windows", "registry_event"),
         "conditions": [("win.eventdata.targetObject", "contains", "TimeProviders")]},
    ],
    "T1547.005": [
        {"name": "Security support provider registered", "logsource": ("windows", "registry_event"),
         "conditions": [("win.eventdata.targetObject", "contains", "Security Packages")]},
    ],
    "T1547.009": [
        {"name": "Startup shortcut (.lnk) creation", "logsource": ("windows", "file_event"),
         "conditions": [("win.eventdata.targetFilename", "contains", "\\Startup\\"), ("win.eventdata.targetFilename", "endswith", ".lnk")]},
    ],

    # =========================================
    # PRIVILEGE ESCALATION — ADDITIONAL
    # =========================================
    "T1055.002": [
        {"name": "PE injection via WriteProcessMemory", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "WriteProcessMemory")]},
    ],
    "T1055.003": [
        {"name": "Thread hijacking via SuspendThread", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "SuspendThread")]},
    ],
    "T1055.004": [
        {"name": "APC injection via QueueUserAPC", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "QueueUserAPC")]},
    ],
    "T1055.009": [
        {"name": "Process hollowing via CREATE_SUSPENDED", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "CREATE_SUSPENDED")]},
    ],
    "T1055.013": [
        {"name": "Process doppelganging via TxF", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "TxF")]},
    ],
    "T1134.003": [
        {"name": "Make and impersonate token via LogonUser", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "LogonUser")]},
    ],
    "T1134.004": [
        {"name": "Parent PID spoofing", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS")]},
    ],
    "T1134.005": [
        {"name": "SID-history injection", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "sIDHistory")]},
    ],
    "T1574.004": [
        {"name": "Dylib hijacking", "logsource": ("windows", "file_event"),
         "conditions": [("win.eventdata.targetFilename", "endswith", ".dylib")]},
    ],
    "T1574.006": [
        {"name": "Dynamic linker hijacking via LD_PRELOAD", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "LD_PRELOAD")]},
    ],
    "T1574.009": [
        {"name": "Path interception by unquoted path", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "Program Files"), ("win.eventdata.image", "endswith", "cmd.exe")]},
    ],
    "T1574.011": [
        {"name": "Services registry permissions weakness", "logsource": ("windows", "registry_event"),
         "conditions": [("win.eventdata.targetObject", "contains", "CurrentControlSet\\Services")]},
    ],
    "T1574.012": [
        {"name": "COR_PROFILER hijacking", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "COR_PROFILER")]},
    ],

    # =========================================
    # EXECUTION — ADDITIONAL
    # =========================================
    "T1059.002": [
        {"name": "AppleScript execution via osascript", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "osascript")]},
    ],
    "T1059.004": [
        {"name": "Unix shell via WSL bash.exe", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "bash.exe")]},
        {"name": "Unix shell execution via wsl.exe", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "wsl.exe")]},
    ],
    "T1059.009": [
        {"name": "Cloud API command via aws-cli", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "aws lambda")]},
    ],
    "T1106": [
        {"name": "Native API call via PowerShell", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "DllImport")]},
    ],
    "T1129": [
        {"name": "Shared modules loaded via PowerShell", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "Import-Module")]},
    ],
    "T1204.003": [
        {"name": "Malicious container image execution", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "docker run"), ("win.eventdata.commandLine", "contains", "--privileged")]},
    ],
    "T1559.001": [
        {"name": "COM object execution via PowerShell CreateObject", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "powershell.exe"), ("win.eventdata.commandLine", "contains", "CreateObject")]},
    ],
    "T1559.002": [
        {"name": "DDE execution via Office document", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.parentImage", "contains", "WINWORD"), ("win.eventdata.image", "endswith", "cmd.exe")]},
    ],
    "T1569.002": [
        {"name": "Service execution via sc.exe start", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "sc.exe"), ("win.eventdata.commandLine", "contains", "start")]},
    ],
    "T1610": [
        {"name": "Privileged container deployment", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "docker run"), ("win.eventdata.commandLine", "contains", "--privileged")]},
    ],

    # =========================================
    # LATERAL MOVEMENT — ADDITIONAL
    # =========================================
    "T1021.003": [
        {"name": "DCOM lateral movement via MMC20.Application", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "MMC20.Application")]},
        {"name": "DCOM lateral movement via PowerShell GetTypeFromProgID", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "powershell.exe"), ("win.eventdata.commandLine", "contains", "GetTypeFromProgID")]},
    ],
    "T1021.004": [
        {"name": "SSH lateral movement outbound port 22", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "22")]},
    ],
    "T1021.005": [
        {"name": "VNC outbound connection port 5900", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "5900")]},
    ],
    "T1210": [
        {"name": "Exploitation of remote service SMB", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "445")]},
    ],
    "T1563.001": [
        {"name": "SSH session hijacking via port forward", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "ssh -L")]},
    ],
    "T1563.002": [
        {"name": "RDP session hijacking via tscon", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "tscon.exe")]},
    ],

    # =========================================
    # INITIAL ACCESS — ADDITIONAL
    # =========================================
    "T1189": [
        {"name": "Drive-by compromise - browser spawns cmd", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.parentImage", "contains", "chrome"), ("win.eventdata.image", "endswith", "cmd.exe")]},
        {"name": "Drive-by via IE spawning wscript", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.parentImage", "contains", "iexplore"), ("win.eventdata.image", "endswith", "wscript.exe")]},
    ],
    "T1195.002": [
        {"name": "Software supply chain - msiexec remote install", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "msiexec.exe"), ("win.eventdata.commandLine", "contains", "http")]},
    ],
    "T1199": [
        {"name": "Trusted relationship abuse via mstsc", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "3389"), ("win.eventdata.image", "endswith", "mstsc.exe")]},
    ],
    "T1566.003": [
        {"name": "Spearphishing via Teams spawning PowerShell", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.parentImage", "contains", "Teams"), ("win.eventdata.image", "endswith", "powershell.exe")]},
    ],

    # =========================================
    # DISCOVERY — ADDITIONAL
    # =========================================
    "T1087.003": [
        {"name": "Email account discovery via Get-GlobalAddressList", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "Get-GlobalAddressList")]},
    ],
    "T1087.004": [
        {"name": "Cloud account discovery via Get-AzureADUser", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "Get-AzureADUser")]},
    ],
    "T1518": [
        {"name": "Software discovery via wmic product", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "wmic.exe"), ("win.eventdata.commandLine", "contains", "product")]},
    ],
    "T1518.001": [
        {"name": "Security software discovery via Get-MpComputerStatus", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "powershell.exe"), ("win.eventdata.commandLine", "contains", "Get-MpComputerStatus")]},
        {"name": "AV discovery via tasklist /svc", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "tasklist.exe"), ("win.eventdata.commandLine", "contains", "/svc")]},
    ],
    "T1497.002": [
        {"name": "User activity sandbox evasion via GetLastInputInfo", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "GetLastInputInfo")]},
    ],
    "T1497.003": [
        {"name": "Time-based evasion via Start-Sleep", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "Start-Sleep")]},
        {"name": "Time-based evasion via ping delay", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "ping.exe"), ("win.eventdata.commandLine", "contains", "-n 30")]},
    ],

    # =========================================
    # COLLECTION — ADDITIONAL
    # =========================================
    "T1560.002": [
        {"name": "Archive via ZipFile in PowerShell", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "ZipFile")]},
    ],
    "T1114.001": [
        {"name": "Local email collection via Outlook PST", "logsource": ("windows", "file_event"),
         "conditions": [("win.eventdata.targetFilename", "endswith", ".pst")]},
    ],
    "T1114.002": [
        {"name": "Remote email collection via PowerShell", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "Get-Mailbox")]},
    ],

    # =========================================
    # COMMAND AND CONTROL — ADDITIONAL
    # =========================================
    "T1071.002": [
        {"name": "C2 via FTP protocol", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "21")]},
    ],
    "T1071.003": [
        {"name": "C2 via mail protocol SMTP", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "25")]},
    ],
    "T1071.005": [
        {"name": "C2 via publish/subscribe protocol MQTT", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "1883")]},
    ],
    "T1104": [
        {"name": "Multi-stage C2 channel", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "8080"), ("win.eventdata.image", "endswith", "powershell.exe")]},
    ],
    "T1132.001": [
        {"name": "Standard base64 encoding in C2", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "base64"), ("win.eventdata.image", "endswith", "powershell.exe")]},
    ],
    "T1132.002": [
        {"name": "Non-standard encoding in C2", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "FromBase64String")]},
    ],
    "T1572": [
        {"name": "Protocol tunneling via SSH", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "ssh -R")]},
        {"name": "Protocol tunneling via ngrok", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "ngrok.exe")]},
    ],
    "T1219.002": [
        {"name": "Remote desktop software - AnyDesk", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "AnyDesk.exe")]},
        {"name": "Remote desktop software - TeamViewer", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "TeamViewer.exe")]},
    ],
    "T1102.001": [
        {"name": "Dead drop resolver via web service", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "443"), ("win.eventdata.commandLine", "contains", "pastebin")]},
    ],

    # =========================================
    # EXFILTRATION — ADDITIONAL
    # =========================================
    "T1020": [
        {"name": "Automated exfiltration via PowerShell", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "Invoke-WebRequest"), ("win.eventdata.commandLine", "contains", "-OutFile")]},
    ],
    "T1030": [
        {"name": "Data transfer size limits via split", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "split")]},
    ],
    "T1048.001": [
        {"name": "Exfil over symmetric encrypted non-C2", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "443"), ("win.eventdata.image", "endswith", "cmd.exe")]},
    ],
    "T1048.002": [
        {"name": "Exfil over SSH port 22", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "22"), ("win.eventdata.image", "endswith", "powershell.exe")]},
    ],
    "T1537": [
        {"name": "Transfer data to cloud storage via CLI", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "az storage"), ("win.eventdata.commandLine", "contains", "upload")]},
    ],
    "T1567.001": [
        {"name": "Exfil to code repository via git", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "git.exe"), ("win.eventdata.commandLine", "contains", "push")]},
    ],
    "T1567.003": [
        {"name": "Exfil to text storage site (Pastebin)", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "pastebin")]},
    ],

    # =========================================
    # IMPACT — ADDITIONAL
    # =========================================
    "T1485": [
        {"name": "Data destruction via sdelete", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "sdelete.exe")]},
        {"name": "Data wipe via cipher /w", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "cipher.exe"), ("win.eventdata.commandLine", "contains", "/w")]},
    ],
    "T1491.002": [
        {"name": "External defacement via web shell execution", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.parentImage", "contains", "w3wp"), ("win.eventdata.image", "endswith", "powershell.exe")]},
    ],
    "T1496.001": [
        {"name": "Compute hijacking for cryptomining", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "xmrig")]},
        {"name": "Crypto miner execution", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "stratum+tcp")]},
    ],
    "T1499.001": [
        {"name": "OS exhaustion flood via hping", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "hping3")]},
    ],
    "T1561.001": [
        {"name": "Disk content wipe via format", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "format.com")]},
    ],
    "T1561.002": [
        {"name": "Disk structure wipe via bootrec", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "bootrec.exe"), ("win.eventdata.commandLine", "contains", "/fixmbr")]},
    ],
    "T1565.001": [
        {"name": "Stored data manipulation via PowerShell", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "Set-Content"), ("win.eventdata.image", "endswith", "powershell.exe")]},
    ],
    # =========================================
    # REMOTE ACCESS SOFTWARE (T1219 family)
    # =========================================
    "T1219": [
        {"name": "Remote access software generic - outbound port 443", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "443"), ("win.eventdata.image", "endswith", "powershell.exe")]},
    ],
    "T1219.001": [
        {"name": "Remote access - ScreenConnect (ConnectWise) client", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "contains", "ScreenConnect")]},
        {"name": "Remote access - ScreenConnect service", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "ScreenConnect")]},
        {"name": "Remote access tool outbound port 8041", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "8041")]},
    ],
    "T1219.002": [
        {"name": "Remote desktop software - AnyDesk", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "AnyDesk.exe")]},
        {"name": "Remote desktop software - TeamViewer", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "TeamViewer.exe")]},
        {"name": "AnyDesk outbound port 7070", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "7070")]},
    ],
    "T1219.003": [
        {"name": "Remote access - Cobalt Strike beacon", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "beacon")]},
        {"name": "Remote access - Metasploit meterpreter", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "meterpreter")]},
        {"name": "Reverse shell via PowerShell", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "powershell.exe"), ("win.eventdata.commandLine", "contains", "Invoke-Expression")]},
    ],

    # =========================================
    # ADDITIONAL C2 / REMOTE ACCESS
    # =========================================
    "T1102": [
        {"name": "Web service used for C2", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "443"), ("win.eventdata.image", "endswith", "powershell.exe")]},
    ],
    "T1102.001": [
        {"name": "Dead drop resolver via web service", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "443"), ("win.eventdata.commandLine", "contains", "pastebin")]},
        {"name": "Dead drop via GitHub raw content", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "raw.githubusercontent")]},
    ],
    "T1102.002": [
        {"name": "Bidirectional C2 via web service HTTPS", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "443"), ("win.eventdata.image", "endswith", "powershell.exe")]},
        {"name": "C2 via pastebin POST", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "pastebin"), ("win.eventdata.commandLine", "contains", "POST")]},
    ],
    "T1102.003": [
        {"name": "One-way C2 via web service", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "443"), ("win.eventdata.image", "endswith", "powershell.exe")]},
    ],

    # =========================================
    # ADDITIONAL MISSING TECHNIQUES
    # =========================================
    "T1053": [
        {"name": "Scheduled task base - schtasks any usage", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "schtasks.exe")]},
    ],
    "T1053.003": [
        {"name": "Cron job persistence", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "crontab")]},
    ],
    "T1036.005": [
        {"name": "Match legitimate name and location - svchost wrong path", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "contains", "svchost"), ("win.eventdata.image", "contains", "\\Temp\\")]},
    ],
    "T1036.006": [
        {"name": "Space after filename to evade detection", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "contains", ".exe ")]},
    ],
    "T1176": [
        {"name": "Browser extension installation via command line", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "--load-extension")]},
        {"name": "Browser extension dropped to AppData", "logsource": ("windows", "file_event"),
         "conditions": [("win.eventdata.targetFilename", "contains", "\\Extensions\\"), ("win.eventdata.targetFilename", "endswith", ".crx")]},
    ],
    "T1185": [
        {"name": "Browser session hijacking via debug port", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "--remote-debugging-port")]},
    ],
    "T1542.001": [
        {"name": "System firmware modification via bcdedit", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "bcdedit.exe"), ("win.eventdata.commandLine", "contains", "set")]},
    ],
    "T1542.003": [
        {"name": "Bootkit - MBR modification", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "bootsect.exe")]},
    ],
    "T1556.001": [
        {"name": "Password filter DLL registered", "logsource": ("windows", "registry_event"),
         "conditions": [("win.eventdata.targetObject", "contains", "Notification Packages")]},
    ],
    "T1556.002": [
        {"name": "Network device authentication bypass", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "tacacs")]},
    ],
    "T1601.001": [
        {"name": "Patch system image - wevtutil", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "wevtutil.exe"), ("win.eventdata.commandLine", "contains", "im")]},
    ],
    "T1611": [
        {"name": "Escape to host via Docker privileged", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "docker"), ("win.eventdata.commandLine", "contains", "--privileged")]},
    ],
    "T1614": [
        {"name": "System location discovery via registry", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "reg.exe"), ("win.eventdata.commandLine", "contains", "CurrentControlSet\\Control\\Nls")]},
    ],
    "T1620": [
        {"name": "Reflective code loading via PowerShell", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "powershell.exe"), ("win.eventdata.commandLine", "contains", "Reflection.Assembly")]},
        {"name": "Reflective DLL loading indicator", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "ReflectivePEInjection")]},
    ],
    "T1647": [
        {"name": "Plist modification for persistence", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "defaults write")]},
    ],
    "T1648": [
        {"name": "Serverless execution via cloud function CLI", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "aws lambda invoke")]},
    ],

}