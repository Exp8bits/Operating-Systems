# Windows Enumeration

### Who is the user that is logged in, and what are their privileges?
  ```powershell
  echo %USERNAME%          // CMD
  $env:UserName
  whoami
  whoami /priv
  ```

### What groups is this user in?
  ```powershell
  whoami /groups
  ```

### All the details of this user?
  ```powershell
  whoami /all
  ```

### To find out the users registered on this machine
  ```cmd
  query user              // CMD
  ```

### To find out more information about the machine we're working on
  ```powershell
  GET-MPComputerStatus
  ```

### To obtain all the tasks/services currently running
  ```powershell
  tasklist /svc
  tasklist /v
  net start
  sc query
  Get-Service | Where-Object { $_.Status -eq "Running" }
  ```

### To obtain process name, id
```powershell
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
# This one liner returns the process owner without admin rights, if something is blank under owner it’s probably running as SYSTEM, NETWORK SERVICE, or LOCAL SERVICE.
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize
```

### To obtain all information about the system
  ```powershell
  systeminfo
  ```

### To get all users in server
  ```powershell
  net user
  dir /b /ad "C:\Users\"                      // CMD
  dir /b /ad "C:\Documentsand Settings\"      // CMD, Windows XP ans below
  ```

### To get all local groups (the ones on the machine itself, not on the domain)
  ```powershell
  net localgroup
  ```

### To find out who is connected to the machine
  ```powershell
  GET-LocalUser | ft Name,Enable,Lastlogon
  ```

### To get password policy
  ```powershell
  net accounts
  ```

### Display the network connections and the listening ports on the machine
  ```powershell
  netstat -ano                // CMD
  ```

### To get more information about the tasklist for a specific PID
  ```powershell
  tasklist /FI "PID eq <PID>"
  ```

---

## Try to access SAM and SYSTEM files
```powershell
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\System32\config\system
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\RegBack\system
```

---

## What software is installed?
```powershell
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
```

---

## Are there any weak folder or file permissions?
```powershell
# Full permissions for everyone or users on program folders?
icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "Everyone"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "Everyone"
icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users"

# Modify Permissions for Everyone or Users on Program Folders?
icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "Everyone"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "Everyone"
icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users"
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}} 
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}} 
```

---

## Check the permission using `accesschk.exe`
- Install `accesschk.exe` if now installed [accesschk.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk)
- Check for writeable folders and files.
  ```poweshell
  # -q = omit banner, -w = show only objects that have write access, -s = recursive, -v = verbose, -u = suppress errors.
  # Search for files that anyone can modify.
  accesschk.exe -qwsvu "Everyone" *
  accesschk.exe -qwsvu "Everyone" "C:\Program Files\*"
  # Search for files that Authenticated Users can modify.
  accesschk.exe -qwsvu "Authenticated Users" *
  # Search for files that Users can modify.
  accesschk.exe -qwsvu "Users" *
  # Enumerate permissions for users 
  accesschk.exe /accepteula \pipe
  accesschk.exe -w \pipe\* -v                             // focus on write permissions for everyone services
  ```

---

## Find any unquoted service paths
```powershell
# CMD
wmic service get name,displayname,pathname,startmode 2>nul |findstr /i "Auto" 2>nul |findstr /i /v "C:\Windows\\" 2>nul |findstr /i /v """
# Powershell
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```

---

## Find scheduled tasks
```powershell
# CMD
schtasks /query /fo LIST 2>nul | findstr <TaskName>
dir C:\windows\tasks
# Powershell
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
```

---

## Check the startup for persistence
```powershell
# CMD
wmic startup get caption,command
dir "C:\Documents and Settings\All Users\Start Menu\Programs\Startup"
dir "C:\Documents and Settings\%username%\Start Menu\Programs\Startup"
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
# Powershell
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
# As soon as you place your malware file in one of these paths, your malware will run automatically when the machine restarts — zero-click.
```

---

## Search if there's anything in the current user's auto-logon
- Default username/password for the domain they're in
  ```powershell
  reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"
  Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' | select "Default*"
  ```

---

## Check if AlwaysInstallElevated enabled for priv esc
  ```powershell
  reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
  ```

---

## Check the hosts file
- You might find more than one subnet mask connected to each other, which is useful for lateral movement.
  ```powershell
  C:\WINDOWS\System32\drivers\etc\hosts
  ```

---

## Check if firewall is turned on or not, if on, what's configured?
```powershell
netsh firewall show state
netsh firewall show config
netsh advfirewall firewall show rule name=all
netsh advfirewall export "firewall.txt"
```
- To display firewall configuration
  ```powershell
  netsh dump
  ```

---

## Check SNMP configurations
```powershell
reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP /s
Get-ChildItem -path HKLM:\SYSTEM\CurrentControlSet\Services\SNMP -Recurse
```

---

## If the server is an IIS webserver, what's in inetpub? Any hidden directories? web.config files?
```powershell
# CMD
dir /a C:\inetpub\
dir /s web.config
C:\Windows\System32\inetsrv\config\applicationHost.config
# Powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

---

## Is XAMPP, Apache, or PHP installed? Any there any XAMPP, Apache, or PHP configuration files?
```powershell
# CMD
dir /s php.ini httpd.conf httpd-xampp.conf my.ini my.cnf
# Powershell
Get-Childitem –Path C:\ -Include php.ini,httpd.conf,httpd-xampp.conf,my.ini,my.cnf -File -Recurse -ErrorAction SilentlyContinue
```

---

## Check IIS Logs
```powershell
C:\inetpub\logs\LogFiles\W3SVC1\u_ex[YYMMDD].log
C:\inetpub\logs\LogFiles\W3SVC2\u_ex[YYMMDD].log
C:\inetpub\logs\LogFiles\FTPSVC1\u_ex[YYMMDD].log
C:\inetpub\logs\LogFiles\FTPSVC2\u_ex[YYMMDD].log
```

---

## Check Apache Logs
```powershell
# CMD
dir /s access.log error.log
# Powershell
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```

---

## Local File Inclusion List
- C:\Apache\conf\httpd.conf
- C:\Apache\logs\access.log
- C:\Apache\logs\error.log
- C:\Apache2\conf\httpd.conf
- C:\Apache2\logs\access.log
- C:\Apache2\logs\error.log
- C:\Apache22\conf\httpd.conf
- C:\Apache22\logs\access.log
- C:\Apache22\logs\error.log
- C:\Apache24\conf\httpd.conf
- C:\Apache24\logs\access.log
- C:\Apache24\logs\error.log
- C:\Documents and Settings\Administrator\NTUser.dat
- C:\php\php.ini
- C:\php4\php.ini
- C:\php5\php.ini
- C:\php7\php.ini
- C:\Program Files (x86)\Apache Group\Apache\conf\httpd.conf
- C:\Program Files (x86)\Apache Group\Apache\logs\access.log
- C:\Program Files (x86)\Apache Group\Apache\logs\error.log
- C:\Program Files (x86)\Apache Group\Apache2\conf\httpd.conf
- C:\Program Files (x86)\Apache Group\Apache2\logs\access.log
- C:\Program Files (x86)\Apache Group\Apache2\logs\error.log
- C:\Program Files (x86)\php\php.ini"
- C:\Program Files\Apache Group\Apache\conf\httpd.conf
- C:\Program Files\Apache Group\Apache\conf\logs\access.log
- C:\Program Files\Apache Group\Apache\conf\logs\error.log
- C:\Program Files\Apache Group\Apache2\conf\httpd.conf
- C:\Program Files\Apache Group\Apache2\conf\logs\access.log
- C:\Program Files\Apache Group\Apache2\conf\logs\error.log
- C:\Program Files\FileZilla Server\FileZilla Server.xml
- C:\Program Files\MySQL\my.cnf
- C:\Program Files\MySQL\my.ini
- C:\Program Files\MySQL\MySQL Server 5.0\my.cnf
- C:\Program Files\MySQL\MySQL Server 5.0\my.ini
- C:\Program Files\MySQL\MySQL Server 5.1\my.cnf
- C:\Program Files\MySQL\MySQL Server 5.1\my.ini
- C:\Program Files\MySQL\MySQL Server 5.5\my.cnf
- C:\Program Files\MySQL\MySQL Server 5.5\my.ini
- C:\Program Files\MySQL\MySQL Server 5.6\my.cnf
- C:\Program Files\MySQL\MySQL Server 5.6\my.ini
- C:\Program Files\MySQL\MySQL Server 5.7\my.cnf
- C:\Program Files\MySQL\MySQL Server 5.7\my.ini
- C:\Program Files\php\php.ini
- C:\Users\Administrator\NTUser.dat
- C:\Windows\debug\NetSetup.LOG
- C:\Windows\Panther\Unattend\Unattended.xml
- C:\Windows\Panther\Unattended.xml
- C:\Windows\php.ini
- C:\Windows\repair\SAM
- C:\Windows\repair\system
- C:\Windows\System32\config\AppEvent.evt
- C:\Windows\System32\config\RegBack\SAM
- C:\Windows\System32\config\RegBack\system
- C:\Windows\System32\config\SAM
- C:\Windows\System32\config\SecEvent.evt
- C:\Windows\System32\config\SysEvent.evt
- C:\Windows\System32\config\SYSTEM
- C:\Windows\System32\drivers\etc\hosts
- C:\Windows\System32\winevt\Logs\Application.evtx
- C:\Windows\System32\winevt\Logs\Security.evtx
- C:\Windows\System32\winevt\Logs\System.evtx
- C:\Windows\win.ini 
- C:\xampp\apache\conf\extra\httpd-xampp.conf
- C:\xampp\apache\conf\httpd.conf
- C:\xampp\apache\logs\access.log
- C:\xampp\apache\logs\error.log
- C:\xampp\FileZillaFTP\FileZilla Server.xml
- C:\xampp\MercuryMail\MERCURY.INI
- C:\xampp\mysql\bin\my.ini
- C:\xampp\php\php.ini
- C:\xampp\security\webdav.htpasswd
- C:\xampp\sendmail\sendmail.ini
- C:\xampp\tomcat\conf\server.xml
