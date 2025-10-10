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

