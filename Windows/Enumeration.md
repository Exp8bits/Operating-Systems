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

### To obtain all the tasks currently running
  ```powershell
  tasklist /svc
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
  accesschk.exe -qwsvu "Everyone" *
  accesschk.exe -qwsvu "Authenticated Users" *
  accesschk.exe -qwsvu "Users" *
  accesschk.exe /accepteula \pipe                 // enumerate permissions for users 
  accesschk.exe -w \pipe\* -v                     // focus on write permissions for everyone services
  ```

---

