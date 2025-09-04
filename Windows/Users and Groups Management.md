# Users and Groups Management

## Display users on the system
- **CMD**:
  ```cmd
  net user
  ```  
*Displays all users on the system.*  
- **PowerShell**:
  ```powershell
  Get-LocalUser
  ```  
*Lists all local user accounts.*

---

## Add, Delete, Modify user accounts
### Add a new user
- **CMD**:  
  ```cmd
  net user <username> <password> /add
  ```
- **PowerShell**:
  ```powershell
  New-LocalUser -Name "<username>" -Password (Read-Host -AsSecureString) -FullName "<Full Name>" -Description "<Description>"
  ```
*Creates a new local user with a specified password.*

### Add User to Administrators Group
- **CMD**:
  ```cmd
  net localgroup Administrators <username> /add
  ```
- **PowerShell**:
  ```powershell
  Add-LocalGroupMember -Group "Administrators" -Member "<username>"
  ```

---

### Delete a user
- **CMD**:
  ```cmd
  net user <username> /delete
  ```
- **PowerShell**:
  ```powershell
  Remove-LocalUser -Name "<username>"
  ```

---

### Rename a user
- **PowerShell**:
  ```powershell
  Rename-LocalUser -Name "<oldUser>" -NewName "<newUser>"
  ```

---

### Modifies properties of an existing local user account.
- **PowerShell**:
  ```powershell
  Set-LocalUser -Name "<username>" -Description "This is a test user."
  ```

---

## Enable/Disable a user account
- **CMD (Disable)**:
  ```cmd
  net user <username> /active:no
  ```
- **CMD (Enable)**:
  ```cmd
  net user <username> /active:yes
  ```
- **PowerShell (Disable)**:
  ```powershell
  Disable-LocalUser -Name "<username>"
  ```
- **PowerShell (Enable)**:
  ```powershell
  Enable-LocalUser -Name "<username>"
  ```

---

## Change user password
- **CMD**:
  ```cmd
  net user <username> *
  ```
*Prompts to change the password for the specified user.*
- **PowerShell**:
  ```powershell
  # Enter the password:
  $Password = Read-Host -AsSecureString
  # Apply the new password to the user:
  Set-LocalUser -Name "<username>" -Password $Password
  ```

---

## Switch user
Shortcut: `Ctrl + Alt + Del` > Switch user
- **CMD**:
  ```cmd
  tsdiscon
  ```
*Disconnects the current session so you can log in as another user.*

---

## View group information
### Display All Groups:
- **CMD**:
  ```cmd
  net localgroup
  ```
- **PowerShell**:
  ```powershell
  Get-LocalGroup
  ```
### Display Group Members:
- **CMD**:
  ```cmd
  net localgroup <groupname>
  ```
- **PowerShell**:
  ```powershell
  Get-LocalGroupMember -Group "<groupname>"
  ```

---

## Group Management
### Create a new group
- **CMD**:
  ```cmd
  net localgroup <groupname> /add
  ```
- **PowerShell**:
  ```powershell
  New-LocalGroup -Name "<groupname>" -Description "<Description>"
  ```
### Modifies properties of an existing local group.
- **PowerShell**:
  ```powershell
  Set-LocalGroup -Name "<groupname>" -Description "Improvise. Adapt. Overcome."
  ```
### Delete a group
- **CMD**:
  ```cmd
  net localgroup <groupname> /delete
  ```
- **PowerShell**:
  ```powershell
  Remove-LocalGroup -Name "<groupname>"
  ```
### Add a user to a group
- **CMD**:
  ```cmd
  net localgroup <groupname> <username> /add
  ```
- **PowerShell**:
  ```powershell
  Add-LocalGroupMember -Group "<groupname>" -Member "<username>"
  ```
### Remove a user from a group
- **CMD**:
  ```cmd
  net localgroup <groupname> <username> /delete
  ```
- **PowerShell**:
  ```powershell
  Remove-LocalGroupMember -Group "<groupname>" -Member "<username>"
  ```

---

## Useful files and locations
### SAM File
- Path: `C:\Windows\System32\config\SAM`
  - *Stores hashed user passwords. Accessible only with SYSTEM privileges.*
### Security Accounts Manager
- **GUI Tools:**
  - `secpol.msc` Local Security Policy
  - `lusrmgr.msc` Local Users and Groups
    - *Local User and Group management GUI.*
### Registry Keys
- `HKEY_LOCAL_MACHINE\SAM\SAM`
  - *Stores user authentication details.*
