# Active Directory Users Management

## Get-ADUser
- Queries and retrieves information about one or more user accounts from Active Directory.
- Search by a specific username:
  ```powershell
  Get-ADUser "<username>"
  ```
- List all users:
  ```powershell
  Get-ADUser -Filter *
  ```
- List active users in AD
  ```powershell
  Get-ADUser -Filter * -Properties Enabled | Where-Object { $_.Enabled -eq $true } 
  # Get-ADUser -Filter * → fetches all AD users.
  # -Properties Enabled → ensures the Enabled attribute is retrieved.
  # Where-Object { $_.Enabled -eq $true } → filters only active accounts.
  # Measure-Object → counts them.
  ```
- Count all active users in AD
  ```powershell
  Get-ADUser -Filter * -Properties Enabled | Where-Object { $_.Enabled -eq $true } | Measure-Object
  ```

---

## New-ADUser
- Creates a new user account in Active Directory.
  ```powershell
  New-ADUser -Name "<FullName>" -SamAccountName "<username>" -UserPrincipalName "<username>@<domain>" -AccountPassword (Read-Host -AsSecureString "Enter Password") -Enabled $true
  New-ADUser -Name "John Doe" -SamAccountName "j.doe" -UserPrincipalName "j.doe@example.com" -AccountPassword (Read-Host -AsSecureString "Enter Password") -Enabled $true
  ```

---

## Set-LocalUser
- Modifies the properties of a local user account on a computer.
- Change a user's description:
  ```powershell
  Set-LocalUser -Name "<username>" -Description "<description>"
  Set-LocalUser -Name "j.doe" -Description "This is a test user."
  ```

---

## Disable-LocalUser
- Disables a local user account to prevent sign-in.
- Disable a user:
  ```powershell
  Disable-LocalUser -Name "<username>"
  Disable-LocalUser -Name "j.doe"
  ```

---

## Enable-LocalUser
- Enables a previously disabled local user account.
- Enable a user:
  ```powershell
  Enable-LocalUser -Name "<username>"
  Enable-LocalUser -Name "j.doe"
  ```

---

## Remove-LocalUser
- Deletes a local user account from the computer.
- Remove a user:
  ```powershell
  Remove-LocalUser -Name "<username>"
  Remove-LocalUser -Name "j.doe"
  ```

---

## Get-LocalGroup
- Displays information about local groups on a computer.
- List all local groups:
  ```powershell
  Get-LocalGroup
  ```

---

## New-LocalGroup
- Creates a new local group on a computer.
- Create a new group:
  ```powershell
  New-LocalGroup -Name "<groupname>" -Description "<description>"
  New-LocalGroup -Name "TestGroup" -Description "This is a new local group."
  ```

---

## Set-LocalGroup
- Modifies the properties of an existing local group.
- Change a group's description:
  ```powershell
  Set-LocalGroup -Name "<groupname>" -Description "<description>"
  Set-LocalGroup -Name "TestGroup" -Description "Updated description"
  ```

---

## Add-LocalGroupMember
- Adds one or more users or groups to a local group.
- Add a user to a group:
  ```powershell
  Add-LocalGroupMember -Group "<groupname>" -Member "<username>"
  Add-LocalGroupMember -Group "TestGroup" -Member "j.doe"
  ```

---

## Remove-LocalGroupMember
- Removes one or more users or groups from a local group.
- Remove a user from a group:
  ```powershell
  Remove-LocalGroupMember -Group "<groupname>" -Member "<username>"
  Remove-LocalGroupMember -Group "TestGroup" -Member "j.doe"
  ```

---

## Remove-LocalGroup
- Deletes a local group from the computer.
- Remove a group:
  ```powershell
  Remove-LocalGroup -Name "<groupname>"
  Remove-LocalGroup -Name "TestGroup"
  ```

---

