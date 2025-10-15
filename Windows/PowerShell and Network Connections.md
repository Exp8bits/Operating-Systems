# Gathering Network Information

### Get-NetIPAddress
- Displays IP address configuration information for all network interfaces.
- View all IP addresses:
  ```powershell
  Get-NetIPAddress
  ```
- View IP addresses for a specific interface:
  ```powershell
  Get-NetIPAddress -InterfaceAlias "<InterfaceName>"
  Get-NetIPAddress -InterfaceAlias "Ethernet0"
  ```

---

### New-NetIPAddress
- Assigns a new IP address to a network interface.
- Assign a static IP:
  ```powershell
  New-NetIPAddress -InterfaceAlias "<InterfaceName>" -IPAddress "<IP>" -PrefixLength "<PrefixLength>" -DefaultGateway "<Gateway>"
  New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress "192.168.1.100" -PrefixLength "24" -DefaultGateway "192.168.1.1"
  # -PrefixLength "24" = Subnet Mask 255.255.255.0
  ```

---

### Get-NetAdapter
- Displays information about network adapters on the system.
- View all network adapters:
  ```powershell
  Get-NetAdapter
  ```

---

### Disable-NetAdapter
- Disables a network adapter.
- Disable a specific adapter:
  ```powershell
  Disable-NetAdapter -Name "<AdapterName>" -Confirm:$false
  Disable-NetAdapter -Name "Wi-Fi" -Confirm:$false
  ```

---

### Enable-NetAdapter
- Enables a previously disabled network adapter.
- Enable a specific adapter:
  ```powershell
  Enable-NetAdapter -Name "<AdapterName>"
  Enable-NetAdapter -Name "Wi-Fi"
  ```

---

### Get-NetRoute
- Displays the IP routing table.
- View all routes:
  ```powershell
  route print
  Get-NetRoute
  Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
  ```

---

### New-NetRoute
- Adds a new route to the IP routing table.
- Add a route:
  ```powershell
  New-NetRoute -DestinationPrefix "<Destination/Prefix>" -InterfaceAlias "<InterfaceName>" -NextHop "<NextHopIP>"
  New-NetRoute -DestinationPrefix "10.0.0.0/24" -InterfaceAlias "Ethernet0" -NextHop "192.168.1.1"
  # -DestinationPrefix: Network you want to route traffic to.
  # -InterfaceAlias: Network adapter name.
  # -NextHop: IP of the router/next hop.
  ```

---

### Get-DnsClientServerAddress
- Displays the DNS server addresses configured on network interfaces.
- View DNS servers:
  ```powershell
  Get-DnsClientServerAddress
  ```

---

### Set-DnsClientServerAddress
- Sets the DNS server addresses for a network interface.
- Set DNS servers:
  ```powershell
  Set-DnsClientServerAddress -InterfaceAlias "<InterfaceName>" -ServerAddresses "<DNS1>","<DNS2>"
  Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses "1.1.1.1","8.8.8.8"
  ```

---

### ipconfig
- Displays all current TCP/IP network configuration values.
- View basic IP configuration:
  ```powershell
  ipconfig
  ```
- View detailed IP configuration (with DNS, DHCP, etc.):
  ```powershell
  ipconfig /all
  Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
  Get-DnsClientServerAddress -AddressFamily IPv4 | ft
  ```

---

### netstat
- Displays active network connections, listening ports, and routing tables.
- View all active connections:
  ```powershell
  netstat -ano
  ```
- View only listening ports:
  ```powershell
  netstat -an | find "LISTEN"
  ```

---

### nslookup
- Queries DNS servers for information about hostnames and IP addresses.
- Resolve a domain to IP:
  ```powershell
  nslookup <domain>
  nslookup "example.com"
  ```
- Find the mail servers of a domain:
  ```powershell
  nslookup -type=MX <domain>
  nslookup -type=MX "example.com"
  ```

---

### arp
- Displays and modifies the ARP (Address Resolution Protocol) cache.
- View ARP table:
  ```powershell
  arp -a
  Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,LinkLayerAddress,State
  ```

---

### Check the hosts file
- You might find more than one subnet mask connected to each other, which is useful for lateral movement.
  ```powershell
  C:\WINDOWS\System32\drivers\etc\hosts
  ```

---

### Check if firewall is turned on or not, if on, what's configured?
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

### Check SNMP configurations
```powershell
reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP /s
Get-ChildItem -path HKLM:\SYSTEM\CurrentControlSet\Services\SNMP -Recurse
```

---

## Testing Connections

### Test-NetConnection
- Tests connectivity to a remote host or service (like ping + port check).
- Test connectivity to a host:
  ```powershell
  Test-NetConnection -ComputerName "<Hostname or IP>"
  Test-NetConnection -ComputerName "google.com" or "8.8.8.8"
  ```
- Test a specific port:
  ```powershell
  Test-NetConnection -ComputerName "<Hostname or IP>" -Port <PortNumber>
  Test-NetConnection -ComputerName "google.com" or "8.8.8.8" -Port 443
  ```

---

### Test-Connection
- Sends ICMP echo request packets (similar to `ping`).
- Test connectivity to a host:
  ```powershell
  Test-Connection -ComputerName "<Hostname or IP>" -Count <Number>
  Test-Connection -ComputerName "google.com" or "8.8.8.8" -Count 5
  ```

---

## Downloading Files

### Invoke-WebRequest
- Downloads files from a URL to your local system.
- Usage:
  ```powershell
  Invoke-WebRequest -Uri "<URL>" -OutFile "<FileName>"
  Invoke-WebRequest -Uri "http://example.com/file.txt" -OutFile "C:\Users\User\file.txt"
  ```

---

## Installation

### Install-Module
```powershell
Install-Module -Name SysInternals
# Installing SysInternals module.
```
