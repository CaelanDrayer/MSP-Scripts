# MSP Scripts

PowerShell and automation scripts for Managed Service Provider operations.

## Structure

```
Windows/
  Security/       Windows Defender, antivirus, firewall
  Networking/     DNS, DHCP, NIC configuration
  Active-Directory/ AD users, groups, GPO
macOS/
Linux/
```

## Windows/Security

| Script | Purpose |
|--------|---------|
| Enable-WindowsDefender.ps1 | Clears GP overrides, starts WinDefend service, enables all core protections, updates signatures |
| Validate-WindowsDefender.ps1 | Checks all protection flags, signature freshness, GP overrides, outputs color-coded status table |

## Usage

Scripts are designed for deployment via NinjaOne RMM (runs as SYSTEM). They can also be run manually from an elevated PowerShell prompt.

```powershell
# Enable Defender
powershell.exe -ExecutionPolicy Bypass -File Enable-WindowsDefender.ps1

# Validate Defender status
powershell.exe -ExecutionPolicy Bypass -File Validate-WindowsDefender.ps1
```

## Compatibility

- PowerShell 5.1+ (Windows PowerShell)
- PowerShell 7+ (PowerShell Core)
- Windows Server 2016+, Windows 10+

## License

Internal use - Dyrand Systems.
