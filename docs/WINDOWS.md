# Windows Installation Guide for NSD

## Prerequisites

NSD requires Npcap for packet capture on Windows. Npcap is the Windows version of the libpcap library and is actively maintained.

### Installing Npcap

1. Download Npcap from the official website: https://npcap.com/#download
2. Run the installer with Administrator privileges
3. During installation, we recommend checking these options:
   - ✅ Install Npcap in WinPcap API-compatible Mode (for compatibility)
   - ✅ Install Npcap service (required for packet capture)
   - ✅ Support raw 802.11 traffic (optional, for WiFi monitoring)

### Alternative: WinPcap (Legacy)

If you have legacy requirements, you can use WinPcap instead:
- Download from: https://www.winpcap.org/install/
- Note: WinPcap is deprecated and no longer maintained

## Installing NSD

### Option 1: Download Pre-built Binary

1. Download the latest Windows release from [GitHub Releases](https://github.com/perplext/nsd/releases)
2. Extract `nsd-windows-amd64.exe` to a directory in your PATH (e.g., `C:\Program Files\nsd\`)
3. Open Command Prompt or PowerShell as Administrator
4. Run: `nsd.exe`

### Option 2: Build from Source

Prerequisites:
- Go 1.24 or later
- Git
- Npcap installed (see above)
- A C compiler (MinGW-w64 or Visual Studio)

```powershell
# Clone the repository
git clone https://github.com/perplext/nsd.git
cd nsd

# Build the binary
go build -o nsd.exe ./cmd/nsd

# Run with administrator privileges
./nsd.exe
```

## Running NSD

NSD requires Administrator privileges to capture network packets on Windows.

### Command Prompt (Admin)
```cmd
nsd.exe
```

### PowerShell (Admin)
```powershell
.\nsd.exe
```

### With specific interface
```powershell
# List available interfaces
.\nsd.exe --list-interfaces

# Use specific interface
.\nsd.exe -i "Ethernet"
```

## Common Issues

### "Unable to load WinPcap/Npcap library"
- **Solution**: Ensure Npcap is installed correctly. Try reinstalling with "WinPcap API-compatible Mode" enabled.

### "Access denied" or "Insufficient privileges"
- **Solution**: Run NSD as Administrator. Right-click on cmd.exe or PowerShell and select "Run as Administrator".

### "No interfaces found"
- **Solution**: 
  1. Check if Npcap service is running: `sc query npcap`
  2. If not running: `sc start npcap`
  3. Restart NSD

### Interface names look like "\Device\NPF_{GUID}"
- This is normal on Windows. Use `--list-interfaces` to see available interfaces with their descriptions.

## Windows-Specific Features

### Performance Considerations
- Windows packet capture may have higher CPU usage compared to Linux due to kernel architecture differences
- For best performance, close unnecessary applications and consider using BPF filters

### Firewall Configuration
- Windows Defender Firewall typically doesn't block packet capture
- Third-party firewalls may need configuration to allow NSD

## Building Windows Installer

To create an MSI installer (requires WiX Toolset):

```powershell
# Install WiX Toolset
choco install wixtoolset

# Build the installer
cd build/windows
./build-installer.ps1
```

## System Requirements

- Windows 10/11 or Windows Server 2016/2019/2022
- 64-bit architecture (x64)
- Administrator privileges
- Npcap or WinPcap installed
- Minimum 4GB RAM recommended