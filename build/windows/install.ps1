# NSD Windows Installer Script
# This script installs NSD on Windows systems

param(
    [string]$InstallPath = "$env:ProgramFiles\NSD",
    [switch]$AddToPath = $true,
    [switch]$CreateShortcut = $true
)

$ErrorActionPreference = "Stop"

Write-Host "NSD (Network Sniffing Dashboard) Windows Installer" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: This installer must be run as Administrator." -ForegroundColor Red
    Write-Host "Please right-click and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

# Check if Npcap is installed
Write-Host "Checking for Npcap installation..." -ForegroundColor Yellow
$npcapInstalled = $false

# Check for Npcap service
try {
    $npcapService = Get-Service -Name "npcap" -ErrorAction SilentlyContinue
    if ($npcapService) {
        $npcapInstalled = $true
        Write-Host "✓ Npcap is installed" -ForegroundColor Green
    }
} catch {}

# Check for legacy NPF service (WinPcap)
if (-not $npcapInstalled) {
    try {
        $npfService = Get-Service -Name "npf" -ErrorAction SilentlyContinue
        if ($npfService) {
            $npcapInstalled = $true
            Write-Host "✓ WinPcap is installed (legacy)" -ForegroundColor Yellow
            Write-Host "  Note: Consider upgrading to Npcap for better performance" -ForegroundColor Yellow
        }
    } catch {}
}

if (-not $npcapInstalled) {
    Write-Host "✗ Npcap is NOT installed" -ForegroundColor Red
    Write-Host ""
    Write-Host "Npcap is required for NSD to capture network packets." -ForegroundColor Yellow
    Write-Host "Please download and install Npcap from: https://npcap.com/#download" -ForegroundColor Yellow
    Write-Host ""
    
    $response = Read-Host "Do you want to open the Npcap download page? (Y/N)"
    if ($response -eq 'Y' -or $response -eq 'y') {
        Start-Process "https://npcap.com/#download"
        Write-Host ""
        Write-Host "Please install Npcap and then run this installer again." -ForegroundColor Yellow
        exit 1
    } else {
        Write-Host ""
        Write-Host "Installation cancelled. Please install Npcap before running NSD." -ForegroundColor Red
        exit 1
    }
}

# Find NSD executable
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$nsdExe = $null

# Look for nsd.exe in common locations
$searchPaths = @(
    (Join-Path $scriptDir "nsd.exe"),
    (Join-Path $scriptDir "..\..\nsd.exe"),
    (Join-Path $scriptDir "..\..\bin\nsd.exe"),
    ".\nsd.exe"
)

foreach ($path in $searchPaths) {
    if (Test-Path $path) {
        $nsdExe = Resolve-Path $path
        break
    }
}

if (-not $nsdExe) {
    Write-Host "ERROR: Cannot find nsd.exe" -ForegroundColor Red
    Write-Host "Please ensure nsd.exe is in the same directory as this installer." -ForegroundColor Yellow
    exit 1
}

Write-Host "Found NSD executable at: $nsdExe" -ForegroundColor Green

# Create installation directory
Write-Host ""
Write-Host "Installing NSD to: $InstallPath" -ForegroundColor Yellow

if (Test-Path $InstallPath) {
    $response = Read-Host "Installation directory already exists. Overwrite? (Y/N)"
    if ($response -ne 'Y' -and $response -ne 'y') {
        Write-Host "Installation cancelled." -ForegroundColor Red
        exit 1
    }
}

try {
    New-Item -ItemType Directory -Force -Path $InstallPath | Out-Null
    
    # Copy files
    Write-Host "Copying files..." -ForegroundColor Yellow
    Copy-Item $nsdExe -Destination (Join-Path $InstallPath "nsd.exe") -Force
    
    # Copy additional files if they exist
    $additionalFiles = @("README.md", "LICENSE", "WINDOWS.md")
    foreach ($file in $additionalFiles) {
        $sourcePath = Join-Path (Split-Path -Parent $nsdExe) $file
        if (Test-Path $sourcePath) {
            Copy-Item $sourcePath -Destination $InstallPath -Force
        }
    }
    
    # Copy examples directory if it exists
    $examplesPath = Join-Path (Split-Path -Parent $nsdExe) "examples"
    if (Test-Path $examplesPath) {
        Copy-Item $examplesPath -Destination $InstallPath -Recurse -Force
    }
    
    Write-Host "✓ Files copied successfully" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to copy files: $_" -ForegroundColor Red
    exit 1
}

# Add to PATH
if ($AddToPath) {
    Write-Host ""
    Write-Host "Adding NSD to system PATH..." -ForegroundColor Yellow
    
    try {
        $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
        if ($currentPath -notlike "*$InstallPath*") {
            [Environment]::SetEnvironmentVariable("Path", "$currentPath;$InstallPath", "Machine")
            Write-Host "✓ Added to PATH successfully" -ForegroundColor Green
            Write-Host "  Note: You may need to restart your terminal for PATH changes to take effect" -ForegroundColor Yellow
        } else {
            Write-Host "✓ Already in PATH" -ForegroundColor Green
        }
    } catch {
        Write-Host "WARNING: Failed to add to PATH: $_" -ForegroundColor Yellow
        Write-Host "You can manually add '$InstallPath' to your PATH environment variable" -ForegroundColor Yellow
    }
}

# Create desktop shortcut
if ($CreateShortcut) {
    Write-Host ""
    Write-Host "Creating desktop shortcut..." -ForegroundColor Yellow
    
    try {
        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\NSD.lnk")
        $Shortcut.TargetPath = "powershell.exe"
        $Shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"Start-Process '$InstallPath\nsd.exe' -Verb RunAs`""
        $Shortcut.WorkingDirectory = $InstallPath
        $Shortcut.IconLocation = "$InstallPath\nsd.exe"
        $Shortcut.Description = "Network Sniffing Dashboard (Run as Administrator)"
        $Shortcut.Save()
        
        Write-Host "✓ Desktop shortcut created" -ForegroundColor Green
    } catch {
        Write-Host "WARNING: Failed to create shortcut: $_" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "NSD installation completed successfully!" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "To run NSD:" -ForegroundColor Cyan
Write-Host "  1. Open Command Prompt or PowerShell as Administrator" -ForegroundColor White
Write-Host "  2. Type: nsd" -ForegroundColor White
Write-Host ""
Write-Host "To list network interfaces:" -ForegroundColor Cyan
Write-Host "  nsd --list-interfaces" -ForegroundColor White
Write-Host ""
Write-Host "To capture on a specific interface:" -ForegroundColor Cyan
Write-Host "  nsd -i `"Ethernet`"" -ForegroundColor White
Write-Host ""
Write-Host "For more information, see the documentation in $InstallPath" -ForegroundColor Yellow