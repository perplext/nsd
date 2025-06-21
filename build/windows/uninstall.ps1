# NSD Windows Uninstaller Script
# This script removes NSD from Windows systems

param(
    [string]$InstallPath = "$env:ProgramFiles\NSD"
)

$ErrorActionPreference = "Stop"

Write-Host "NSD (Network Sniffing Dashboard) Windows Uninstaller" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: This uninstaller must be run as Administrator." -ForegroundColor Red
    Write-Host "Please right-click and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

# Check if NSD is installed
if (-not (Test-Path $InstallPath)) {
    Write-Host "NSD is not installed at: $InstallPath" -ForegroundColor Yellow
    exit 0
}

Write-Host "This will uninstall NSD from: $InstallPath" -ForegroundColor Yellow
$response = Read-Host "Are you sure you want to continue? (Y/N)"
if ($response -ne 'Y' -and $response -ne 'y') {
    Write-Host "Uninstallation cancelled." -ForegroundColor Yellow
    exit 0
}

Write-Host ""

# Remove from PATH
Write-Host "Removing NSD from system PATH..." -ForegroundColor Yellow
try {
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $newPath = ($currentPath.Split(';') | Where-Object { $_ -ne $InstallPath }) -join ';'
    
    if ($currentPath -ne $newPath) {
        [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
        Write-Host "✓ Removed from PATH successfully" -ForegroundColor Green
    } else {
        Write-Host "✓ Not found in PATH" -ForegroundColor Green
    }
} catch {
    Write-Host "WARNING: Failed to remove from PATH: $_" -ForegroundColor Yellow
    Write-Host "You may need to manually remove '$InstallPath' from your PATH environment variable" -ForegroundColor Yellow
}

# Remove desktop shortcut
Write-Host ""
Write-Host "Removing desktop shortcut..." -ForegroundColor Yellow
$shortcutPath = "$env:USERPROFILE\Desktop\NSD.lnk"
if (Test-Path $shortcutPath) {
    try {
        Remove-Item $shortcutPath -Force
        Write-Host "✓ Desktop shortcut removed" -ForegroundColor Green
    } catch {
        Write-Host "WARNING: Failed to remove shortcut: $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "✓ No desktop shortcut found" -ForegroundColor Green
}

# Remove installation directory
Write-Host ""
Write-Host "Removing installation files..." -ForegroundColor Yellow
try {
    Remove-Item $InstallPath -Recurse -Force
    Write-Host "✓ Installation files removed successfully" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to remove files: $_" -ForegroundColor Red
    Write-Host "You may need to manually delete the folder: $InstallPath" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "NSD has been uninstalled successfully!" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Note: Npcap was not removed as it may be used by other applications." -ForegroundColor Yellow
Write-Host "If you want to remove Npcap, please use the Windows Control Panel." -ForegroundColor Yellow