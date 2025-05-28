$ErrorActionPreference = 'Stop'
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$packageName = $env:ChocolateyPackageName
$packageVersion = $env:ChocolateyPackageVersion

# Download URLs for different architectures
$url64 = "https://github.com/perplext/nsd/releases/download/v$packageVersion/nsd-windows-amd64.zip"
$url32 = "https://github.com/perplext/nsd/releases/download/v$packageVersion/nsd-windows-386.zip"

$packageArgs = @{
  packageName   = $packageName
  unzipLocation = $toolsDir
  fileType      = 'zip'
  url           = $url32
  url64bit      = $url64
  softwareName  = 'NSD*'
  checksum      = ''  # Will be populated during build
  checksumType  = 'sha256'
  checksum64    = ''  # Will be populated during build
  checksumType64= 'sha256'
  validExitCodes= @(0)
}

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "NSD requires administrator privileges for packet capture. Please run as administrator."
}

# Install the package
Install-ChocolateyZipPackage @packageArgs

# Create shim for command line access
$exePath = Join-Path $toolsDir "nsd.exe"
if (Test-Path $exePath) {
    Install-ChocolateyPath $toolsDir
    Write-Host "NSD has been installed successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "To get started:" -ForegroundColor Yellow
    Write-Host "1. Open Command Prompt or PowerShell as Administrator" -ForegroundColor White
    Write-Host "2. Run: nsd -i <interface-name>" -ForegroundColor White
    Write-Host "3. Use 'nsd --help' for more options" -ForegroundColor White
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor Yellow
    Write-Host "  nsd -i Ethernet" -ForegroundColor White
    Write-Host "  nsd -i Wi-Fi -theme CyberpunkNeon" -ForegroundColor White
    Write-Host "  nsd -i Ethernet -filter `"tcp port 443`"" -ForegroundColor White
} else {
    Write-Error "Installation failed: nsd.exe not found"
}