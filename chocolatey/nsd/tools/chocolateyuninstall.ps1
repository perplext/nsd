$ErrorActionPreference = 'Stop'
$packageName = $env:ChocolateyPackageName
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"

# Remove from PATH
$pathToRemove = $toolsDir
$pathType = [System.EnvironmentVariableTarget]::Machine
$currentPath = [Environment]::GetEnvironmentVariable("PATH", $pathType)

if ($currentPath -like "*$pathToRemove*") {
    $newPath = $currentPath.Replace(";$pathToRemove", "").Replace("$pathToRemove;", "").Replace("$pathToRemove", "")
    [Environment]::SetEnvironmentVariable("PATH", $newPath, $pathType)
    Write-Host "Removed NSD from system PATH" -ForegroundColor Green
}

# Clean up any configuration files (optional)
$configPaths = @(
    "$env:USERPROFILE\.config\nsd",
    "$env:APPDATA\nsd",
    "$env:LOCALAPPDATA\nsd"
)

foreach ($configPath in $configPaths) {
    if (Test-Path $configPath) {
        $response = Read-Host "Remove NSD configuration files at '$configPath'? (y/N)"
        if ($response -eq 'y' -or $response -eq 'Y') {
            Remove-Item -Path $configPath -Recurse -Force
            Write-Host "Removed configuration files at $configPath" -ForegroundColor Green
        }
    }
}

Write-Host "NSD has been uninstalled successfully!" -ForegroundColor Green