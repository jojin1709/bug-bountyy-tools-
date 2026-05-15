# BugHunt.ai Windows PowerShell Launcher
# Run in PowerShell: .\bughunt.ps1 hunt target.com

param(
    [string]$Command = "",
    [string]$Target = "",
    [string]$Scope = ""
)

if (-not $Command) {
    Write-Host ""
    Write-Host "[*] BugHunt.ai - Windows PowerShell Launcher"
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  .\bughunt.ps1 setup                  - Install everything"
    Write-Host "  .\bughunt.ps1 hunt <target>         - Hunt target"
    Write-Host "  .\bughunt.ps1 hunt <target> <scope> - Hunt with scope"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\bughunt.ps1 setup"
    Write-Host "  .\bughunt.ps1 hunt target.com"
    Write-Host "  .\bughunt.ps1 hunt target.com scope.txt"
    Write-Host ""
    exit 1
}

# Check WSL installed
$wslCheck = wsl --list 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] WSL not installed. Install with:"
    Write-Host "    wsl --install"
    Write-Host "    wsl --install -d kali-linux"
    exit 1
}

# Get current directory (Windows path)
$currentPath = Get-Location
$wslPath = $currentPath -replace "C:", "/mnt/c" -replace "\\", "/"

# Build command
$pythonCmd = "python3 bughunt.py $Command"
if ($Target) {
    $pythonCmd += " $Target"
}
if ($Scope) {
    $pythonCmd += " $Scope"
}

# Run in WSL Kali
Write-Host "[*] Running in WSL Kali Linux..."
Write-Host ""

wsl -d kali-linux -- bash -c "cd '$wslPath' && $pythonCmd"
