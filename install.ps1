$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'  # PowerShell 5.1's progress bar makes downloads crawl
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'

$dir = "$env:LOCALAPPDATA\LinkDesk"
New-Item -ItemType Directory -Force $dir | Out-Null
Get-Process linkdesk -ErrorAction SilentlyContinue | Stop-Process -Force  # allow reinstall/update

Write-Host 'Downloading LinkDesk...'
Invoke-WebRequest 'https://github.com/kennumi/linkdesk/releases/latest/download/linkdesk.exe' -OutFile "$dir\linkdesk.exe" -UseBasicParsing

$lnk = (New-Object -ComObject WScript.Shell).CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\LinkDesk.lnk")
$lnk.TargetPath = "$dir\linkdesk.exe"
$lnk.Save()

Write-Host 'Installed. LinkDesk is in your Start menu.'
Start-Process "$dir\linkdesk.exe"
