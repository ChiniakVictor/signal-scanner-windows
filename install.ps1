# Per-user install (no admin): %LOCALAPPDATA%\Programs\SignalScanner + Start Menu and Desktop shortcuts.
param([string]$Source = "$PSScriptRoot\dist\SignalScanner")
$ErrorActionPreference = 'Stop'
$dest = Join-Path $env:LOCALAPPDATA 'Programs\SignalScanner'
Get-Process SignalScanner -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$dest*" } | Stop-Process -Force
Start-Sleep -Milliseconds 500
if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
New-Item -ItemType Directory -Force $dest | Out-Null
Copy-Item "$Source\*" $dest -Recurse -Force
Copy-Item "$PSScriptRoot\uninstall.ps1" $dest -Force
$exe = Join-Path $dest 'SignalScanner.exe'
$ico = Join-Path $dest '_internal\signalscanner.ico'
$ws = New-Object -ComObject WScript.Shell
foreach ($lnk in @((Join-Path ([Environment]::GetFolderPath('Programs')) 'Signal Scanner.lnk'),
                   (Join-Path ([Environment]::GetFolderPath('Desktop')) 'Signal Scanner.lnk'))) {
    $s = $ws.CreateShortcut($lnk); $s.TargetPath = $exe; $s.WorkingDirectory = $dest
    if (Test-Path $ico) { $s.IconLocation = $ico } ; $s.Description = 'Signal Scanner'; $s.Save()
}
Write-Host "Installed to $dest"
