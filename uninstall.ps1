# Removes Signal Scanner (per-user). Settings (%APPDATA%\SignalScanner) and the tracker log
# (%LOCALAPPDATA%\SignalScanner) are kept unless -Purge.
param([switch]$Purge)
$dest = Join-Path $env:LOCALAPPDATA 'Programs\SignalScanner'
Get-Process SignalScanner -ErrorAction SilentlyContinue | Stop-Process -Force
Remove-Item (Join-Path ([Environment]::GetFolderPath('Programs')) 'Signal Scanner.lnk') -ErrorAction SilentlyContinue
Remove-Item (Join-Path ([Environment]::GetFolderPath('Desktop')) 'Signal Scanner.lnk') -ErrorAction SilentlyContinue
if ($Purge) {
    Remove-Item (Join-Path $env:APPDATA 'SignalScanner') -Recurse -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $env:LOCALAPPDATA 'SignalScanner') -Recurse -ErrorAction SilentlyContinue
}
Set-Location $env:TEMP
Remove-Item $dest -Recurse -Force -ErrorAction SilentlyContinue
Write-Host 'Signal Scanner removed.'
