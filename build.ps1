# Builds dist\SignalScanner\SignalScanner.exe (self-contained, no Python needed to run).
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$py = "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe"
if (-not (Test-Path .venv)) { & $py -m venv .venv }
.\.venv\Scripts\python.exe -m pip install --disable-pip-version-check -q -r requirements.txt
.\.venv\Scripts\python.exe make_icon.py
.\.venv\Scripts\pyinstaller.exe --noconfirm --clean --windowed --name SignalScanner `
    --icon signalscanner.ico --add-data "signalscanner.ico;." --add-data "sigscan\data;sigscan\data" --collect-submodules winrt --collect-submodules bleak `
    --exclude-module tkinter run.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }
Write-Host "Built: $PSScriptRoot\dist\SignalScanner\SignalScanner.exe"
