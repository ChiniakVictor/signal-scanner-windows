# Signal Scanner for Windows

Source code for Signal Scanner for Windows 1.0, made by Victor.

The Windows companion to Signal Scanner: Wi-Fi networks with full beacon details, Bluetooth LE devices and trackers, NFC and radio information. Everything stays on the PC.

## Download

Download and install the app for free from [kodiakking.com](https://kodiakking.com).

## Build

Requirements: Windows 10/11 and Python 3.12 (64-bit) from python.org.

Open PowerShell in this folder and run:

```
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

`build.ps1` makes a virtual environment, installs `requirements.txt`, and builds a self-contained app in `dist\` with PyInstaller. Then run `install.ps1` (right-click > Run with PowerShell) to install it, or `uninstall.ps1` to remove it.

To run from source instead: `python -m venv .venv`, `.venv\Scripts\pip install -r requirements.txt`, then `.venv\Scripts\python run.py`.

## License

No license has been chosen for this project yet.
