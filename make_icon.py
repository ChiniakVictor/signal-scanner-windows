"""Render the app icon to signalscanner.ico (used by PyInstaller and shortcuts)."""
import sys
from PySide6.QtWidgets import QApplication
from sigscan.app import app_icon

app = QApplication(sys.argv)
ok = app_icon().pixmap(256, 256).save("signalscanner.ico", "ICO")
print("icon saved" if ok else "icon save FAILED")
