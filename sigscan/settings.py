"""Settings stored as JSON in %APPDATA%\\SignalScanner\\settings.json."""
from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, fields


def app_dir() -> str:
    d = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~/.config"), "SignalScanner")
    os.makedirs(d, exist_ok=True)
    return d


def data_dir() -> str:
    d = os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~/.local/share"), "SignalScanner")
    os.makedirs(d, exist_ok=True)
    return d


@dataclass
class Settings:
    wifi_interval: int = 30
    bt_interval: int = 5
    classic_inquiry: bool = True
    forget_minutes: int = 10
    tracker_minutes: int = 60
    tracker_days: int = 2
    export_dir: str = ""

    @classmethod
    def load(cls) -> "Settings":
        try:
            with open(os.path.join(app_dir(), "settings.json"), encoding="utf-8") as f:
                raw = json.load(f)
            names = {f.name for f in fields(cls)}
            return cls(**{k: v for k, v in raw.items() if k in names})
        except Exception:
            return cls()

    def save(self):
        p = os.path.join(app_dir(), "settings.json")
        with open(p + ".tmp", "w", encoding="utf-8") as f:
            json.dump(asdict(self), f, indent=2)
        os.replace(p + ".tmp", p)


def log(msg: str):
    try:
        with open(os.path.join(data_dir(), "signalscanner.log"), "a", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + msg + "\n")
    except Exception:
        pass
