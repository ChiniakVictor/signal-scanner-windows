"""Offline lookup tables: IEEE OUI registry, Bluetooth SIG company IDs and 16-bit UUIDs (same data as the Android app)."""
from __future__ import annotations

import gzip
import os
import re
import sys

_oui: dict[int, str] = {}
_companies: dict[int, str] = {}
_uuids: dict[int, str] = {}
_loaded = False

UUID_OVERRIDES = {
    0xFD6F: "Exposure Notification", 0xFE2C: "Google Fast Pair", 0xFEAA: "Eddystone (Google)", 0xFD5A: "Samsung SmartTag",
    0xFD44: "Apple Find My", 0xFEED: "Tile", 0xFEEC: "Tile", 0xFFF6: "Matter commissioning", 0xFEF3: "Google Nearby",
    0xFE9F: "Google", 0xFCF1: "Google Find My Device", 0xFE03: "Amazon", 0xFE07: "Sonos", 0xFDF0: "Google (Phone Hub)",
    0x1812: "HID over GATT (keyboard/mouse)",
}
_SUFFIX = re.compile(r"[, ]+(co\.?,? ?ltd\.?|ltd\.?|inc\.?|corp(oration)?\.?|llc|gmbh|s\.?a\.?|b\.?v\.?|limited|co\.?|ag|oy|a/s|ab|kk|pte|plc)$", re.I)


def data_path(name: str) -> str:
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    p = os.path.join(base, "sigscan", "data", name)
    return p if os.path.exists(p) else os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", name)


def _short(s: str) -> str:
    v = s.strip()
    for _ in range(3):
        v = _SUFFIX.sub("", v).strip()
    return v or s


def load():
    global _loaded
    if _loaded:
        return
    try:
        with gzip.open(data_path("oui.dat"), "rt", encoding="utf-8") as f:
            for line in f:
                if len(line) > 7 and line[6] == "\t":
                    _oui[int(line[:6], 16)] = _short(line[7:].rstrip("\n"))
    except Exception:
        pass
    for name, tgt in (("bt_companies.txt", _companies), ("bt_uuids.txt", _uuids)):
        try:
            with open(data_path(name), encoding="utf-8") as f:
                for line in f:
                    k, _, v = line.rstrip("\n").partition("\t")
                    if v:
                        tgt[int(k, 16)] = v
        except Exception:
            pass
    _uuids.update(UUID_OVERRIDES)
    _loaded = True


def parse_mac(mac: str | None) -> bytes | None:
    if not mac:
        return None
    p = re.split(r"[:-]", mac)
    if len(p) != 6:
        return None
    try:
        return bytes(int(x, 16) for x in p)
    except ValueError:
        return None


def vendor(mac: str | None) -> str | None:
    m = parse_mac(mac)
    if m is None or m[0] & 0x02:
        return None
    return _oui.get((m[0] << 16) | (m[1] << 8) | m[2])


def oui_name(oui: int) -> str | None:
    return _oui.get(oui)


def company(cid: int) -> str | None:
    return _companies.get(cid)


def uuid_name(u16: int) -> str | None:
    return _uuids.get(u16)


def locally_administered(mac: str | None) -> bool:
    m = parse_mac(mac)
    return bool(m and m[0] & 0x02)
