"""BLE advertisement decoding (port of the Android app's BtParse.kt)."""
from __future__ import annotations

import struct
import uuid as _uuid
from dataclasses import dataclass

from . import lookup


@dataclass
class Decoded:
    title: str
    lines: list


def hexsp(b: bytes | None) -> str:
    return " ".join(f"{x:02X}" for x in (b or b""))


def uuid16_of(u: str) -> int | None:
    u = str(u).lower()
    if u.endswith("-0000-1000-8000-00805f9b34fb") and u.startswith("0000"):
        return int(u[4:8], 16)
    return None


def uuid16_label(u: int) -> str:
    n = lookup.uuid_name(u)
    return f"0x{u:04X}" + (f" {n}" if n else "")


KNOWN128 = {"6e400001-b5a3-f393-e0a9-e50e24dcca9e": "(Nordic UART)", "d0611e78-bbb4-4591-a5f8-487910ae4366": "(Apple Continuity)",
            "9fa480e0-4967-4542-9390-d343dc5d04ae": "(Apple Nearby)"}


def uuid_label(u: str) -> str:
    s = uuid16_of(u)
    if s is not None: return uuid16_label(s)
    return f"{u} {KNOWN128[u.lower()]}" if u.lower() in KNOWN128 else str(u)


APPLE_TYPES = {0x01: "Apple overflow area", 0x02: "iBeacon", 0x03: "AirPrint", 0x05: "AirDrop", 0x06: "HomeKit", 0x07: "Proximity pairing (AirPods/Beats)",
               0x08: "Hey Siri", 0x09: "AirPlay target", 0x0A: "AirPlay source", 0x0B: "Magic Switch (Watch)", 0x0C: "Handoff", 0x0D: "Tethering target",
               0x0E: "Tethering source", 0x0F: "Nearby Action", 0x10: "Nearby Info", 0x12: "Find My", 0x16: "Unknown (0x16)"}
AIRPODS = {0x0220: "AirPods", 0x0F20: "AirPods (2nd gen)", 0x1320: "AirPods (3rd gen)", 0x0E20: "AirPods Pro", 0x1420: "AirPods Pro (2nd gen)",
           0x2420: "AirPods Pro 2 (USB-C)", 0x0A20: "AirPods Max", 0x1F20: "AirPods Max (USB-C)", 0x1920: "AirPods 4", 0x1B20: "AirPods 4 ANC",
           0x0320: "Powerbeats3", 0x0B20: "Powerbeats Pro", 0x0C20: "Beats Solo Pro", 0x1120: "Beats Studio Buds", 0x1020: "Beats Flex",
           0x0520: "BeatsX", 0x0620: "Beats Solo3", 0x0920: "Beats Studio3", 0x1720: "Beats Studio Pro", 0x1220: "Beats Fit Pro", 0x1620: "Beats Studio Buds+"}
MS_TYPES = {1: "Xbox One", 6: "Apple iPhone", 7: "Apple iPad", 8: "Android device", 9: "Windows 10/11 desktop", 11: "Windows 10 phone",
            12: "Linux device", 13: "Windows IoT", 14: "Surface Hub", 15: "Windows laptop", 16: "Windows tablet"}


def decode_apple(d: bytes) -> Decoded:
    lines, title, o = [], "Apple Continuity", 0
    while o + 2 <= len(d):
        t = d[o]
        if t == 0x01:
            lines.append("Overflow area (iOS app advertising in the background)"); break
        l = min(d[o + 1], len(d) - o - 2)
        if t == 0 and l == 0: break
        v = d[o + 2:o + 2 + l]
        if t == 0x02 and l >= 21:
            title = "iBeacon"
            lines += [f"iBeacon UUID {_uuid.UUID(bytes=bytes(v[:16]))}", f"Major {(v[16] << 8) | v[17]}, Minor {(v[18] << 8) | v[19]}",
                      f"Measured power @1 m: {struct.unpack('b', v[20:21])[0]} dBm"]
        elif t == 0x12:
            title = "Find My (AirTag / separated Apple device)" if l >= 25 else "Find My (owner nearby)"
            st = v[0] if v else 0
            batt = ["full", "medium", "low", "critically low"][(st >> 6) & 3]
            lines.append(f"Find My: {'separated from owner (offline-finding key broadcast)' if l >= 25 else 'near its owner'}, battery {batt}")
        elif t == 0x07:
            title = "AirPods / Beats"
            if v and v[0] != 0x01:
                lines.append("Proximity pairing (newer encrypted format – model/battery not readable)")
            else:
                if l >= 3:
                    m = (v[1] << 8) | v[2]; lines.append(f"Model: {AIRPODS.get(m, f'0x{m:04X}')}")
                if l >= 7:
                    def lvl(x): return "–" if x == 15 else f"{x * 10}%"
                    lines.append(f"Battery L {lvl(v[5] >> 4)} R {lvl(v[5] & 15)} case {lvl(v[6] & 15)}")
        elif t == 0x10:
            if title == "Apple Continuity": title = "Apple device (Nearby Info)"
            if l >= 1:
                acts = {0: "activity unknown", 1: "reporting disabled", 3: "idle", 5: "playing audio", 7: "screen on / locked", 9: "video",
                        10: "on a call (watch)", 11: "on a call", 13: "driving", 14: "on a call", 15: "video/call"}
                a = v[0] & 0x0F
                lines.append(f"Nearby Info: {acts.get(a, f'action {a}')}" + (", Wi-Fi on" if l >= 2 and v[1] & 0x10 else ""))
        elif t == 0x0F: lines.append(f"Nearby Action (type 0x{v[1] if len(v) > 1 else 0:02X}) – e.g. setup/Wi-Fi password sharing")
        elif t == 0x0C: lines.append("Handoff (continuity of an app between devices)")
        elif t == 0x09: lines.append("AirPlay target (Apple TV/HomePod/Mac)")
        elif t == 0x05: lines.append("AirDrop is open/searching")
        elif t == 0x06: lines.append("HomeKit accessory")
        elif t == 0x0B: lines.append("Apple Watch (Magic Switch)")
        elif t == 0x0D: lines.append("Instant Hotspot available")
        else: lines.append(f"{APPLE_TYPES.get(t, f'type 0x{t:02X}')}: {hexsp(v)}")
        o += 2 + l
    return Decoded(title, lines or [hexsp(d)])


def decode_manufacturer(cid: int, d: bytes) -> Decoded | None:
    try:
        if cid == 0x004C: return decode_apple(d)
        if cid == 0x0006:
            if len(d) >= 2 and d[0] == 0x01:
                dt = d[1] & 0x1F
                return Decoded("Microsoft CDP beacon", [f"Device: {MS_TYPES.get(dt, f'type {dt}')}", "Windows/Xbox/phone-link device nearby (Connected Devices Platform)"])
            if d and d[0] == 0x03:
                return Decoded("Microsoft Swift Pair", ["Device is in pairing mode and offers Swift Pair" + (", name: " + d[3:].decode("utf-8", "replace").strip("\x00") if len(d) > 3 else "")])
            return Decoded("Microsoft", [hexsp(d)])
        if cid == 0x0075:
            if len(d) >= 2 and d[0] == 0x42 and d[1] == 0x04: t = "Samsung Galaxy device / Smart View advertisement"
            elif d and d[0] == 0x01: t = "Samsung Galaxy Buds / wearable"
            else: t = f"Samsung proprietary data ({len(d)} bytes)"
            return Decoded("Samsung", [t])
        if cid == 0x00E0: return Decoded("Google", [f"Google proprietary data ({len(d)} bytes)"])
        if cid == 0x0059: return Decoded("Nordic Semiconductor", ["Usually a custom/DIY device or sensor"])
        if cid == 0x0499 and len(d) >= 14 and d[0] == 5:
            temp = struct.unpack(">h", d[1:3])[0] * 0.005; hum = struct.unpack(">H", d[3:5])[0] * 0.0025; pres = (struct.unpack(">H", d[5:7])[0] + 50000) / 100
            return Decoded("RuuviTag", [f"Temperature {temp:.2f} °C", f"Humidity {hum:.1f} %", f"Pressure {pres:.1f} hPa"])
    except Exception:
        pass
    return None


def decode_service(u16: int, d: bytes) -> Decoded | None:
    try:
        if u16 == 0xFEAA:
            f = d[0]
            if f == 0x00: return Decoded("Eddystone-UID", [f"Tx @0 m {struct.unpack('b', d[1:2])[0]} dBm", f"Namespace {d[2:12].hex()}", f"Instance {d[12:18].hex()}"])
            if f == 0x10:
                schemes = ["http://www.", "https://www.", "http://", "https://"]
                exp = [".com/", ".org/", ".edu/", ".net/", ".info/", ".biz/", ".gov/", ".com", ".org", ".edu", ".net", ".info", ".biz", ".gov"]
                url = schemes[d[2]] if d[2] < 4 else ""
                for c in d[3:]: url += exp[c] if c < len(exp) else chr(c)
                return Decoded("Eddystone-URL", [f"URL {url}"])
            if f == 0x20: return Decoded("Eddystone-TLM", [f"Battery {(d[2] << 8) | d[3]} mV", f"Temperature {struct.unpack('b', d[4:5])[0] + d[5] / 256:.1f} °C"])
            if f == 0x30: return Decoded("Eddystone-EID", [f"Ephemeral ID {d[2:10].hex()}"])
            if f in (0x40, 0x41): return Decoded("Google Find My Device tag", ["Find My Device network" + (" · separated from owner (unwanted-tracking mode)" if f == 0x41 else "")])
            return Decoded("Eddystone", [hexsp(d)])
        if u16 == 0xFE2C: return Decoded("Google Fast Pair", [f"Model ID 0x{d.hex()} (pairing mode)" if len(d) == 3 else "Account-key filter (paired device advertising to its owner)"])
        if u16 == 0xFD6F: return Decoded("Exposure Notification", [f"Rolling proximity ID {d[:16].hex()}"])
        if u16 == 0xFD5A: return Decoded("Samsung SmartTag / SmartThings Find", [f"Offline-finding advertisement ({len(d)} bytes)"])
        if u16 in (0xFEED, 0xFEEC): return Decoded("Tile tracker", ["Tile advertisement"])
        if u16 == 0xFCB2: return Decoded("DULT tracker", ["Detecting Unwanted Location Trackers advertisement"])
        if u16 == 0xFFF6 and len(d) >= 7:
            return Decoded("Matter commissioning", [f"Discriminator {d[1] | ((d[2] & 0x0F) << 8)}", f"Vendor ID 0x{d[3] | (d[4] << 8):04X}, product 0x{d[5] | (d[6] << 8):04X}"])
        if u16 == 0xFEF3: return Decoded("Google Nearby / Quick Share", [f"{len(d)} bytes"])
        if u16 == 0x180F: return Decoded("Battery", [f"{d[0]} %"])
    except Exception:
        pass
    return None


def distance_m(rssi: int, at1m: int, n: float = 2.2) -> float:
    return 10 ** ((at1m - rssi) / (10 * n))


MAJORS = {0x0000: "Miscellaneous", 0x0100: "Computer", 0x0200: "Phone", 0x0300: "Networking", 0x0400: "Audio/Video", 0x0500: "Peripheral",
          0x0600: "Imaging", 0x0700: "Wearable", 0x0800: "Toy", 0x0900: "Health"}
MINORS = {0x0104: "Desktop", 0x010C: "Laptop", 0x011C: "Tablet", 0x020C: "Smartphone", 0x0204: "Cellular phone", 0x0404: "Headset", 0x0408: "Hands-free",
          0x0414: "Loudspeaker", 0x0418: "Headphones", 0x041C: "Portable audio", 0x0420: "Car audio", 0x0424: "Set-top box", 0x0428: "Hi-Fi audio",
          0x043C: "Display + loudspeaker", 0x0448: "Gaming/toy", 0x0540: "Keyboard", 0x0580: "Mouse", 0x05C0: "Keyboard + mouse", 0x0504: "Joystick",
          0x0508: "Gamepad", 0x050C: "Remote control", 0x0704: "Wristwatch", 0x0714: "Glasses"}


def class_of_device(cod: int | None) -> str | None:
    if not cod: return None
    m = MAJORS.get(cod & 0x1F00)
    mi = MINORS.get(cod & 0x1FFC) or MINORS.get((cod & 0x1F00) | (cod & 0xC0))
    return " · ".join(x for x in (m, mi) if x) or f"0x{cod:06X}"
