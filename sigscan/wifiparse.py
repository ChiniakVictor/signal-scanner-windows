"""Wi-Fi information-element parsing (port of the Android app's WifiParse.kt)."""
from __future__ import annotations

import math
from dataclasses import dataclass, field

from . import lookup


@dataclass
class Rsn:
    group: str
    pairwise: list
    akms: list
    akm_ids: list
    mfp_required: bool
    mfp_capable: bool


@dataclass
class Ie:
    id: int
    ext: int | None
    name: str
    summary: str
    hex: str

    @property
    def label(self):
        return f"255/{self.ext}" if self.ext is not None else str(self.id)


@dataclass
class IeInfo:
    items: list = field(default_factory=list)
    ssid: str | None = None
    rates: list = field(default_factory=list)
    ds_channel: int | None = None
    dtim: int | None = None
    country: str | None = None
    country_env: str | None = None
    max_tx_power: int | None = None
    station_count: int | None = None
    channel_util: int | None = None
    ht_streams: int = 0
    vht_streams: int = 0
    he_streams: int = 0
    ht: bool = False
    vht: bool = False
    he: bool = False
    eht: bool = False
    ht_width40: bool = False
    ht_secondary: int = 0
    bss_color: int | None = None
    rsn: Rsn | None = None
    wpa: Rsn | None = None
    wps: bool = False
    wps_state: str | None = None
    wps_device: dict = field(default_factory=dict)
    wmm: bool = False
    k11: bool = False
    r11: bool = False
    v11: bool = False
    ftm_responder: bool = False
    interworking: bool = False
    hs20: bool = False
    owe_transition: bool = False
    mld_mac: str | None = None
    ap_name: str | None = None
    vendors: list = field(default_factory=list)
    he_op_6g: tuple | None = None
    eht_width: int | None = None
    vht_width: int | None = None
    vht_center0: int | None = None
    reduced_neighbors: int = 0

    @property
    def streams(self):
        return max(self.ht_streams, self.vht_streams, self.he_streams)


def hexs(b: bytes, mx: int = 512) -> str:
    s = " ".join(f"{x:02X}" for x in b[:mx])
    return s + (" …" if len(b) > mx else "")


def channel_of(freq: int) -> int:
    if freq == 2484: return 14
    if 2412 <= freq <= 2472: return (freq - 2407) // 5
    if 5160 <= freq <= 5895: return (freq - 5000) // 5
    if freq == 5935: return 2
    if 5955 <= freq <= 7115: return (freq - 5950) // 5
    if 4910 <= freq <= 4980: return (freq - 4000) // 5
    return 0


def band(freq: int) -> str:
    if freq < 2500: return "2.4 GHz"
    if freq < 5925: return "5 GHz"
    if freq < 7200: return "6 GHz"
    return "60 GHz" if freq > 50000 else "?"


def freq_of(ch: int, bnd: str) -> int:
    if bnd == "2.4 GHz": return 2484 if ch == 14 else 2407 + 5 * ch
    if bnd == "6 GHz": return 5950 + 5 * ch
    return 5000 + 5 * ch


def distance_m(rssi: int, freq: int) -> float:
    return 10 ** ((27.55 - 20 * math.log10(freq) + abs(rssi)) / 20.0)


def bars(rssi: int) -> int:
    return 4 if rssi >= -55 else 3 if rssi >= -67 else 2 if rssi >= -75 else 1 if rssi >= -85 else 0


def quality(rssi: int) -> str:
    for lim, n in ((-50, "Excellent"), (-60, "Very good"), (-67, "Good"), (-75, "Fair"), (-85, "Weak")):
        if rssi >= lim: return n
    return "Very weak"


def standard(ie: IeInfo, freq: int) -> tuple[int, str, str]:
    if ie.eht: s = 8
    elif ie.he: s = 6
    elif ie.vht: s = 5
    elif ie.ht: s = 4
    else: s = 1
    names = {1: ("Legacy", "802.11b/g (legacy)" if freq < 2500 else "802.11a (legacy)"), 4: ("Wi-Fi 4", "Wi-Fi 4 (802.11n)"),
             5: ("Wi-Fi 5", "Wi-Fi 5 (802.11ac)"), 6: ("Wi-Fi 6E" if freq >= 5925 else "Wi-Fi 6", "Wi-Fi 6E (802.11ax)" if freq >= 5925 else "Wi-Fi 6 (802.11ax)"),
             8: ("Wi-Fi 7", "Wi-Fi 7 (802.11be)")}
    return s, names[s][0], names[s][1]


def width_and_center(ie: IeInfo, freq: int) -> tuple[int, int]:
    """(width MHz, center frequency MHz) of the BSS's operating channel."""
    b = band(freq)
    if ie.eht_width:
        w = ie.eht_width
    elif ie.he_op_6g:
        return ie.he_op_6g[1], freq_of(ie.he_op_6g[2], "6 GHz")
    elif ie.vht_width:
        return ie.vht_width, freq_of(ie.vht_center0, b) if ie.vht_center0 else freq
    elif ie.ht_secondary in (1, 3):
        return 40, freq + (10 if ie.ht_secondary == 1 else -10)
    else:
        w = 20
    return w, freq


def max_rate(std: int, width: int, streams: int) -> float | None:
    ss = max(1, streams)
    table = {4: [(40, 150.0), (0, 72.2)], 5: [(160, 866.7), (80, 433.3), (40, 200.0), (0, 86.7)],
             6: [(160, 1201.0), (80, 600.5), (40, 286.8), (0, 143.4)], 8: [(320, 2882.0), (160, 1441.0), (80, 720.6), (40, 344.1), (0, 172.1)],
             1: [(0, 54.0)]}
    for lim, per in table.get(std, []):
        if width >= lim: return per * ss
    return None


CIPHERS = {1: "WEP-40", 2: "TKIP", 4: "CCMP-128", 5: "WEP-104", 6: "BIP-CMAC-128", 8: "GCMP-128", 9: "GCMP-256", 10: "CCMP-256",
           11: "BIP-GMAC-128", 12: "BIP-GMAC-256", 13: "BIP-CMAC-256"}
AKMS = {1: "802.1X", 2: "PSK", 3: "FT-802.1X", 4: "FT-PSK", 5: "802.1X-SHA256", 6: "PSK-SHA256", 8: "SAE", 9: "FT-SAE", 11: "Suite-B",
        12: "Suite-B-192", 13: "FT-802.1X-SHA384", 14: "FILS-SHA256", 15: "FILS-SHA384", 18: "OWE", 19: "FT-PSK-SHA384", 20: "PSK-SHA384",
        24: "SAE-EXT-KEY", 25: "FT-SAE-EXT-KEY"}


def _suite(b, o, names):
    oui = (b[o] << 16) | (b[o + 1] << 8) | b[o + 2]
    t = b[o + 3]
    if oui in (0x000FAC, 0x0050F2): return names.get(t, f"type {t}"), t
    return f"{oui:06X}:{t}", 1000 + t


def le16(b, o): return b[o] | (b[o + 1] << 8)
def be16(b, o): return (b[o] << 8) | b[o + 1]


def parse_rsn(b: bytes, start: int) -> Rsn | None:
    try:
        o = start + 2
        grp = "CCMP-128"
        if o + 4 <= len(b): grp = _suite(b, o, CIPHERS)[0]; o += 4
        pw, akm, ids = [], [], []
        if o + 2 <= len(b):
            n = le16(b, o); o += 2
            for _ in range(n):
                if o + 4 <= len(b): pw.append(_suite(b, o, CIPHERS)[0]); o += 4
        if o + 2 <= len(b):
            n = le16(b, o); o += 2
            for _ in range(n):
                if o + 4 <= len(b):
                    s = _suite(b, o, AKMS); akm.append(s[0]); ids.append(s[1]); o += 4
        req = cap = False
        if o + 2 <= len(b):
            c = le16(b, o); req = bool(c & 0x40); cap = bool(c & 0x80)
        return Rsn(grp, pw, akm, ids, req, cap)
    except Exception:
        return None


def _streams(mp: int, n: int = 8) -> int:
    s = 0
    for i in range(n):
        if (mp >> (2 * i)) & 3 != 3: s = i + 1
    return s


IE_NAMES = {0: "SSID", 1: "Supported rates", 3: "DS parameter (channel)", 5: "TIM (DTIM)", 7: "Country", 11: "BSS Load", 32: "Power constraint",
            35: "TPC report", 42: "ERP info", 45: "HT capabilities (802.11n)", 48: "RSN (WPA2/WPA3)", 50: "Extended rates", 51: "AP channel report",
            52: "Neighbor report", 54: "Mobility domain (802.11r)", 56: "Timeout interval", 59: "Supported operating classes", 61: "HT operation",
            62: "Secondary channel offset", 67: "BSS available admission capacity", 70: "RM capabilities (802.11k)", 72: "20/40 BSS coexistence",
            74: "Overlapping BSS scan params", 90: "BSS max idle period", 107: "Interworking", 108: "Advertisement protocol", 111: "Roaming consortium",
            113: "Mesh configuration", 114: "Mesh ID", 127: "Extended capabilities", 133: "Cisco CCX (AP name)", 159: "Secondary channel offset",
            191: "VHT capabilities (802.11ac)", 192: "VHT operation", 195: "Transmit power envelope", 201: "Reduced neighbor report",
            221: "Vendor specific", 244: "RSN extension"}
EXT_NAMES = {35: "HE capabilities (802.11ax)", 36: "HE operation", 38: "MU EDCA parameters", 39: "Spatial reuse", 59: "HE 6 GHz band caps",
             106: "EHT operation (802.11be)", 107: "Multi-link (MLO)", 108: "EHT capabilities", 55: "Short SSID list"}
VENDOR_OUIS = {0x0050F2: "Microsoft/WFA", 0x506F9A: "Wi-Fi Alliance", 0x001018: "Broadcom", 0x000C43: "MediaTek/Ralink", 0x00037F: "Qualcomm Atheros",
               0x8CFDF0: "Qualcomm", 0x0017F2: "Apple", 0x00904C: "Epigram (Broadcom)", 0x00E04C: "Realtek", 0x001392: "Ruckus", 0x000B86: "Aruba",
               0x004096: "Cisco", 0x000FAC: "IEEE 802.11", 0x000CE7: "MediaTek", 0x0C4327: "MediaTek", 0x001A11: "Google", 0x0050F3: "Microsoft",
               0x0024E2: "Hon Hai", 0x00A0C6: "Qualcomm", 0x001374: "Atheros", 0x00146C: "Netgear", 0xF4F5E8: "Google", 0x18FE34: "Espressif",
               0x00156D: "Ubiquiti", 0x0026BB: "Apple", 0x000393: "Apple", 0x2CF0A2: "Apple"}
WPS_ATTRS = {0x1011: "Device name", 0x1021: "Manufacturer", 0x1023: "Model name", 0x1024: "Model number", 0x1042: "Serial number"}


def split_ies(raw: bytes) -> list[tuple[int, int, bytes]]:
    out, o = [], 0
    while o + 2 <= len(raw):
        i, l = raw[o], raw[o + 1]
        if o + 2 + l > len(raw): break
        body = raw[o + 2:o + 2 + l]
        if i == 255 and l >= 1:
            out.append((255, body[0], body[1:]))
        else:
            out.append((i, -1, body))
        o += 2 + l
    return out


def _yn(x): return "yes" if x else "no"


def parse_ies(raw: bytes) -> IeInfo:
    r = IeInfo()
    for iid, ext_id, b in split_ies(raw):
        name = IE_NAMES.get(iid, f"Element {iid}")
        ext = None
        s = ""
        try:
            if iid == 0:
                r.ssid = "" if (not b or all(x == 0 for x in b)) else b.decode("utf-8", "replace")
                s = r.ssid or "(hidden)"
            elif iid in (1, 50):
                r.rates += [(x & 0x7F) / 2 for x in b]
                s = ", ".join(f"{(x & 0x7F) / 2:g}" + ("*" if x & 0x80 else "") for x in b) + " Mbit/s (* = basic)"
            elif iid == 3:
                r.ds_channel = b[0]; s = f"channel {b[0]}"
            elif iid == 5:
                r.dtim = b[1]; s = f"DTIM count {b[0]}, period {b[1]}"
            elif iid == 7:
                cc = b[:2].decode("ascii", "replace"); r.country = cc
                r.country_env = {"I": "indoor", "O": "outdoor", " ": "any"}.get(chr(b[2]))
                parts, o = [], 3
                while o + 3 <= len(b):
                    f, n, p = b[o], b[o + 1], b[o + 2]
                    if f >= 201: parts.append(f"op-ext {f}/{n}")
                    elif f > 0:
                        end = f"–{f + (n - 1) * (4 if f > 14 else 1)}" if n > 1 else ""
                        parts.append(f"ch {f}{end}: " + (f"{p} dBm" if 1 <= p <= 60 else "power n/a"))
                        if 1 <= p <= 60: r.max_tx_power = max(r.max_tx_power or 0, p)
                    o += 3
                s = cc + (f" ({r.country_env})" if r.country_env else "") + "  " + "; ".join(parts)
            elif iid == 11:
                r.station_count = le16(b, 0); r.channel_util = (b[2] * 100 + 127) // 255
                s = f"{r.station_count} clients, channel {r.channel_util}% busy, admission cap {le16(b, 3) * 32} µs/s"
            elif iid == 32: s = f"local power constraint {b[0]} dB"
            elif iid == 35: s = f"tx power {int.from_bytes(b[0:1], 'little', signed=True)} dBm (as reported), link margin {b[1]} dB"
            elif iid == 51: s = f"operating class {b[0]}, channels " + ", ".join(str(x) for x in b[1:])
            elif iid == 42: s = f"non-ERP present={b[0] & 1}, protection={(b[0] >> 1) & 1}, barker preamble={(b[0] >> 2) & 1}"
            elif iid == 45:
                r.ht = True; cap = le16(b, 0); r.ht_width40 = bool(cap & 2)
                r.ht_streams = sum(1 for i in range(4) if b[3 + i] != 0)
                s = f"{r.ht_streams} stream(s), 40 MHz {_yn(r.ht_width40)}, SGI20 {_yn(cap & 0x20)}, SGI40 {_yn(cap & 0x40)}, LDPC {_yn(cap & 1)}"
            elif iid == 48:
                r.rsn = parse_rsn(b, 0)
                if r.rsn:
                    s = f"group {r.rsn.group}; pairwise {'/'.join(r.rsn.pairwise)}; AKM {'/'.join(r.rsn.akms)}; PMF " + ("required" if r.rsn.mfp_required else "capable" if r.rsn.mfp_capable else "off")
            elif iid == 54:
                r.r11 = True; s = f"mobility domain {le16(b, 0):04X}, FT over DS {_yn(b[2] & 1)}"
            elif iid == 61:
                off = b[1] & 3; r.ht_secondary = off
                s = f"primary ch {b[0]}, secondary {({1: 'above', 3: 'below'}).get(off, 'none')}, width {'any (40)' if b[1] & 4 else '20'} MHz"
            elif iid == 70:
                r.k11 = True; s = f"neighbor report {_yn(b[0] & 2)}, beacon measurement {_yn(b[0] & 0x70)}"
            elif iid == 107:
                r.interworking = True
                t = b[0] & 0x0F
                s = f"access network type {t}, internet {_yn(b[0] & 0x10)}"
            elif iid == 111: s = f"{b[0]} consortium OI(s) in ANQP"
            elif iid == 114: s = b.decode("utf-8", "replace")
            elif iid == 127:
                def bit(n): return n // 8 < len(b) and (b[n // 8] >> (n % 8)) & 1 == 1
                r.v11 = bit(19); r.ftm_responder = bit(70)
                if bit(31): r.interworking = True
                f = [n for c, n in ((bit(19), "BSS transition (11v)"), (bit(31), "interworking"), (bit(70), "FTM responder"), (bit(71), "FTM initiator"),
                                    (bit(62), "op-mode notification"), (bit(46), "WNM notification"), (bit(77), "TWT requester"), (bit(78), "TWT responder")) if c]
                s = ", ".join(f) if f else f"{len(b)} bytes"
            elif iid == 133:
                if len(b) >= 26:
                    r.ap_name = b[10:26].decode("ascii", "replace").strip("\x00 "); s = f'AP name "{r.ap_name}"'
            elif iid == 191:
                r.vht = True; cap = int.from_bytes(b[0:4], "little"); r.vht_streams = _streams(le16(b, 4))
                cw = (cap >> 2) & 3
                s = f"{r.vht_streams} stream(s), {({1: '160 MHz', 2: '160 & 80+80 MHz'}).get(cw, '80 MHz')}, SU beamformer {_yn(cap & (1 << 11))}, MU beamformer {_yn(cap & (1 << 19))}"
            elif iid == 192:
                w, c0, c1 = b[0], b[1], b[2]
                if w == 0: r.vht_width = None
                elif c1 != 0 or w in (2, 3): r.vht_width = 160
                else: r.vht_width = 80
                r.vht_center0 = c1 if (c1 != 0 and abs(c1 - c0) == 8) else c0
                s = f"width {({0: '20/40', 1: '80/160/80+80', 2: '160 (old)', 3: '80+80 (old)'}).get(w, '?')}, center seg0 ch {c0}, seg1 ch {c1}"
            elif iid == 195: s = "max tx power " + "/".join(f"{int.from_bytes(bytes([x]), 'little', signed=True) / 2:g}" for x in b[1:]) + " dBm"
            elif iid == 201: r.reduced_neighbors += 1; s = f"co-located/neighbor APs advertised ({len(b)} bytes)"
            elif iid == 221 and len(b) >= 3:
                oui = (b[0] << 16) | (b[1] << 8) | b[2]; t = b[3] if len(b) > 3 else -1
                vn = VENDOR_OUIS.get(oui) or lookup.oui_name(oui) or f"{oui:06X}"
                name = f"Vendor: {vn}"
                if oui == 0x0050F2 and t == 1:
                    name = "WPA (legacy)"; r.wpa = parse_rsn(b, 4)
                    if r.wpa: s = f"group {r.wpa.group}; pairwise {'/'.join(r.wpa.pairwise)}; AKM {'/'.join(r.wpa.akms)}"
                elif oui == 0x0050F2 and t == 2:
                    name = "WMM / QoS"; r.wmm = True; s = "WMM " + ("parameters" if len(b) > 4 and b[4] == 1 else "info")
                elif oui == 0x0050F2 and t == 4:
                    name = "WPS"; r.wps = True; o = 4
                    while o + 4 <= len(b):
                        at, al = be16(b, o), be16(b, o + 2)
                        if o + 4 + al > len(b): break
                        v = b[o + 4:o + 4 + al]
                        if at == 0x1044: r.wps_state = "configured" if v[0] == 2 else "not configured"
                        elif at == 0x1047: r.wps_device["UUID"] = v.hex().upper()
                        elif at == 0x1054 and len(v) >= 8: r.wps_device["Device type"] = f"cat {be16(v, 0)}, sub {be16(v, 6)}"
                        elif at == 0x1057 and v and v[0] == 1: r.wps_device["AP setup locked"] = "yes"
                        elif at == 0x1041 and v and v[0] == 1: r.wps_device["Selected registrar"] = "yes (WPS active now)"
                        elif at in WPS_ATTRS:
                            txt = v.decode("utf-8", "replace").strip("\x00 ")
                            if txt: r.wps_device[WPS_ATTRS[at]] = txt
                        o += 4 + al
                    s = "; ".join(([r.wps_state] if r.wps_state else []) + [f"{k}: {v}" for k, v in r.wps_device.items()])
                elif oui == 0x506F9A and t == 0x10:
                    name = "Hotspot 2.0 (Passpoint)"; r.hs20 = True; s = f"release {((b[4] if len(b) > 4 else 0) >> 4) + 1}"
                elif oui == 0x506F9A and t == 0x1C:
                    name = "OWE transition"; r.owe_transition = True; s = "paired with an open/OWE network"
                elif oui == 0x506F9A and t == 0x09: name = "Wi-Fi Direct (P2P)"; s = "P2P group owner / device"
                elif oui == 0x506F9A and t in (0x1A, 0x1B): name = "Multi-AP (EasyMesh)"; s = "EasyMesh"
                else:
                    if vn not in r.vendors: r.vendors.append(vn)
                    s = f"type {t}, {len(b)} bytes"
            elif iid == 255:
                ext = ext_id; e = b
                name = EXT_NAMES.get(ext, f"Extension {ext}")
                if ext == 35:
                    r.he = True; phy0 = e[6]; r.he_streams = _streams(le16(e, 17))
                    w = [n for c, n in ((phy0 & 2, "40 MHz (2.4)"), (phy0 & 4, "40/80 MHz (5/6)"), (phy0 & 8, "160 MHz"), (phy0 & 16, "80+80 MHz")) if c]
                    s = f"{r.he_streams} stream(s), " + ", ".join(w)
                elif ext == 36:
                    p = e[0] | (e[1] << 8) | (e[2] << 16)
                    r.bss_color = e[3] & 0x3F
                    o = 6
                    if p & (1 << 14): o += 3
                    if p & (1 << 15): o += 1
                    s6 = ""
                    if p & (1 << 17) and o + 5 <= len(e):
                        pc = e[o]; w = {0: 20, 1: 40, 2: 80}.get(e[o + 1] & 3, 160)
                        c1 = e[o + 3]; center = c1 if (w == 160 and c1 != 0) else e[o + 2]
                        r.he_op_6g = (pc, w, center); s6 = f", 6 GHz primary ch {pc}, {w} MHz, center ch {center}"
                    s = f"BSS color {r.bss_color}{s6}"
                elif ext == 106:
                    if e[0] & 1 and len(e) >= 8:
                        r.eht_width = {0: 20, 1: 40, 2: 80, 3: 160, 4: 320}.get(e[5] & 7)
                        s = f"EHT width {r.eht_width} MHz, center ch {e[7] or e[6]}"
                    else:
                        s = "EHT operating on the HT/VHT/HE channel"
                    r.eht = True
                elif ext == 108: r.eht = True; s = "802.11be (Wi-Fi 7) capabilities"
                elif ext == 107:
                    if len(e) >= 9 and (e[0] & 7) == 0:
                        r.mld_mac = ":".join(f"{x:02x}" for x in e[3:9]); s = f"MLD address {r.mld_mac}"
                    else:
                        s = "multi-link element"
                else:
                    s = f"{len(e)} bytes"
            else:
                s = f"{len(b)} bytes"
        except Exception:
            pass
        r.items.append(Ie(iid, ext, name, s, hexs(b, 64)))
    return r


def security(ie: IeInfo | None, privacy: bool = False) -> str:
    akm = set(ie.rsn.akm_ids) if ie and ie.rsn else set()
    has_rsn = bool(ie and ie.rsn)
    if 18 in akm: return "Enhanced Open (OWE, transition)" if ie.owe_transition else "Enhanced Open (OWE)"
    if 12 in akm: return "WPA3-Enterprise 192-bit"
    if akm & {8, 24} and akm & {2, 6}: return "WPA2/WPA3-Personal (transition)"
    if akm & {8, 24, 9}: return "WPA3-Personal (SAE)"
    if akm & {1, 3, 5} and ie.rsn.mfp_required and 5 in akm: return "WPA3-Enterprise"
    if has_rsn and akm & {1, 3, 5}: return "WPA2-Enterprise (802.1X)"
    if has_rsn and ie.wpa: return "WPA/WPA2-Personal (mixed)"
    if has_rsn: return "WPA2-Personal (PSK)"
    if ie and ie.wpa: return "WPA-Enterprise (legacy)" if ie.wpa.akm_ids and 1 in ie.wpa.akm_ids else "WPA-Personal (legacy, weak)"
    if privacy: return "WEP (insecure)"
    return "Open (no encryption)"
