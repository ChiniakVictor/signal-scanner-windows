"""Native Wi-Fi (wlanapi.dll) via ctypes: trigger scans, read the per-BSSID list with raw IEs, and the current connection."""
from __future__ import annotations

import ctypes
import sys
import time
from ctypes import POINTER, byref, c_ubyte, c_ulong, c_ulonglong, c_ushort, c_void_p, c_wchar, c_long, c_bool, c_int
from ctypes import wintypes as W
from dataclasses import dataclass, field

ERROR_ACCESS_DENIED = 5


class GUID(ctypes.Structure):
    _fields_ = [("Data1", c_ulong), ("Data2", c_ushort), ("Data3", c_ushort), ("Data4", c_ubyte * 8)]


class DOT11_SSID(ctypes.Structure):
    _fields_ = [("uSSIDLength", c_ulong), ("ucSSID", c_ubyte * 32)]


class WLAN_INTERFACE_INFO(ctypes.Structure):
    _fields_ = [("InterfaceGuid", GUID), ("strInterfaceDescription", c_wchar * 256), ("isState", c_int)]


class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
    _fields_ = [("dwNumberOfItems", W.DWORD), ("dwIndex", W.DWORD), ("InterfaceInfo", WLAN_INTERFACE_INFO * 1)]


class WLAN_RATE_SET(ctypes.Structure):
    _fields_ = [("uRateSetLength", c_ulong), ("usRateSet", c_ushort * 126)]


class WLAN_BSS_ENTRY(ctypes.Structure):
    _fields_ = [("dot11Ssid", DOT11_SSID), ("uPhyId", c_ulong), ("dot11Bssid", c_ubyte * 6), ("dot11BssType", c_int), ("dot11BssPhyType", c_int),
                ("lRssi", c_long), ("uLinkQuality", c_ulong), ("bInRegDomain", c_ubyte), ("usBeaconPeriod", c_ushort), ("ullTimestamp", c_ulonglong),
                ("ullHostTimestamp", c_ulonglong), ("usCapabilityInformation", c_ushort), ("ulChCenterFrequency", c_ulong),
                ("wlanRateSet", WLAN_RATE_SET), ("ulIeOffset", c_ulong), ("ulIeSize", c_ulong)]


class WLAN_BSS_LIST(ctypes.Structure):
    _fields_ = [("dwTotalSize", W.DWORD), ("dwNumberOfItems", W.DWORD), ("wlanBssEntries", WLAN_BSS_ENTRY * 1)]


class WLAN_ASSOCIATION_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("dot11Ssid", DOT11_SSID), ("dot11BssType", c_int), ("dot11Bssid", c_ubyte * 6), ("dot11PhyType", c_int), ("uDot11PhyIndex", c_ulong),
                ("wlanSignalQuality", c_ulong), ("ulRxRate", c_ulong), ("ulTxRate", c_ulong)]


class WLAN_SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("bSecurityEnabled", W.BOOL), ("bOneXEnabled", W.BOOL), ("dot11AuthAlgorithm", c_int), ("dot11CipherAlgorithm", c_int)]


class WLAN_CONNECTION_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("isState", c_int), ("wlanConnectionMode", c_int), ("strProfileName", c_wchar * 256),
                ("wlanAssociationAttributes", WLAN_ASSOCIATION_ATTRIBUTES), ("wlanSecurityAttributes", WLAN_SECURITY_ATTRIBUTES)]


PHY = {1: "FHSS", 2: "DSSS", 3: "IR", 4: "802.11a (OFDM)", 5: "802.11b (HR-DSSS)", 6: "802.11g (ERP)", 7: "802.11n (HT)", 8: "802.11ac (VHT)",
       9: "802.11ad (DMG)", 10: "802.11ax (HE)", 11: "802.11be (EHT)"}
AUTH = {1: "Open", 2: "Shared key (WEP)", 3: "WPA-Enterprise", 4: "WPA-Personal", 6: "WPA2-Enterprise", 7: "WPA2-Personal", 8: "WPA3-Enterprise 192",
        9: "WPA3-Personal (SAE)", 10: "OWE", 11: "WPA3-Enterprise"}
CIPHER = {0: "none", 1: "WEP-40", 2: "TKIP", 4: "CCMP", 5: "WEP-104", 6: "BIP", 8: "GCMP", 9: "GCMP-256", 10: "CCMP-256", 0x100: "WEP"}
STATE = {0: "not ready", 1: "connected", 2: "ad hoc", 3: "disconnecting", 4: "disconnected", 5: "associating", 6: "discovering", 7: "authenticating"}


@dataclass
class Bss:
    ssid: str
    bssid: str
    rssi: int
    link_quality: int
    freq_mhz: int
    phy: str
    beacon_ms: float
    capability: int
    rates: list
    ies: bytes
    host_ts: int            # FILETIME of last beacon/probe response seen by the driver
    in_reg_domain: bool


@dataclass
class Conn:
    state: str
    profile: str = ""
    ssid: str = ""
    bssid: str = ""
    phy: str = ""
    quality: int = 0
    rx_mbps: float = 0.0
    tx_mbps: float = 0.0
    auth: str = ""
    cipher: str = ""
    channel: int | None = None
    rssi: int | None = None


@dataclass
class Iface:
    guid: GUID
    description: str
    state: str


class WlanError(Exception):
    def __init__(self, code, what):
        super().__init__(f"{what} failed (error {code})")
        self.code = code


class Wlan:
    def __init__(self):
        if sys.platform != "win32":
            raise WlanError(-1, "WlanAPI (Windows only)")
        self.api = ctypes.WinDLL("wlanapi.dll")
        self.h = W.HANDLE()
        ver = W.DWORD()
        rc = self.api.WlanOpenHandle(2, None, byref(ver), byref(self.h))
        if rc: raise WlanError(rc, "WlanOpenHandle")
        self.api.WlanFreeMemory.argtypes = [c_void_p]

    def close(self):
        if self.h:
            self.api.WlanCloseHandle(self.h, None); self.h = None

    def interfaces(self) -> list[Iface]:
        p = POINTER(WLAN_INTERFACE_INFO_LIST)()
        rc = self.api.WlanEnumInterfaces(self.h, None, byref(p))
        if rc: raise WlanError(rc, "WlanEnumInterfaces")
        try:
            n = p.contents.dwNumberOfItems
            arr = ctypes.cast(ctypes.addressof(p.contents.InterfaceInfo), POINTER(WLAN_INTERFACE_INFO * n)).contents if n else []
            return [Iface(GUID.from_buffer_copy(i.InterfaceGuid), i.strInterfaceDescription, STATE.get(i.isState, str(i.isState))) for i in arr]
        finally:
            self.api.WlanFreeMemory(p)

    def scan(self, iface: Iface) -> int:
        return self.api.WlanScan(self.h, byref(iface.guid), None, None, None)

    def bss_list(self, iface: Iface) -> list[Bss]:
        p = POINTER(WLAN_BSS_LIST)()
        rc = self.api.WlanGetNetworkBssList(self.h, byref(iface.guid), None, 3, False, None, byref(p))
        if rc: raise WlanError(rc, "WlanGetNetworkBssList")
        out = []
        try:
            n = p.contents.dwNumberOfItems
            base = ctypes.addressof(p.contents.wlanBssEntries)
            size = ctypes.sizeof(WLAN_BSS_ENTRY)
            for k in range(n):
                addr = base + k * size
                e = WLAN_BSS_ENTRY.from_address(addr)
                ies = ctypes.string_at(addr + e.ulIeOffset, e.ulIeSize) if e.ulIeSize else b""
                ssid = bytes(e.dot11Ssid.ucSSID[:e.dot11Ssid.uSSIDLength]).decode("utf-8", "replace")
                rates = sorted({(e.wlanRateSet.usRateSet[i] & 0x7FFF) / 2 for i in range(min(126, e.wlanRateSet.uRateSetLength // 2))})
                out.append(Bss(ssid, ":".join(f"{x:02x}" for x in e.dot11Bssid), e.lRssi, e.uLinkQuality, e.ulChCenterFrequency // 1000,
                               PHY.get(e.dot11BssPhyType, str(e.dot11BssPhyType)), e.usBeaconPeriod * 1.024, e.usCapabilityInformation, rates, ies,
                               e.ullHostTimestamp, bool(e.bInRegDomain)))
        finally:
            self.api.WlanFreeMemory(p)
        return out

    def _query(self, iface, opcode, ctype):
        size = W.DWORD(); data = c_void_p(); vt = c_int()
        rc = self.api.WlanQueryInterface(self.h, byref(iface.guid), opcode, None, byref(size), byref(data), byref(vt))
        if rc: return None, rc
        try:
            return ctype.from_buffer_copy(ctypes.string_at(data.value, ctypes.sizeof(ctype))), 0
        finally:
            self.api.WlanFreeMemory(data)

    def connection(self, iface: Iface) -> Conn:
        st = iface.state
        ca, rc = self._query(iface, 7, WLAN_CONNECTION_ATTRIBUTES)
        if ca is None:
            if rc == ERROR_ACCESS_DENIED: raise WlanError(rc, "WlanQueryInterface")
            return Conn(st)
        a = ca.wlanAssociationAttributes; s = ca.wlanSecurityAttributes
        ch, _ = self._query(iface, 8, c_ulong)
        rs, _ = self._query(iface, 0x10000102, c_long)
        return Conn(STATE.get(ca.isState, st), ca.strProfileName, bytes(a.dot11Ssid.ucSSID[:a.dot11Ssid.uSSIDLength]).decode("utf-8", "replace"),
                    ":".join(f"{x:02x}" for x in a.dot11Bssid), PHY.get(a.dot11PhyType, str(a.dot11PhyType)), a.wlanSignalQuality,
                    a.ulRxRate / 1000, a.ulTxRate / 1000, AUTH.get(s.dot11AuthAlgorithm, str(s.dot11AuthAlgorithm)),
                    CIPHER.get(s.dot11CipherAlgorithm, str(s.dot11CipherAlgorithm)), ch.value if ch is not None else None, rs.value if rs is not None else None)


def location_state() -> dict:
    """Windows 11 24H2+ only gives apps Wi-Fi scan data when Location services (and desktop-app access) are on."""
    out = {"system": None, "user": None, "desktop": None}
    if sys.platform != "win32": return out
    import winreg
    base = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
    for key, root, sub in (("system", winreg.HKEY_LOCAL_MACHINE, base), ("user", winreg.HKEY_CURRENT_USER, base), ("desktop", winreg.HKEY_CURRENT_USER, base + r"\NonPackaged")):
        try:
            with winreg.OpenKey(root, sub) as k:
                out[key] = winreg.QueryValueEx(k, "Value")[0]
        except OSError:
            pass
    return out
