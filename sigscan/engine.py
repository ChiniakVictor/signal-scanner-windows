"""Background scanners: Wi-Fi (WlanAPI) and Bluetooth (bleak/WinRT). Everything stays on this PC."""
from __future__ import annotations

import asyncio
import json
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field

from . import btparse, lookup, trackers, wifiparse as wp
from .settings import Settings, log

NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0
FILETIME_EPOCH = 116444736000000000


def ft_to_unix(ft: int) -> float:
    return (ft - FILETIME_EPOCH) / 1e7 if ft else 0.0


def run(cmd: list[str], timeout=20) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, creationflags=NO_WINDOW)
        for enc in ("utf-8", "mbcs" if sys.platform == "win32" else "latin-1"):
            try: return r.stdout.decode(enc)
            except Exception: pass
    except Exception as e:
        log(f"run {cmd[0]}: {e}")
    return ""


# ----------------------------------------------------------------------------------------- Wi-Fi
@dataclass
class Ap:
    bssid: str
    ssid: str = ""
    vendor: str | None = None
    rssi: int = -100
    freq: int = 0
    channel: int = 0
    band: str = ""
    width: int = 20
    center: int = 0
    std: int = 1
    std_short: str = ""
    std_long: str = ""
    phy: str = ""
    security: str = ""
    ie: wp.IeInfo | None = None
    beacon_ms: float = 0
    rates: list = field(default_factory=list)
    link_quality: int = 0
    first_seen: float = 0
    last_seen: float = 0
    last_beacon: float = 0
    history: list = field(default_factory=list)   # (t, rssi)
    connected: bool = False

    @property
    def hidden(self): return not self.ssid

    @property
    def max_rate(self): return wp.max_rate(self.std, self.width, self.ie.streams if self.ie else 1)

    @property
    def distance(self): return wp.distance_m(self.rssi, self.freq) if self.freq else None


@dataclass
class WifiState:
    adapter: str = ""
    adapter_state: str = ""
    error: str | None = None
    location_blocked: bool = False
    last_scan: float = 0
    last_results: float = 0
    scans: int = 0
    conn: object = None


class WifiWorker(threading.Thread):
    def __init__(self, settings: Settings):
        super().__init__(daemon=True, name="wifi")
        self.s = settings
        self.lock = threading.Lock()
        self.aps: dict[str, Ap] = {}
        self.state = WifiState()
        self.stop_ev = threading.Event()
        self.wake = threading.Event()
        self.paused = False

    def run(self):
        try:
            from .wlan import Wlan, WlanError
            wl = Wlan()
        except Exception as e:
            self.state.error = f"Wi-Fi API unavailable: {e}"; return
        while not self.stop_ev.is_set():
            if not self.paused:
                try:
                    self.cycle(wl)
                except Exception as e:
                    code = getattr(e, "code", None)
                    self.state.location_blocked = code == 5
                    self.state.error = ("Windows blocks Wi-Fi scan data while Location services is off" if code == 5 else str(e))
                    log(f"wifi: {e}")
            self.wake.wait(max(5, self.s.wifi_interval) - 4.5); self.wake.clear()
        wl.close()

    def cycle(self, wl):
        ifs = wl.interfaces()
        if not ifs:
            self.state.error = "No Wi-Fi adapter"; return
        i = ifs[0]
        self.state.adapter, self.state.adapter_state = i.description, i.state
        rc = wl.scan(i)
        self.state.last_scan = time.time(); self.state.scans += 1
        if self.stop_ev.wait(4.5): return
        bss = wl.bss_list(i)
        conn = wl.connection(i)
        now = time.time()
        with self.lock:
            for b in bss:
                a = self.aps.get(b.bssid) or Ap(b.bssid, first_seen=now)
                ie = wp.parse_ies(b.ies) if b.ies else wp.IeInfo()
                a.ssid = b.ssid or (ie.ssid or ""); a.vendor = lookup.vendor(b.bssid); a.freq = b.freq_mhz
                a.channel = wp.channel_of(b.freq_mhz) or (ie.ds_channel or 0); a.band = wp.band(b.freq_mhz)
                a.width, a.center = wp.width_and_center(ie, b.freq_mhz)
                a.std, a.std_short, a.std_long = wp.standard(ie, b.freq_mhz)
                a.phy = b.phy; a.security = wp.security(ie, bool(b.capability & 0x10)); a.ie = ie
                a.beacon_ms = b.beacon_ms; a.rates = b.rates; a.link_quality = b.link_quality
                lb = ft_to_unix(b.host_ts)
                fresh = lb == 0 or lb > a.last_beacon
                a.last_beacon = lb or now
                if fresh:
                    a.rssi = b.rssi; a.last_seen = now
                    a.history.append((now, b.rssi)); del a.history[:-480]
                a.connected = conn is not None and conn.bssid == b.bssid
                self.aps[b.bssid] = a
            cut = now - self.s.forget_minutes * 60
            for k in [k for k, v in self.aps.items() if v.last_seen < cut]: del self.aps[k]
            self.state.conn = conn
            self.state.last_results = now
            self.state.error = None if bss else "Scan returned no networks"
            self.state.location_blocked = False

    def snapshot(self):
        with self.lock:
            return list(self.aps.values()), self.state


# ------------------------------------------------------------------------------------- Bluetooth
@dataclass
class Dev:
    address: str
    name: str | None = None
    rssi: int | None = None
    tx_power: int | None = None
    addr_type: str | None = None
    connectable: bool | None = None
    first_seen: float = 0
    last_seen: float = 0
    packets: int = 0
    stamps: list = field(default_factory=list)
    history: list = field(default_factory=list)
    manu: dict = field(default_factory=dict)
    svc: dict = field(default_factory=dict)
    uuids: list = field(default_factory=list)
    raw: bytes = b""
    ble: bool = False
    classic: bool = False
    paired: bool = False
    is_connected: bool = False
    cod: int | None = None
    kind: str = ""
    tracker: trackers.TrackerHit | None = None

    @property
    def vendor(self): return lookup.vendor(self.address)

    @property
    def decoded(self) -> list:
        out = []
        for cid, d in self.manu.items():
            x = btparse.decode_manufacturer(cid, d)
            if x: out.append(x)
        for u, d in self.svc.items():
            x = btparse.decode_service(u, d) if isinstance(u, int) else None
            if x: out.append(x)
        return out

    @property
    def tag(self):
        if self.tracker: return self.tracker.type
        d = self.decoded
        if d: return d[0].title
        if self.cod: return btparse.class_of_device(self.cod)
        return None

    @property
    def adv_interval_ms(self):
        s = sorted(self.stamps)
        d = sorted(b - a for a, b in zip(s, s[1:]) if b - a > 0.005)
        return d[len(d) // 4] * 1000 if len(d) >= 4 else None

    @property
    def distance(self):
        if self.rssi is None: return None
        return btparse.distance_m(self.rssi, (self.tx_power - 41) if self.tx_power is not None else -59)


@dataclass
class BtState:
    available: bool = False
    scanning: bool = False
    inquiry: bool = False
    last_inquiry: float = 0
    error: str | None = None
    backend: str = ""


class BtWorker(threading.Thread):
    def __init__(self, settings: Settings, store: trackers.TrackerStore):
        super().__init__(daemon=True, name="bt")
        self.s = settings
        self.store = store
        self.lock = threading.Lock()
        self.devs: dict[str, Dev] = {}
        self.state = BtState()
        self.loop: asyncio.AbstractEventLoop | None = None
        self.paused = False
        self._stop = False
        self.bonded: set[str] = set()

    def run(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self.main())
        except Exception as e:
            self.state.error = str(e); log(f"bt: {e}")

    def stop(self):
        self._stop = True

    async def main(self):
        try:
            from bleak import BleakScanner
        except Exception as e:
            self.state.error = f"Bluetooth library missing: {e}"; return
        scanner = None
        last_inq = 0.0
        inq_task = None
        while not self._stop:
            if self.paused:
                if scanner: await scanner.stop(); scanner = None; self.state.scanning = False
                await asyncio.sleep(1); continue
            if scanner is None:
                try:
                    scanner = BleakScanner(detection_callback=self.on_adv, scanning_mode="active")
                    await scanner.start()
                    self.state.scanning = True; self.state.available = True; self.state.error = None; self.state.backend = "WinRT BluetoothLEAdvertisementWatcher (active)"
                except Exception as e:
                    scanner = None; self.state.scanning = False; self.state.error = f"BLE scan failed: {e}"
                    await asyncio.sleep(10); continue
            if (inq_task is None or inq_task.done()) and time.time() - last_inq > max(30, self.s.bt_interval * 6):
                last_inq = time.time()
                inq_task = asyncio.ensure_future(self.enumerate_classic())
            self.tick()
            await asyncio.sleep(max(1, self.s.bt_interval))
        if scanner:
            try: await scanner.stop()
            except Exception: pass

    def on_adv(self, device, adv):
        now = time.time()
        addr = device.address.upper()
        with self.lock:
            d = self.devs.get(addr) or Dev(addr, first_seen=now)
            d.ble = True; d.last_seen = now; d.packets += 1
            d.rssi = adv.rssi
            d.stamps.append(now); del d.stamps[:-40]
            if adv.local_name: d.name = adv.local_name
            if adv.tx_power is not None: d.tx_power = adv.tx_power
            if adv.manufacturer_data: d.manu.update({k: bytes(v) for k, v in adv.manufacturer_data.items()})
            for u, v in (adv.service_data or {}).items():
                k = btparse.uuid16_of(u); d.svc[k if k is not None else u] = bytes(v)
            for u in adv.service_uuids or []:
                if u not in d.uuids: d.uuids.append(u)
            det = getattr(device, "details", None)
            args = getattr(det, "adv", None) or getattr(det, "scan", None)
            if args is not None:
                try: d.connectable = bool(args.is_connectable)
                except Exception: pass
                try: d.addr_type = "public" if int(args.bluetooth_address_type) == 0 else "random"
                except Exception: pass
                try:
                    raw = b""
                    for sec in args.advertisement.data_sections:
                        b = bytes(sec.data); raw += bytes([len(b) + 1, sec.data_type]) + b
                    if raw: d.raw = raw
                except Exception: pass
            self.devs[addr] = d
            u16 = {btparse.uuid16_of(u) for u in d.uuids} - {None}
            hit = trackers.classify(addr, d.manu, {k: v for k, v in d.svc.items() if isinstance(k, int)}, u16)
            d.tracker = hit
        if hit:
            try: self.store.record(hit, addr, adv.rssi, addr in self.bonded)
            except Exception as e: log(f"tracker db: {e}")

    def tick(self):
        now = time.time()
        with self.lock:
            for d in self.devs.values():
                if d.rssi is not None and now - d.last_seen < self.s.bt_interval + 1:
                    d.history.append((now, d.rssi)); del d.history[:-720]
            cut = now - self.s.forget_minutes * 60
            for k in [k for k, v in self.devs.items() if v.last_seen < cut and not v.paired]: del self.devs[k]

    async def enumerate_classic(self):
        try:
            from winrt.windows.devices.bluetooth import BluetoothDevice, BluetoothLEDevice
            from winrt.windows.devices.enumeration import DeviceInformation, DeviceInformationKind
        except Exception as e:
            self.state.error = f"WinRT Bluetooth unavailable: {e}"; return
        found = []   # (DeviceInformation, paired, le)
        for cls, le in ((BluetoothDevice, False), (BluetoothLEDevice, True)):
            try:
                infos = await DeviceInformation.find_all_async_aqs_filter(cls.get_device_selector_from_pairing_state(True))
                found += [(i, True, le) for i in infos]
            except Exception as e:
                log(f"paired enum ({'LE' if le else 'classic'}): {e}")
        if self.s.classic_inquiry:
            # Classic inquiry: an association-endpoint watcher with IssueInquiry, stopped after ~12 s.
            self.state.inquiry = True
            seen = {}
            try:
                aqs = ('System.Devices.Aep.ProtocolId:="{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}" AND '
                       'System.Devices.Aep.IsPaired:=System.StructuredQueryType.Boolean#False AND '
                       'System.Devices.Aep.Bluetooth.IssueInquiry:=System.StructuredQueryType.Boolean#True')
                props = ["System.Devices.Aep.DeviceAddress", "System.Devices.Aep.SignalStrength", "System.Devices.Aep.Bluetooth.Cod.Major", "System.Devices.Aep.Bluetooth.Cod.Minor"]
                w = DeviceInformation.create_watcher_with_kind_aqs_filter_and_additional_properties(aqs, props, DeviceInformationKind.ASSOCIATION_ENDPOINT)
                def added(_w, info): seen[info.id] = info
                tok = w.add_added(added)
                w.start()
                await asyncio.sleep(12)
                try: w.stop()
                except Exception: pass
                try: w.remove_added(tok)
                except Exception: pass
                now = time.time()
                for info in list(seen.values()):
                    try:
                        p = info.properties
                        addr = str(p.lookup("System.Devices.Aep.DeviceAddress") or "").upper()
                        if not addr: continue
                        rssi = p.lookup("System.Devices.Aep.SignalStrength") if p.has_key("System.Devices.Aep.SignalStrength") else None
                        mj = p.lookup("System.Devices.Aep.Bluetooth.Cod.Major") if p.has_key("System.Devices.Aep.Bluetooth.Cod.Major") else None
                        mn = p.lookup("System.Devices.Aep.Bluetooth.Cod.Minor") if p.has_key("System.Devices.Aep.Bluetooth.Cod.Minor") else None
                        cod = ((int(mj) & 0x1F) << 8) | ((int(mn or 0) & 0x3F) << 2) if mj is not None else None
                        with self.lock:
                            d = self.devs.get(addr) or Dev(addr, first_seen=now)
                            d.classic = True; d.name = info.name or d.name; d.last_seen = now
                            if cod is not None: d.cod = int(cod)
                            if rssi is not None: d.rssi = int(rssi)
                            self.devs[addr] = d
                    except Exception as e:
                        log(f"inquiry dev: {e}")
            except Exception as e:
                log(f"inquiry: {e!r}")
            self.state.inquiry = False; self.state.last_inquiry = time.time()
        now = time.time()
        bonded = set()
        for info, paired, le in found:
            try:
                bd = await (BluetoothLEDevice if le else BluetoothDevice).from_id_async(info.id)
                if bd is None: continue
                a = bd.bluetooth_address
                addr = ":".join(f"{(a >> (8 * k)) & 0xFF:02X}" for k in range(5, -1, -1))
                with self.lock:
                    d = self.devs.get(addr) or Dev(addr, first_seen=now)
                    if le: d.ble = True
                    else:
                        d.classic = True
                        d.cod = bd.class_of_device.raw_value
                    d.name = bd.name or info.name or d.name
                    d.is_connected = int(bd.connection_status) == 1
                    d.paired = True
                    if d.is_connected: d.last_seen = now
                    self.devs[addr] = d
                bonded.add(addr)
                try: bd.close()
                except Exception: pass
            except Exception as e:
                log(f"paired dev: {e!r}")
        if bonded: self.bonded = bonded

    def snapshot(self):
        with self.lock:
            return list(self.devs.values()), self.state


# ---------------------------------------------------------------------------------------- Radios
PS_INFO = r"""
$o = @{}
$bt = Get-PnpDevice -Class Bluetooth -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -like 'USB\*' -or $_.InstanceId -like 'PCI\*' } | Select-Object -First 1
if ($bt) {
  $o.bt_name = $bt.FriendlyName
  $p = Get-PnpDeviceProperty -InstanceId $bt.InstanceId -ErrorAction SilentlyContinue
  foreach ($x in $p) {
    if ($x.KeyName -like '{A92F26CA-EDA7-4B1D-9DB2-27B68AA5A2EB}*') { $o['bt_' + $x.KeyName.Split(' ')[-1]] = "$($x.Data)" }
    if ($x.KeyName -eq 'DEVPKEY_Device_DriverVersion') { $o.bt_driver = "$($x.Data)" }
    if ($x.KeyName -eq 'DEVPKEY_Device_Manufacturer') { $o.bt_maker = "$($x.Data)" }
    if ($x.KeyName -eq 'DEVPKEY_Device_DriverDate') { $o.bt_driver_date = "$($x.Data)" }
  }
}
$nfc = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.Class -eq 'Proximity' -or $_.FriendlyName -match 'NFC|Near Field' }
$o.nfc = @($nfc | ForEach-Object { $_.FriendlyName })
$o | ConvertTo-Json -Compress
"""
LMP = {6: "4.0", 7: "4.1", 8: "4.2", 9: "5.0", 10: "5.1", 11: "5.2", 12: "5.3", 13: "5.4", 14: "6.0"}


def kv_lines(text: str) -> list[tuple[str, str]]:
    out = []
    for line in text.splitlines():
        m = re.match(r"\s*([^:]{2,60}?)\s+:\s(.*)$", line)
        if m: out.append((m.group(1).strip(), m.group(2).strip()))
    return out


def radio_info() -> dict:
    """Collected once at start (a few seconds) in a worker thread."""
    info: dict = {"wifi_driver": [], "wifi_caps": [], "bt": [], "nfc": [], "radios": []}
    if sys.platform != "win32": return info
    info["wifi_driver"] = [x for x in kv_lines(run(["netsh", "wlan", "show", "drivers"])) if x[0] not in ("Interface name",)]
    info["wifi_caps"] = kv_lines(run(["netsh", "wlan", "show", "wirelesscapabilities"]))
    try:
        j = json.loads(run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", PS_INFO], 40) or "{}")
    except Exception:
        j = {}
    bt = []
    if j.get("bt_name"):
        bt.append(("Adapter", j["bt_name"]))
        if j.get("bt_maker"): bt.append(("Maker", j["bt_maker"]))
        if j.get("bt_2"):
            cid = int(j["bt_2"]); bt.append(("Chip maker (company ID)", f"{lookup.company(cid) or '?'} (0x{cid:04X})"))
        if j.get("bt_4"):
            v = int(j["bt_4"]); bt.append(("Bluetooth version (LMP)", f"{LMP.get(v, '?')} (LMP {v}, subversion {j.get('bt_5', '?')})"))
        if j.get("bt_6"): bt.append(("HCI version", f"{LMP.get(int(j['bt_6']), '?')} (HCI {j['bt_6']}, revision {j.get('bt_7', '?')})"))
        if j.get("bt_1"):
            a = int(j["bt_1"]); bt.append(("Adapter address", ":".join(f"{(a >> (8 * k)) & 0xFF:02X}" for k in range(5, -1, -1))))
        if j.get("bt_driver"): bt.append(("Driver", f"{j['bt_driver']} ({j.get('bt_driver_date', '')})"))
    info["bt"] = bt
    info["nfc_pnp"] = j.get("nfc") or []
    return info


async def winrt_info() -> dict:
    out = {"bt_caps": [], "radios": [], "nfc": None}
    try:
        from winrt.windows.devices.bluetooth import BluetoothAdapter
        ad = await BluetoothAdapter.get_default_async()
        if ad:
            caps = [("Classic (BR/EDR)", ad.is_classic_supported), ("Low Energy", ad.is_low_energy_supported), ("Central role", ad.is_central_role_supported),
                    ("Peripheral role", ad.is_peripheral_role_supported), ("Advertisement offload", ad.is_advertisement_offload_supported)]
            for n, attr in (("LE Secure Connections", "are_low_energy_secure_connections_supported"), ("Extended advertising", "is_extended_advertising_supported"),
                            ("Max advertisement length", "max_advertisement_data_length"),
                            ("LE Coded PHY (long range)", "is_low_energy_coded_phy_supported")):
                try: caps.append((n, getattr(ad, attr)))
                except Exception: pass
            out["bt_caps"] = [(k, ("yes" if v else "no") if isinstance(v, bool) else str(v)) for k, v in caps]
    except Exception as e:
        log(f"bt adapter: {e}")
    try:
        from winrt.windows.devices.radios import Radio
        rs = await Radio.get_radios_async()
        kinds = {0: "Other", 1: "Wi-Fi", 2: "Mobile broadband", 3: "Bluetooth", 4: "FM"}
        states = {0: "unknown", 1: "on", 2: "off", 3: "disabled"}
        out["radios"] = [(r.name if r.name == kinds.get(int(r.kind)) else f"{kinds.get(int(r.kind), r.kind)} ({r.name})", states.get(int(r.state), str(r.state))) for r in rs]
    except Exception as e:
        log(f"radios: {e}")
    try:
        from winrt.windows.networking.proximity import ProximityDevice
        pd = ProximityDevice.get_default()
        out["nfc"] = None if pd is None else {"id": pd.device_id, "bps": pd.bits_per_second, "max_msg": pd.max_message_bytes}
    except Exception as e:
        out["nfc_error"] = str(e)
    return out
