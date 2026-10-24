"""Unknown-tracker detection (same classification as the Android app). The PC has no GPS, so the
'following you' rule is time-based: an unknown tracker that is separated from its owner and keeps
showing up near this PC for a long time (or across several days) is flagged."""
from __future__ import annotations

import os
import sqlite3
import threading
import time
from dataclasses import dataclass

APPLE, CHIPOLO = 0x004C, 0x08C3


@dataclass
class TrackerHit:
    id: str
    type: str
    family: str
    separated: bool | None
    detail: str
    payload: str | None


def find_my(addr: str, d: bytes) -> TrackerHit | None:
    i = 0
    while i + 1 < len(d):
        t, l = d[i], d[i + 1]
        if t == 0 and l == 0: break
        if t == 0x12:
            v = d[i + 2:i + 2 + l]
            st = v[0] if v else 0
            kind = {1: "AirTag", 2: "Find My accessory", 3: "AirPods (Find My)"}.get((st >> 4) & 3, "Apple device (Find My)")
            batt = ["full", "medium", "low", "critically low"][(st >> 6) & 3]
            sep = l >= 25
            return TrackerHit(f"FM-{addr}", kind, "apple", sep,
                              f"Separated from owner (full key broadcast) · battery {batt}" if sep else "Owner nearby (short form – address rotates ~15 min)",
                              v[1:7].hex().upper() if sep else None)
        if l == 0: break
        i += 2 + l
    return None


def classify(addr: str, manu: dict, svc: dict, uuids16: set) -> TrackerHit | None:
    if APPLE in manu:
        h = find_my(addr, manu[APPLE])
        if h: return h
    if 0xFD5A in svc:
        d = svc[0xFD5A]
        return TrackerHit(f"SS-{addr}", "Samsung SmartTag", "samsung", None, "SmartTag advertisement" + (f" · state byte 0x{d[0]:02X}" if d else ""), d[:8].hex().upper())
    if 0xFEAA in svc and svc[0xFEAA] and svc[0xFEAA][0] in (0x40, 0x41):
        d = svc[0xFEAA]
        return TrackerHit(f"GF-{addr}", "Google Find My Device tag", "google", d[0] == 0x41,
                          "Find My Device network · unwanted-tracking mode ON (separated from owner)" if d[0] == 0x41 else "Find My Device network · near owner / normal mode", d[1:9].hex().upper())
    if 0xFCB2 in svc:
        return TrackerHit(f"DU-{addr}", "DULT tracker (cross-platform)", "dult", None, "Detecting Unwanted Location Trackers advertisement", svc[0xFCB2][:8].hex().upper())
    tile = {0xFEED, 0xFEEC, 0xFD84}
    if uuids16 & tile or set(svc) & tile or 0x067C in manu:
        return TrackerHit(f"TL-{addr}", "Tile", "tile", None, "Tile tracker", None)
    chip = {0xFE33, 0xFE65}
    if uuids16 & chip or set(svc) & chip or CHIPOLO in manu:
        return TrackerHit(f"CP-{addr}", "Chipolo", "chipolo", None, "Chipolo tracker", None)
    return None


@dataclass
class Rule:
    min_minutes: int = 60      # seen over this long (unknown, separated from owner) ...
    min_days: int = 2          # ... or on this many different days


@dataclass
class Verdict:
    flagged: bool
    reason: str
    span_s: float
    days: int
    sightings: int
    sessions: int


def evaluate(times: list[float], separated: bool | None, trusted: bool, rule: Rule, gap_s: float = 600) -> Verdict:
    ts = sorted(times)
    span = ts[-1] - ts[0] if len(ts) > 1 else 0.0
    days = len({time.strftime("%Y-%m-%d", time.localtime(t)) for t in ts})
    sessions = 1 + sum(1 for a, b in zip(ts, ts[1:]) if b - a > gap_s) if ts else 0
    # longest continuous stretch (sightings no more than gap_s apart)
    longest, start = 0.0, ts[0] if ts else 0.0
    for a, b in zip(ts, ts[1:]):
        if b - a > gap_s: start = b
        longest = max(longest, b - start)
    if trusted:
        return Verdict(False, "Trusted – never alerts", span, days, len(ts), sessions)
    if separated is False:
        return Verdict(False, "Near its owner (owner's phone is close) – not the stalking case", span, days, len(ts), sessions)
    by_time = longest >= rule.min_minutes * 60
    by_days = days >= rule.min_days
    if by_time or by_days:
        why = f"Near this PC for {int(longest // 60)} min in a row" if by_time else f"Seen on {days} different days"
        return Verdict(True, why + (" while separated from its owner" if separated else ""), span, days, len(ts), sessions)
    return Verdict(False, f"{int(longest // 60)} min in a row, {days} day(s) – below alert thresholds", span, days, len(ts), sessions)


def db_path() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~/.local/share")
    d = os.path.join(base, "SignalScanner")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "trackers.db")


class TrackerStore:
    KEEP_DAYS = 7

    def __init__(self, path: str | None = None):
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path or db_path(), check_same_thread=False)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS trackers(id TEXT PRIMARY KEY, type TEXT, family TEXT, detail TEXT, address TEXT, payload TEXT,
                separated INTEGER, first REAL, last REAL, trusted INTEGER DEFAULT 0, alerted REAL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS sightings(id INTEGER PRIMARY KEY AUTOINCREMENT, tracker TEXT, t REAL, rssi INTEGER);
            CREATE INDEX IF NOT EXISTS s_tr ON sightings(tracker);""")
        cut = time.time() - self.KEEP_DAYS * 86400
        self.db.execute("DELETE FROM sightings WHERE t < ?", (cut,))
        self.db.execute("DELETE FROM trackers WHERE last < ? AND trusted = 0", (cut,))
        self.db.commit()
        self.last_rec: dict[str, float] = {}
        self.live: dict[str, tuple[int, float]] = {}

    def record(self, h: TrackerHit, addr: str, rssi: int, bonded: bool, now: float | None = None) -> bool:
        now = now or time.time()
        self.live[h.id] = (rssi, now)
        if now - self.last_rec.get(h.id, 0) < 60:
            return False
        self.last_rec[h.id] = now
        with self.lock:
            row = self.db.execute("SELECT first, trusted, alerted FROM trackers WHERE id=?", (h.id,)).fetchone()
            first, trusted, alerted = (row if row else (now, 0, 0))
            self.db.execute("INSERT OR REPLACE INTO trackers VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                            (h.id, h.type, h.family, h.detail, addr, h.payload, None if h.separated is None else int(h.separated), first, now, int(trusted or bonded), alerted))
            self.db.execute("INSERT INTO sightings(tracker, t, rssi) VALUES (?,?,?)", (h.id, now, rssi))
            self.db.commit()
        return True

    def all(self, rule: Rule) -> list[dict]:
        out = []
        with self.lock:
            rows = self.db.execute("SELECT id, type, family, detail, address, payload, separated, first, last, trusted, alerted FROM trackers ORDER BY last DESC").fetchall()
            for r in rows:
                s = self.db.execute("SELECT t, rssi FROM sightings WHERE tracker=? ORDER BY t", (r[0],)).fetchall()
                sep = None if r[6] is None else bool(r[6])
                v = evaluate([x[0] for x in s] or [r[7]], sep, bool(r[9]), rule)
                out.append(dict(id=r[0], type=r[1], family=r[2], detail=r[3], address=r[4], payload=r[5], separated=sep, first=r[7], last=r[8],
                                trusted=bool(r[9]), alerted=r[10], verdict=v, sightings=s, live=self.live.get(r[0])))
        now = time.time()
        # owner-nearby Find My items rotate addresses every ~15 min; hide stale ones
        return [t for t in out if t["verdict"].flagged or t["trusted"] or t["separated"] is not False or now - t["last"] < 1800]

    def set_trusted(self, tid: str, v: bool):
        with self.lock:
            self.db.execute("UPDATE trackers SET trusted=?, alerted=0 WHERE id=?", (int(v), tid)); self.db.commit()

    def set_alerted(self, tid: str):
        with self.lock:
            self.db.execute("UPDATE trackers SET alerted=? WHERE id=?", (time.time(), tid)); self.db.commit()

    def forget(self, tid: str):
        with self.lock:
            self.db.execute("DELETE FROM sightings WHERE tracker=?", (tid,)); self.db.execute("DELETE FROM trackers WHERE id=?", (tid,)); self.db.commit()


FIND_HINT = {
    "apple": "This PC can't ring an AirTag. Use an Android phone (Settings → Safety and emergency → Unknown tracker alerts → Scan now → Play sound) or an iPhone (Find My → Items → Identify Found Item). Separated AirTags also beep on their own after a while.",
    "samsung": "Use SmartThings on a Galaxy phone → SmartThings Find → 'Unknown tag search'; it can ring a separated SmartTag.",
    "google": "Use an Android phone: Settings → Safety and emergency → Unknown tracker alerts → Scan now → Play sound.",
    "tile": "Use the Tile app → 'Scan and Secure'. Tiles can't be rung by strangers.",
    "chipolo": "Use an Android phone's Unknown tracker alerts → Scan now (newer Chipolos are on the Google/Apple networks).",
    "dult": "Use an Android phone's Unknown tracker alerts → Scan now, or an iPhone's Find My, to play a sound.",
}
