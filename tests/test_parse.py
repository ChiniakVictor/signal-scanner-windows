import sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from sigscan import wifiparse as wp, btparse as bp, trackers as tr, lookup

lookup.load()

def ie(i, body): return bytes([i, len(body)]) + body

def test_channels():
    assert wp.channel_of(2412) == 1 and wp.channel_of(5745) == 149 and wp.channel_of(5955) == 1 and wp.channel_of(2484) == 14
    assert wp.band(6115) == "6 GHz" and wp.freq_of(149, "5 GHz") == 5745

def test_ies():
    rsn = bytes([1, 0, 0, 0x0F, 0xAC, 4, 1, 0, 0, 0x0F, 0xAC, 4, 2, 0, 0, 0x0F, 0xAC, 2, 0, 0x0F, 0xAC, 8, 0x80, 0])
    raw = ie(0, b"Hilltop") + ie(1, bytes([0x82, 0x84, 0x8B, 0x96])) + ie(3, bytes([6])) + ie(48, rsn) + ie(11, bytes([5, 0, 128, 0, 0])) \
        + ie(45, bytes([0x6F, 0, 0x17, 0xFF, 0xFF, 0, 0] + [0] * 19)) + ie(61, bytes([149, 0x05, 0, 0, 0] + [0] * 17)) \
        + ie(191, bytes([0x32, 0, 0, 0, 0xFA, 0xFF, 0xFA, 0xFF, 0, 0, 0, 0])) + ie(192, bytes([1, 155, 0, 0, 0])) \
        + ie(221, bytes([0x00, 0x50, 0xF2, 4, 0x10, 0x44, 0, 1, 2, 0x10, 0x21, 0, 3]) + b"GE ") + ie(7, b"US " + bytes([1, 11, 30]))
    r = wp.parse_ies(raw)
    assert r.ssid == "Hilltop" and r.ds_channel == 6 and r.station_count == 5 and r.channel_util == 50
    assert r.ht_streams == 2 and r.vht_streams == 2 and r.vht_width == 80 and r.vht_center0 == 155
    assert wp.security(r) == "WPA2/WPA3-Personal (transition)", wp.security(r)
    assert r.wps and r.wps_state == "configured" and r.wps_device.get("Manufacturer") == "GE"
    assert wp.standard(r, 5745)[1] == "Wi-Fi 5"
    assert wp.width_and_center(r, 5745) == (80, 5775)
    assert r.country == "US" and r.max_tx_power == 30
    assert wp.max_rate(5, 80, 2) == 866.6

def test_he_6g():
    he_op = bytes([255, 1 + 6 + 5, 36]) + bytes([0, 0, 0x02, 5, 0, 0]) + bytes([37, 2, 39, 0, 0])
    r = wp.parse_ies(he_op)
    assert r.he_op_6g == (37, 80, 39) and wp.width_and_center(r, 6135) == (80, 6145)

def test_ble():
    d = bp.decode_manufacturer(0x004C, bytes([0x10, 0x05, 0x03, 0x18, 0x1, 0x2, 0x3, 0x12, 0x02, 0x00, 0x01]))
    assert d.title == "Find My (owner nearby)" and any("Nearby Info" in x for x in d.lines)
    assert bp.decode_manufacturer(0x0006, bytes([0x01, 0x09, 0x20, 0x02])).lines[0] == "Device: Windows 10/11 desktop"
    assert bp.decode_service(0xFEAA, bytes([0x41, 1, 2])).title == "Google Find My Device tag"
    assert bp.uuid16_of("0000feaa-0000-1000-8000-00805f9b34fb") == 0xFEAA
    assert "Apple" in (lookup.company(0x004C) or "")

def test_tracker_classify():
    key = bytes(range(1, 23))
    h = tr.classify("C1:22:33:44:55:66", {0x004C: bytes([0x12, 0x19, 0x10]) + key + bytes([0, 0])}, {}, set())
    assert h.type == "AirTag" and h.separated is True and h.payload == "010203040506"
    assert tr.classify("A", {0x004C: bytes([0x12, 0x02, 0x00, 0x01])}, {}, set()).separated is False
    assert tr.classify("A", {}, {0xFD5A: b"\x42\x01"}, set()).family == "samsung"
    assert tr.classify("A", {}, {}, {0xFEED}).family == "tile"
    assert tr.classify("A", {}, {}, {0xFE33}).family == "chipolo"
    assert tr.classify("A", {}, {0xFE2C: b"\x01\x02\x03"}, set()) is None

def test_tracker_rule():
    t0 = time.mktime((2026, 10, 8, 12, 0, 0, 0, 0, -1)); rule = tr.Rule()
    mins = lambda *m: [t0 + x * 60 for x in m]
    assert not tr.evaluate(mins(0, 10, 20), True, False, rule).flagged
    assert tr.evaluate(mins(*range(0, 66, 5)), True, False, rule).flagged
    assert not tr.evaluate(mins(0, 30, 61), True, False, rule).flagged   # gaps > 10 min aren't continuous
    assert not tr.evaluate(mins(*range(0, 66, 5)), False, False, rule).flagged        # owner nearby
    assert not tr.evaluate(mins(*range(0, 66, 5)), True, True, rule).flagged          # trusted
    assert tr.evaluate([t0, t0 + 86400], None, False, rule).flagged           # two days
    assert not tr.evaluate([t0, t0 + 86400], None, False, tr.Rule(min_days=3)).flagged

def test_store(tmp_path=None):
    import tempfile
    p = os.path.join(tempfile.mkdtemp(), "t.db")
    s = tr.TrackerStore(p)
    h = tr.TrackerHit("FM-X", "AirTag", "apple", True, "sep", "01")
    t0 = time.time() - 4000
    for i in range(0, 70, 5): s.record(h, "X", -60, False, now=t0 + i * 60)
    rows = s.all(tr.Rule())
    assert rows[0]["verdict"].flagged and len(rows[0]["sightings"]) == 14
    s.set_trusted("FM-X", True)
    assert not s.all(tr.Rule())[0]["verdict"].flagged

if __name__ == "__main__":
    n = 0
    for k, f in list(globals().items()):
        if k.startswith("test_"): f(); n += 1
    print(n, "tests passed")
