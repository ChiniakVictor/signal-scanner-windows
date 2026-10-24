"""Signal Scanner for Windows: main window."""
from __future__ import annotations

import argparse
import asyncio
import csv
import html
import io
import json
import os
import sys
import threading
import time

from PySide6.QtCore import QPointF, Qt, QTimer, Signal, QObject
from PySide6.QtGui import QAction, QColor, QIcon, QPainter, QPalette, QPen, QPixmap, QPolygonF
from PySide6.QtNetwork import QLocalServer, QLocalSocket
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QDialog, QDialogButtonBox, QFormLayout, QFrame,
                               QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow, QMenu, QMessageBox, QPushButton,
                               QScrollArea, QSpinBox, QSplitter, QStackedWidget, QSystemTrayIcon, QTableWidget,
                               QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget, QButtonGroup)

from . import __version__, btparse, engine, lookup, trackers, wifiparse as wp
from .graph import AMBER as QAMBER, CYAN as QCYAN, ChannelGraph, Sparkline, Timeline, color_for, rssi_color
from .settings import Settings, app_dir, data_dir, log

GREEN = "#3DDC97"; AMBER = "#FFC857"; RED = "#FF6B6B"; ORANGE = "#FFA94D"; BG = "#101418"; CARD = "#171D23"; TEXT = "#E6EAEE"; SUB = "#9AA4AE"
CYAN = "#4DD0E1"; PURPLE = "#B39DFF"

STYLE = f"""
QWidget {{ background:{BG}; color:{TEXT}; font-family:'Segoe UI'; font-size:13px; }}
QFrame#card, QFrame#detail {{ background:{CARD}; border-radius:10px; }}
QFrame#card QLabel, QFrame#detail QLabel, QFrame#card QCheckBox {{ background:transparent; }}
QFrame#banner {{ background:#3A2A12; border-radius:8px; }}
QFrame#banner QLabel {{ background:transparent; }}
QPushButton {{ background:#1F2830; border:1px solid #2C3842; border-radius:8px; padding:6px 12px; }}
QPushButton:hover {{ background:#26323C; }}
QPushButton#primary {{ background:{CYAN}; color:#00252B; border:0; font-weight:700; padding:6px 18px; }}
QPushButton#primary[danger="true"] {{ background:{RED}; color:#1A0000; }}
QPushButton#chip {{ border-radius:14px; padding:5px 14px; }}
QPushButton#chip:checked {{ background:#2E3A45; border-color:{CYAN}; color:{CYAN}; }}
QLineEdit, QComboBox, QSpinBox {{ background:#1F2830; border:1px solid #2C3842; border-radius:6px; padding:5px; }}
QTabWidget::pane {{ border:0; }}
QTabBar::tab {{ background:transparent; color:{SUB}; padding:8px 18px; border-bottom:2px solid transparent; font-weight:600; }}
QTabBar::tab:selected {{ color:{CYAN}; border-bottom:2px solid {CYAN}; }}
QTableWidget {{ background:{CARD}; alternate-background-color:#1B2229; border:0; border-radius:8px; selection-background-color:#1E3440; selection-color:{TEXT}; }}
QHeaderView::section {{ background:{CARD}; color:{SUB}; border:0; padding:6px; font-weight:600; }}
QToolTip {{ background:#202830; color:white; border:1px solid #2C3842; }}
QDialog, QMessageBox, QMenu {{ background:{CARD}; }}
QMenu::item:selected {{ background:#1E3440; }}
QSplitter::handle {{ background:{BG}; width:8px; }}
QScrollArea {{ border:0; }}
QCheckBox {{ spacing:10px; background:transparent; }}
QCheckBox::indicator {{ width:18px; height:18px; border:2px solid #8A98A6; border-radius:4px; background:#1F2830; }}
QCheckBox::indicator:checked {{ background:{GREEN}; border-color:{GREEN}; image:url(__CHECK_SVG__); }}
QScrollBar:vertical {{ background:{BG}; width:10px; }}
QScrollBar::handle:vertical {{ background:#2C3842; border-radius:5px; min-height:30px; }}
QScrollBar:horizontal {{ background:{BG}; height:10px; }}
QScrollBar::handle:horizontal {{ background:#2C3842; border-radius:5px; min-width:30px; }}
"""


def app_icon() -> QIcon:
    pm = QPixmap(256, 256); pm.fill(Qt.transparent)
    p = QPainter(pm); p.setRenderHint(QPainter.Antialiasing)
    p.setBrush(QColor("#0E1A24")); p.setPen(Qt.NoPen); p.drawRoundedRect(8, 8, 240, 240, 48, 48)
    for i, r in enumerate((40, 72, 104)):
        pen = QPen(QColor(CYAN if i < 2 else GREEN), 14); pen.setCapStyle(Qt.RoundCap); p.setPen(pen); p.setBrush(Qt.NoBrush)
        p.drawArc(128 - r, 150 - r, 2 * r, 2 * r, 45 * 16, 90 * 16)
    p.setPen(Qt.NoPen); p.setBrush(QColor(TEXT)); p.drawEllipse(QPointF(128, 150), 14, 14)
    for k, hgt in enumerate((30, 50, 70)):
        p.setBrush(QColor(AMBER)); p.drawRoundedRect(150 + k * 22, 214 - hgt, 14, hgt, 4, 4)
    p.end()
    return QIcon(pm)


def _check_svg_path() -> str:
    base = os.path.join(app_dir(), "check")
    for scale, suffix in ((1, ""), (2, "@2x"), (3, "@3x")):
        size = 18 * scale
        pm = QPixmap(size, size); pm.fill(Qt.transparent)
        p = QPainter(pm); p.setRenderHint(QPainter.Antialiasing)
        pen = QPen(QColor("#0B1A12"), 2.6 * scale); pen.setCapStyle(Qt.RoundCap); pen.setJoinStyle(Qt.RoundJoin); p.setPen(pen)
        p.drawPolyline(QPolygonF([QPointF(4 * scale, 9.5 * scale), QPointF(7.5 * scale, 13 * scale), QPointF(14 * scale, 5.5 * scale)]))
        p.end(); pm.save(base + suffix + ".png", "PNG")
    return (base + ".png").replace("\\", "/")


def ago(sec: float) -> str:
    s = int(max(0, sec))
    if s < 60: return f"{s}s"
    if s < 3600: return f"{s // 60}m {s % 60}s"
    if s < 86400: return f"{s // 3600}h {(s % 3600) // 60}m"
    return f"{s // 86400}d {(s % 86400) // 3600}h"


def hm(t: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(t)) if t else "—"


def dt(t: float) -> str:
    return time.strftime("%a %b %d %H:%M:%S", time.localtime(t)) if t else "—"


def section(title: str, rows) -> str:
    rows = [(k, v) for k, v in rows if v not in (None, "", [])]
    if not rows: return ""
    out = [f"<p style='color:{CYAN};font-weight:600;letter-spacing:1px;margin:14px 0 4px 0'>{html.escape(title.upper())}</p><table cellspacing=0 cellpadding=2>"]
    for k, v in rows:
        col = None
        if isinstance(v, tuple): v, col = v
        out.append(f"<tr><td style='color:{SUB};padding-right:16px' valign=top width=190>{html.escape(str(k))}</td>"
                   f"<td{f' style=color:{col}' if col else ''}>{html.escape(str(v))}</td></tr>")
    out.append("</table>")
    return "".join(out)


class Item(QTableWidgetItem):
    def __init__(self, text, sort=None, color=None):
        super().__init__("" if text is None else str(text))
        self.sortv = sort if sort is not None else (str(text).lower() if text is not None else "")
        if color: self.setForeground(QColor(color))

    def __lt__(self, other):
        try: return self.sortv < other.sortv
        except TypeError: return str(self.sortv) < str(other.sortv)


class ListDetail(QWidget):
    """Search + chips + table on the left, scrollable detail (graph + HTML) on the right."""
    def __init__(self, columns, chips, placeholder, empty_text, sort_col=3):
        super().__init__()
        self.sort_col = sort_col
        self.sel_key = None
        self._sized = False
        lay = QHBoxLayout(self); lay.setContentsMargins(0, 0, 0, 0)
        split = QSplitter(); lay.addWidget(split)
        left = QWidget(); ll = QVBoxLayout(left); ll.setContentsMargins(0, 0, 0, 0)
        top = QHBoxLayout()
        self.search = QLineEdit(); self.search.setPlaceholderText(placeholder); self.search.setClearButtonEnabled(True)
        top.addWidget(self.search, 1)
        self.chip_group = QButtonGroup(self); self.chip_group.setExclusive(True)
        for i, c in enumerate(chips):
            b = QPushButton(c); b.setObjectName("chip"); b.setCheckable(True); b.setChecked(i == 0)
            self.chip_group.addButton(b, i); top.addWidget(b)
        self.top = top
        ll.addLayout(top)
        self.header_label = QLabel(); self.header_label.setWordWrap(True); self.header_label.setTextFormat(Qt.RichText)
        ll.addWidget(self.header_label)
        self.stack = QStackedWidget()
        self.table = QTableWidget(0, len(columns)); self.table.setHorizontalHeaderLabels(columns)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows); self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers); self.table.verticalHeader().hide(); self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True); self.table.setShowGrid(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive); self.table.horizontalHeader().setStretchLastSection(True)
        self.table.itemSelectionChanged.connect(self._sel)
        self.stack.addWidget(self.table)
        ll.addWidget(self.stack, 1)
        split.addWidget(left)
        right = QFrame(); right.setObjectName("detail")
        rl = QVBoxLayout(right)
        self.title = QLabel(); self.title.setStyleSheet("font-size:18px;font-weight:700"); self.title.setWordWrap(True)
        self.subtitle = QLabel(); self.subtitle.setStyleSheet(f"color:{SUB}"); self.subtitle.setWordWrap(True)
        self.big = QLabel(); self.big.setStyleSheet("font-size:28px;font-weight:700")
        self.graph = Sparkline(axes=True)
        self.body = QLabel(); self.body.setWordWrap(True); self.body.setTextFormat(Qt.RichText); self.body.setAlignment(Qt.AlignTop)
        self.body.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.buttons = QHBoxLayout()
        inner = QWidget(); il = QVBoxLayout(inner); il.setContentsMargins(4, 4, 8, 4)
        for wdg in (self.title, self.subtitle, self.big, self.graph): il.addWidget(wdg)
        il.addLayout(self.buttons); il.addWidget(self.body); il.addStretch(1)
        self.scroll = QScrollArea(); self.scroll.setWidgetResizable(True); self.scroll.setWidget(inner)
        self.empty = QLabel(empty_text); self.empty.setAlignment(Qt.AlignCenter); self.empty.setStyleSheet(f"color:{SUB}")
        rl.addWidget(self.scroll); rl.addWidget(self.empty)
        split.addWidget(right); split.setSizes([760, 560])
        self.show_detail(False)

    def show_detail(self, on: bool):
        self.scroll.setVisible(on); self.empty.setVisible(not on)

    def chip(self) -> int:
        return self.chip_group.checkedId()

    def _sel(self):
        r = self.table.currentRow()
        it = self.table.item(r, 0) if r >= 0 else None
        if it is not None and it.data(Qt.UserRole):
            self.sel_key = it.data(Qt.UserRole)

    def fill(self, rows):
        """rows: list of (key, [Item...])"""
        t = self.table
        t.setSortingEnabled(False)
        t.blockSignals(True)
        t.setRowCount(len(rows))
        sel_row = -1
        for r, (key, items) in enumerate(rows):
            for c, it in enumerate(items):
                if c == 0: it.setData(Qt.UserRole, key)
                t.setItem(r, c, it)
            if key == self.sel_key: sel_row = r
        t.setSortingEnabled(True)
        if rows and not self._sized:
            self._sized = True
            t.sortItems(self.sort_col, Qt.DescendingOrder)
            t.resizeColumnsToContents()
            for c in range(t.columnCount()): t.setColumnWidth(c, min(max(t.columnWidth(c) + 12, 60), 230))
        if sel_row >= 0:
            for r in range(t.rowCount()):
                if t.item(r, 0).data(Qt.UserRole) == self.sel_key: t.selectRow(r); break
        else:
            t.clearSelection()
        t.blockSignals(False)


class SettingsDialog(QDialog):
    def __init__(self, s: Settings, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings"); self.s = s
        f = QFormLayout(self)
        self.wifi = QSpinBox(); self.wifi.setRange(10, 600); self.wifi.setValue(s.wifi_interval); self.wifi.setSuffix(" s")
        self.bt = QSpinBox(); self.bt.setRange(1, 60); self.bt.setValue(s.bt_interval); self.bt.setSuffix(" s")
        self.inq = QCheckBox("Bluetooth classic discovery (finds non-LE devices, ~10 s inquiry every 30 s)"); self.inq.setChecked(s.classic_inquiry)
        self.forget = QSpinBox(); self.forget.setRange(1, 120); self.forget.setValue(s.forget_minutes); self.forget.setSuffix(" min")
        self.tmin = QSpinBox(); self.tmin.setRange(10, 600); self.tmin.setValue(s.tracker_minutes); self.tmin.setSuffix(" min")
        self.tdays = QSpinBox(); self.tdays.setRange(2, 7); self.tdays.setValue(s.tracker_days); self.tdays.setSuffix(" days")
        f.addRow("Wi-Fi scan every", self.wifi)
        note = QLabel("30 s is a good default: each scan takes ~4 s and briefly pauses Wi-Fi traffic on many adapters."); note.setWordWrap(True); note.setStyleSheet(f"color:{SUB}")
        f.addRow("", note)
        f.addRow("Bluetooth sample every", self.bt)
        f.addRow("", self.inq)
        f.addRow("Forget devices not seen for", self.forget)
        f.addRow("Tracker alert: near this PC for", self.tmin)
        f.addRow("…or seen on", self.tdays)
        bb = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel); bb.accepted.connect(self.accept); bb.rejected.connect(self.reject)
        f.addRow(bb)

    def apply(self):
        s = self.s
        s.wifi_interval, s.bt_interval, s.classic_inquiry = self.wifi.value(), self.bt.value(), self.inq.isChecked()
        s.forget_minutes, s.tracker_minutes, s.tracker_days = self.forget.value(), self.tmin.value(), self.tdays.value()
        s.save()


class Bridge(QObject):
    info = Signal(dict)


class MainWindow(QMainWindow):
    def __init__(self, args):
        super().__init__()
        self.args = args
        self.s = Settings.load()
        lookup.load()
        self.store = trackers.TrackerStore()
        self.wifi = engine.WifiWorker(self.s); self.wifi.start()
        self.bt = engine.BtWorker(self.s, self.store); self.bt.start()
        self.info: dict = {}
        self.bridge = Bridge(); self.bridge.info.connect(self._got_info)
        threading.Thread(target=self._collect_info, daemon=True).start()
        self.setWindowTitle("Signal Scanner"); self.resize(1360, 860)
        self.tray = QSystemTrayIcon(app_icon(), self); self.tray.setToolTip("Signal Scanner"); self.tray.show()
        self.tray.activated.connect(lambda *_: (self.showNormal(), self.raise_(), self.activateWindow()))

        root = QWidget(); v = QVBoxLayout(root); v.setContentsMargins(14, 10, 14, 10)
        head = QHBoxLayout()
        t = QLabel("Signal Scanner"); t.setStyleSheet("font-size:20px;font-weight:700"); head.addWidget(t)
        self.status = QLabel(); self.status.setStyleSheet(f"color:{SUB}"); head.addWidget(self.status, 1)
        self.pause_btn = QPushButton("Pause"); self.pause_btn.setObjectName("primary"); self.pause_btn.clicked.connect(self.toggle_pause)
        exp = QPushButton("Export ▾"); m = QMenu(exp)
        for label, kind in (("Wi-Fi (CSV)", "wifi"), ("Bluetooth (CSV)", "bt"), ("Trackers (CSV)", "trackers"), ("Everything (JSON)", "json")):
            a = QAction(label, m); a.triggered.connect(lambda _=False, k=kind: self.export(k)); m.addAction(a)
        exp.setMenu(m)
        st = QPushButton("Settings"); st.clicked.connect(self.open_settings)
        for b in (self.pause_btn, exp, st): head.addWidget(b)
        v.addLayout(head)
        self.pills = QLabel(); self.pills.setTextFormat(Qt.RichText); v.addWidget(self.pills)
        self.banner = QFrame(); self.banner.setObjectName("banner"); bl = QHBoxLayout(self.banner)
        self.banner_text = QLabel(); self.banner_text.setWordWrap(True); bl.addWidget(self.banner_text, 1)
        bb = QPushButton("Open Location settings"); bb.clicked.connect(lambda: os.startfile("ms-settings:privacy-location") if sys.platform == "win32" else None); bl.addWidget(bb)
        self.banner.hide(); v.addWidget(self.banner)

        self.tabs = QTabWidget(); v.addWidget(self.tabs, 1)
        # Wi-Fi
        self.wt = ListDetail(["SSID", "BSSID", "Vendor", "RSSI", "Ch", "Band", "Width", "Standard", "Security", "Seen"],
                             ["All", "2.4 GHz", "5 GHz", "6 GHz"], "Search SSID, BSSID, vendor, channel…", "Select a network to see everything about it")
        self.view_btn = QPushButton("Channel graph"); self.view_btn.setCheckable(True); self.view_btn.toggled.connect(lambda on: self.wt.stack.setCurrentIndex(1 if on else 0))
        self.wt.top.addWidget(self.view_btn)
        cg = QWidget(); cl = QVBoxLayout(cg)
        self.cgraphs = [ChannelGraph(b) for b in ("2.4 GHz", "5 GHz", "6 GHz")]
        for g in self.cgraphs:
            lab = QLabel(g.band); lab.setStyleSheet("font-weight:600"); cl.addWidget(lab); cl.addWidget(g, 1)
        cs = QScrollArea(); cs.setWidgetResizable(True); cs.setWidget(cg); self.wt.stack.addWidget(cs)
        self.tabs.addTab(self.wt, "Wi-Fi")
        # Bluetooth
        self.btt = ListDetail(["Name", "Address", "Vendor", "RSSI", "What", "Distance", "Kind", "Seen"],
                              ["All", "In range", "BLE", "Classic", "Paired"], "Search name, address, vendor, type…", "Select a device to see its advertisement details")
        self.tabs.addTab(self.btt, "Bluetooth")
        # Trackers
        self.tt = ListDetail(["Type", "Address", "Status", "Sightings", "First seen", "Last seen", "RSSI"], ["All", "Flagged"],
                             "Search…", "Select a tracker to see its sightings", sort_col=5)
        self.tt.graph.hide(); self.timeline = Timeline(); self.tt.graph.parentWidget().layout().insertWidget(3, self.timeline)
        self.trust_btn = QPushButton("Trust this device"); self.trust_btn.clicked.connect(self.toggle_trust)
        self.forget_btn = QPushButton("Forget"); self.forget_btn.clicked.connect(self.forget_tracker)
        self.tt.buttons.addWidget(self.trust_btn); self.tt.buttons.addWidget(self.forget_btn); self.tt.buttons.addStretch(1)
        self.tabs.addTab(self.tt, "Trackers")
        # NFC + Radios
        self.nfc = QLabel(); self.nfc.setWordWrap(True); self.nfc.setTextFormat(Qt.RichText); self.nfc.setAlignment(Qt.AlignTop)
        self.tabs.addTab(self._scroll(self.nfc), "NFC")
        self.radios = QLabel(); self.radios.setWordWrap(True); self.radios.setTextFormat(Qt.RichText); self.radios.setAlignment(Qt.AlignTop)
        self.radios.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.tabs.addTab(self._scroll(self.radios), "Radios")
        self.setCentralWidget(root)
        for w in (self.wt, self.btt, self.tt):
            w.search.textChanged.connect(self.tick); w.chip_group.idClicked.connect(lambda *_: self.tick()); w.table.itemSelectionChanged.connect(self.tick)
        self.timer = QTimer(self); self.timer.timeout.connect(self.tick); self.timer.start(1000)
        self.tick()

    def _scroll(self, w):
        f = QFrame(); f.setObjectName("detail"); l = QVBoxLayout(f); l.addWidget(w)
        s = QScrollArea(); s.setWidgetResizable(True); s.setWidget(f); return s

    # ------------------------------------------------------------------ info
    def _collect_info(self):
        i = engine.radio_info()
        try:
            i.update(asyncio.run(engine.winrt_info()))
        except Exception as e:
            log(f"winrt info: {e}")
        self.bridge.info.emit(i)

    def _got_info(self, i):
        self.info = i; self.tick()

    # ------------------------------------------------------------------ actions
    def toggle_pause(self):
        p = not self.wifi.paused
        self.wifi.paused = p; self.bt.paused = p
        self.pause_btn.setText("Resume" if p else "Pause"); self.pause_btn.setProperty("danger", p)
        self.pause_btn.style().unpolish(self.pause_btn); self.pause_btn.style().polish(self.pause_btn)
        if not p: self.wifi.wake.set()

    def open_settings(self):
        d = SettingsDialog(self.s, self)
        if d.exec():
            d.apply(); self.wifi.wake.set(); self.tick()

    def toggle_trust(self):
        k = self.tt.sel_key
        if not k: return
        cur = next((t for t in self.store.all(self.rule()) if t["id"] == k), None)
        if cur: self.store.set_trusted(k, not cur["trusted"]); self.tick()

    def forget_tracker(self):
        if self.tt.sel_key: self.store.forget(self.tt.sel_key); self.tt.sel_key = None; self.tick()

    def rule(self):
        return trackers.Rule(self.s.tracker_minutes, self.s.tracker_days)

    # ------------------------------------------------------------------ refresh
    def tick(self):
        now = time.time()
        aps, ws = self.wifi.snapshot()
        devs, bs = self.bt.snapshot()
        tr = self.store.all(self.rule())
        loc = ws.location_blocked
        self.banner.setVisible(loc)
        if loc:
            self.banner_text.setText("Windows' Location services is off, and Windows 11 only gives apps Wi-Fi network details (names, BSSIDs, signal) when it is on. "
                                     "Turn on Location services and 'Let desktop apps access your location'. Signal Scanner doesn't use or store your position.")
        paused = self.wifi.paused
        self.status.setText(("  ⏸ paused" if paused else "  ● scanning") + f"  ·  Wi-Fi every {self.s.wifi_interval}s · Bluetooth every {self.s.bt_interval}s")
        def pill(t, c): return f"<span style='color:{c}'>●</span>&nbsp;{html.escape(t)}&nbsp;&nbsp;&nbsp;&nbsp;"
        nfc_ok = bool(self.info.get("nfc") or self.info.get("nfc_pnp"))
        self.pills.setText(pill("Wi-Fi: " + ("blocked (Location off)" if loc else (ws.error or f"{len(aps)} networks")), RED if loc else AMBER if ws.error else GREEN)
                           + pill("BLE: " + ("scanning" if bs.scanning else (bs.error or "starting")), GREEN if bs.scanning else AMBER)
                           + pill("BT classic: " + ("inquiry…" if bs.inquiry else "on" if self.s.classic_inquiry else "off"), GREEN if self.s.classic_inquiry else SUB)
                           + pill("NFC: " + ("present" if nfc_ok else "not present" if self.info else "checking…"), GREEN if nfc_ok else SUB))
        flagged = sum(1 for t in tr if t["verdict"].flagged)
        self.tabs.setTabText(0, f"Wi-Fi ({len(aps)})"); self.tabs.setTabText(1, f"Bluetooth ({sum(1 for d in devs if now - d.last_seen < 60)})")
        self.tabs.setTabText(2, f"Trackers ⚠{flagged}" if flagged else f"Trackers ({len(tr)})")
        self.tick_wifi(aps, ws, now); self.tick_bt(devs, bs, now); self.tick_trackers(tr, now); self.tick_nfc(); self.tick_radios(ws, bs, aps, devs)
        for t in tr:
            if t["verdict"].flagged and not t["alerted"]:
                self.store.set_alerted(t["id"])
                self.tray.showMessage(f"Unknown {t['type']} may be following you", t["verdict"].reason + ". Open Signal Scanner → Trackers.", QSystemTrayIcon.Warning, 15000)

    def tick_wifi(self, aps, ws, now):
        w = self.wt
        q = w.search.text().strip().lower(); band = [None, "2.4 GHz", "5 GHz", "6 GHz"][max(0, w.chip())]
        sel = [a for a in aps if (band is None or a.band == band) and (not q or q in f"{a.ssid} {a.bssid} {a.vendor} {a.channel} {a.security} {a.std_short}".lower())]
        rows = []
        for a in sorted(sel, key=lambda a: -a.rssi):
            rows.append((a.bssid, [Item(("★ " if a.connected else "") + (a.ssid or "(hidden)"), a.ssid.lower() or "~"), Item(a.bssid), Item(a.vendor or ("(randomized)" if lookup.locally_administered(a.bssid) else "")),
                                   Item(a.rssi, a.rssi, rssi_color(a.rssi).name()), Item(a.channel, a.channel), Item(a.band), Item(f"{a.width} MHz", a.width),
                                   Item(a.std_short), Item(a.security, color=RED if a.security.startswith(("Open", "WEP")) else None), Item(ago(now - a.last_seen) + " ago", a.last_seen)]))
        w.fill(rows)
        for g in self.cgraphs: g.set_aps(sel if band is None else aps)
        c = ws.conn
        hdr = ""
        if c is not None and c.state == "connected":
            hdr = (f"<span style='color:{GREEN}'>●</span> Connected to <b>{html.escape(c.ssid)}</b> · {html.escape(c.bssid)} · {html.escape(c.phy)} · "
                   f"{c.rssi if c.rssi is not None else '?'} dBm · channel {c.channel} · {c.rx_mbps:.0f}/{c.tx_mbps:.0f} Mbit/s rx/tx · {html.escape(c.auth)} {html.escape(c.cipher)}")
        elif ws.adapter:
            hdr = f"{html.escape(ws.adapter)} · {html.escape(ws.adapter_state)}"
        if ws.last_scan:
            hdr += f"<br><span style='color:{SUB}'>Last scan {ago(now - ws.last_scan)} ago · {ws.scans} scans · results show the driver's beacon timestamps</span>"
        if ws.error and not ws.location_blocked: hdr += f"<br><span style='color:{AMBER}'>{html.escape(ws.error)}</span>"
        w.header_label.setText(hdr)
        a = next((x for x in aps if x.bssid == w.sel_key), None)
        w.show_detail(a is not None)
        if not a: return
        w.title.setText(a.ssid or "(hidden network)"); w.subtitle.setText(f"{a.bssid} · {a.vendor or 'randomized/unknown vendor'}")
        w.big.setText(f"<span style='color:{rssi_color(a.rssi).name()}'>{a.rssi} dBm</span> <span style='font-size:14px;color:{SUB}'>{wp.quality(a.rssi)} · {'●' * wp.bars(a.rssi)}{'○' * (4 - wp.bars(a.rssi))}</span>")
        w.graph.window = 1800; w.graph.gap = max(90, self.s.wifi_interval * 3); w.graph.set_data(a.history, rssi_color(a.rssi))
        ie = a.ie or wp.IeInfo()
        mr = a.max_rate
        body = section("Signal", [("RSSI", f"{a.rssi} dBm"), ("Link quality (Windows)", f"{a.link_quality} %"), ("Distance (free-space est.)", f"≈ {a.distance:.0f} m" if a.distance else None),
                                  ("First seen", dt(a.first_seen)), ("Last heard", f"{hm(a.last_seen)} ({ago(now - a.last_seen)} ago)"),
                                  ("History", f"{len(a.history)} samples · min {min(r for _, r in a.history)} · max {max(r for _, r in a.history)} dBm" if a.history else None)])
        body += section("Channel", [("Frequency", f"{a.freq} MHz"), ("Band / channel", f"{a.band} · ch {a.channel}"), ("Width", f"{a.width} MHz"), ("Center", f"{a.center} MHz"),
                                    ("Standard", a.std_long), ("PHY (driver)", a.phy), ("Spatial streams", ie.streams or None),
                                    ("Max PHY rate", f"{mr:.0f} Mbit/s" if mr else None), ("Basic/supported rates", ", ".join(f"{r:g}" for r in a.rates) + " Mbit/s" if a.rates else None),
                                    ("Beacon interval", f"{a.beacon_ms:.0f} ms"), ("DTIM", ie.dtim), ("BSS color", ie.bss_color)])
        rsn = ie.rsn or ie.wpa
        body += section("Security", [("Security", (a.security, RED if a.security.startswith(("Open", "WEP")) else None)),
                                     ("AKM", "/".join(rsn.akms) if rsn else None), ("Pairwise cipher", "/".join(rsn.pairwise) if rsn else None), ("Group cipher", rsn.group if rsn else None),
                                     ("PMF (802.11w)", ("required" if rsn.mfp_required else "capable" if rsn.mfp_capable else "off") if rsn else None),
                                     ("WPS", (ie.wps_state or "on") if ie.wps else "off")] + [(f"WPS {k}", v) for k, v in ie.wps_device.items()])
        body += section("Load & features", [("Clients (BSS Load)", ie.station_count), ("Channel busy", f"{ie.channel_util} %" if ie.channel_util is not None else None),
                                            ("Country", f"{ie.country} {ie.country_env or ''}" if ie.country else None), ("Max tx power", f"{ie.max_tx_power} dBm" if ie.max_tx_power else None),
                                            ("802.11k / r / v", f"{'yes' if ie.k11 else 'no'} / {'yes' if ie.r11 else 'no'} / {'yes' if ie.v11 else 'no'}"),
                                            ("FTM responder (RTT)", "yes" if ie.ftm_responder else None), ("Passpoint", "yes" if ie.hs20 else None),
                                            ("Wi-Fi 7 MLD address", ie.mld_mac), ("AP name", ie.ap_name), ("Vendor elements", ", ".join(ie.vendors) or None)])
        c = ws.conn
        if a.connected and c:
            body += section("Your connection", [("Profile", c.profile), ("Rx / Tx rate", f"{c.rx_mbps:.0f} / {c.tx_mbps:.0f} Mbit/s"), ("Signal quality", f"{c.quality} %"),
                                                ("Auth / cipher", f"{c.auth} / {c.cipher}")])
        body += section(f"Information elements ({len(ie.items)})", [(f"{x.label} {x.name}", x.summary or x.hex) for x in ie.items])
        w.body.setText(body)

    def tick_bt(self, devs, bs, now):
        w = self.btt
        q = w.search.text().strip().lower(); chip = w.chip()
        def keep(d):
            if chip == 1 and now - d.last_seen > 60: return False
            if chip == 2 and not d.ble: return False
            if chip == 3 and not d.classic: return False
            if chip == 4 and not d.paired: return False
            return not q or q in f"{d.name} {d.address} {d.vendor} {d.tag}".lower()
        rows = []
        for d in sorted(filter(keep, devs), key=lambda d: -(d.rssi if d.rssi is not None and now - d.last_seen < 60 else -200)):
            inr = now - d.last_seen < 60
            kind = "/".join(x for x, c in (("LE", d.ble), ("Classic", d.classic)) if c) + (" · paired" if d.paired else "") + (" · connected" if d.is_connected else "")
            dist = d.distance
            rows.append((d.address, [Item(d.name or "(no name)", (d.name or "~").lower()), Item(d.address), Item(d.vendor or (d.addr_type == "random" and "(random address)") or ""),
                                     Item(d.rssi if inr and d.rssi is not None else "—", d.rssi if inr and d.rssi is not None else -999, rssi_color(d.rssi if inr else None).name()),
                                     Item(d.tag or "", color=ORANGE if d.tracker else None), Item((f"≈ {dist:.1f} m" if dist < 50 else "> 50 m") if dist and inr else "", dist or 999),
                                     Item(kind), Item(ago(now - d.last_seen) + " ago" if d.last_seen else "", d.last_seen)]))
        w.fill(rows)
        w.header_label.setText(f"<span style='color:{SUB}'>{len([d for d in devs if now - d.last_seen < 60])} in range · {len(devs)} total · "
                               f"{html.escape(bs.backend or '')}{' · last classic inquiry ' + ago(now - bs.last_inquiry) + ' ago' if bs.last_inquiry else ''}</span>"
                               + (f"<br><span style='color:{AMBER}'>{html.escape(bs.error)}</span>" if bs.error else ""))
        d = next((x for x in devs if x.address == w.sel_key), None)
        w.show_detail(d is not None)
        if not d: return
        w.title.setText(d.name or "(no name)"); w.subtitle.setText(f"{d.address} · {d.vendor or ('random address' if d.addr_type == 'random' else 'unknown vendor')}")
        inr = now - d.last_seen < 60
        w.big.setText(f"<span style='color:{rssi_color(d.rssi if inr else None).name()}'>{d.rssi if inr and d.rssi is not None else '—'} dBm</span>")
        w.graph.window = 600; w.graph.gap = 30; w.graph.set_data(d.history, rssi_color(d.rssi))
        body = section("Device", [("Address", d.address), ("Address type", d.addr_type), ("Vendor (OUI)", d.vendor), ("Bluetooth", "/".join(x for x, c in (("LE", d.ble), ("Classic", d.classic)) if c)),
                                  ("Class of device", btparse.class_of_device(d.cod)), ("Paired", "yes" if d.paired else "no"), ("Connected", "yes" if d.is_connected else None),
                                  ("Connectable", None if d.connectable is None else ("yes" if d.connectable else "no")), ("Tx power", f"{d.tx_power} dBm" if d.tx_power is not None else None),
                                  ("Distance (est.)", f"≈ {d.distance:.1f} m" if d.distance and inr else None), ("Advertising interval", f"≈ {d.adv_interval_ms:.0f} ms" if d.adv_interval_ms else None),
                                  ("Packets", d.packets or None), ("First seen", dt(d.first_seen)), ("Last seen", f"{hm(d.last_seen)} ({ago(now - d.last_seen)} ago)" if d.last_seen else "not seen over the air yet (known from Windows' paired list)")])
        if d.tracker:
            body += section("Tracker", [("Type", (d.tracker.type, ORANGE)), ("Status", d.tracker.detail), ("See", "Trackers tab")])
        for x in d.decoded:
            body += section(x.title, [("", l) for l in x.lines])
        body += section("Manufacturer data", [(f"{lookup.company(k) or 'Company'} (0x{k:04X})", btparse.hexsp(v)) for k, v in d.manu.items()])
        body += section("Service data", [(btparse.uuid16_label(k) if isinstance(k, int) else str(k), btparse.hexsp(v)) for k, v in d.svc.items()])
        body += section("Service UUIDs", [("", btparse.uuid_label(u)) for u in d.uuids])
        if d.raw: body += section("Raw advertisement", [("", btparse.hexsp(d.raw))])
        w.body.setText(body)

    def tick_trackers(self, tr, now):
        w = self.tt
        q = w.search.text().strip().lower()
        sel = [t for t in tr if (w.chip() != 1 or t["verdict"].flagged) and (not q or q in f"{t['type']} {t['address']}".lower())]
        rows = []
        for t in sel:
            v = t["verdict"]
            status = "FLAGGED" if v.flagged else "Trusted" if t["trusted"] else "Owner nearby" if t["separated"] is False else "Watching"
            col = RED if v.flagged else GREEN if t["trusted"] else SUB if t["separated"] is False else AMBER
            live = t["live"]
            rows.append((t["id"], [Item(t["type"]), Item(t["address"]), Item(status, color=col), Item(len(t["sightings"]), len(t["sightings"])),
                                   Item(dt(t["first"]), t["first"]), Item(ago(now - t["last"]) + " ago", t["last"]),
                                   Item(live[0] if live and now - live[1] < 60 else "—", live[0] if live and now - live[1] < 60 else -999)]))
        w.fill(rows)
        n = sum(1 for t in tr if t["verdict"].flagged)
        w.header_label.setText((f"<b style='color:{RED}'>⚠ {n} tracker(s) flagged</b>" if n else f"<b style='color:{GREEN}'>No tracker flagged</b>")
                               + f"<br><span style='color:{SUB}'>This PC has no GPS, so instead of 'moving with you' it flags an unknown tracker that's separated from its owner "
                               f"and stays near this PC for {self.s.tracker_minutes}+ min in a row, or shows up on {self.s.tracker_days}+ different days (Settings). "
                               "Trackers near their owner change address ~every 15 min and are only listed briefly. Sightings are kept 7 days on this PC only.</span>")
        t = next((x for x in tr if x["id"] == w.sel_key), None)
        w.show_detail(t is not None)
        if not t: return
        v = t["verdict"]
        w.title.setText(t["type"]); w.subtitle.setText(t["address"])
        w.big.setText(f"<span style='font-size:15px;color:{RED if v.flagged else GREEN if t['trusted'] else AMBER}'>{html.escape(v.reason)}</span>")
        self.timeline.set_points(t["sightings"])
        self.trust_btn.setText("Stop trusting" if t["trusted"] else "Trust this device")
        live = t["live"]
        body = section("Tracker", [("Type", t["type"]), ("Status", t["detail"]), ("Address", t["address"]), ("Key bytes", t["payload"]),
                                   ("Signal now", f"{live[0]} dBm ({ago(now - live[1])} ago)" if live and now - live[1] < 60 else "not in range"),
                                   ("First seen", dt(t["first"])), ("Last seen", dt(t["last"])), ("Sightings", f"{len(t['sightings'])} (at most one a minute)"),
                                   ("Separate visits", v.sessions), ("Different days", v.days), ("Alerted", dt(t["alerted"]) if t["alerted"] else None)])
        body += section("Find it / play a sound", [("", trackers.FIND_HINT.get(t["family"], trackers.FIND_HINT["dult"]))])
        w.body.setText(body)

    def tick_nfc(self):
        i = self.info
        if not i:
            self.nfc.setText("Checking for NFC hardware…"); return
        if i.get("nfc"):
            n = i["nfc"]
            txt = section("NFC", [("Status", ("present", GREEN)), ("Device", n.get("id")), ("Speed", f"{n.get('bps')} bit/s"), ("Max message", f"{n.get('max_msg')} bytes")])
            txt += "<p>Windows exposes NFC for tap-to-share messages (Windows.Networking.Proximity). Reading arbitrary tag details needs a smart-card style NFC reader driver.</p>"
        elif i.get("nfc_pnp"):
            txt = section("NFC", [("Status", ("hardware found", AMBER)), ("Devices", ", ".join(i["nfc_pnp"])),
                                  ("Note", "An NFC device is installed but no proximity driver is active.")])
        else:
            txt = section("NFC", [("Status", ("not present", SUB)), ("Details", "This PC has no NFC radio (no proximity device or NFC reader is installed). "
                                  "A USB NFC reader (e.g. ACR122U) would show up here.")])
        self.nfc.setText(txt)

    def tick_radios(self, ws, bs, aps, devs):
        i = self.info
        loc = engine.__dict__.get("_loc_cache")
        try:
            from .wlan import location_state
            loc = location_state()
        except Exception:
            loc = {}
        txt = section("Radios (Windows)", i.get("radios") or [("", "checking…")])
        txt += section("Wi-Fi adapter", [("Adapter", ws.adapter), ("State", ws.adapter_state)] + list(i.get("wifi_driver", [])))
        txt += section("Wi-Fi capabilities (driver)", i.get("wifi_caps", []))
        txt += section("Location (needed for Wi-Fi scan data on Windows 11)", [("System Location services", loc.get("system")), ("This user", loc.get("user")),
                                                                               ("Desktop apps", loc.get("desktop")),
                                                                               ("Wi-Fi scan data", ("blocked – turn Location on", RED) if ws.location_blocked else ("available", GREEN) if aps else "—")])
        txt += section("Bluetooth adapter", list(i.get("bt", [])) + list(i.get("bt_caps", [])) + [("BLE scanner", bs.backend or bs.error or "starting")])
        txt += section("Not on this PC", [("Cellular, GNSS, UWB", "not present (desktop PC)"), ("NFC", "present" if i.get("nfc") else "not present")])
        self.radios.setText(txt)

    # ------------------------------------------------------------------ export
    def export_dir(self):
        d = self.s.export_dir or os.path.join(os.path.expanduser("~"), "Documents", "SignalScanner")
        os.makedirs(d, exist_ok=True); return d

    def export_data(self, kind: str) -> tuple[str, str]:
        aps, ws = self.wifi.snapshot(); devs, bs = self.bt.snapshot(); tr = self.store.all(self.rule())
        if kind == "wifi":
            b = io.StringIO(); c = csv.writer(b)
            c.writerow(["ssid", "bssid", "vendor", "rssi_dbm", "frequency_mhz", "band", "channel", "width_mhz", "center_mhz", "standard", "security", "streams",
                        "max_rate_mbps", "clients", "channel_util_pct", "country", "first_seen", "last_heard", "connected", "rssi_history"])
            for a in aps:
                ie = a.ie or wp.IeInfo()
                c.writerow([a.ssid, a.bssid, a.vendor, a.rssi, a.freq, a.band, a.channel, a.width, a.center, a.std_long, a.security, ie.streams,
                            a.max_rate, ie.station_count, ie.channel_util, ie.country, dt(a.first_seen), dt(a.last_seen), a.connected, " ".join(str(r) for _, r in a.history)])
            return "csv", b.getvalue()
        if kind == "bt":
            b = io.StringIO(); c = csv.writer(b)
            c.writerow(["name", "address", "address_type", "vendor", "le", "classic", "paired", "rssi_dbm", "tx_power", "distance_m", "decoded", "class_of_device",
                        "manufacturer_data", "service_data", "uuids", "raw", "first_seen", "last_seen"])
            for d in devs:
                c.writerow([d.name, d.address, d.addr_type, d.vendor, d.ble, d.classic, d.paired, d.rssi, d.tx_power, f"{d.distance:.1f}" if d.distance else "",
                            "; ".join(f"{x.title}: {' / '.join(x.lines)}" for x in d.decoded), btparse.class_of_device(d.cod),
                            "; ".join(f"0x{k:04X}:{v.hex()}" for k, v in d.manu.items()), "; ".join(f"{k}:{v.hex()}" for k, v in d.svc.items()),
                            " ".join(d.uuids), d.raw.hex(), dt(d.first_seen), dt(d.last_seen)])
            return "csv", b.getvalue()
        if kind == "trackers":
            b = io.StringIO(); c = csv.writer(b)
            c.writerow(["type", "address", "status", "flagged", "reason", "trusted", "sightings", "first_seen", "last_seen", "days"])
            for t in tr:
                c.writerow([t["type"], t["address"], t["detail"], t["verdict"].flagged, t["verdict"].reason, t["trusted"], len(t["sightings"]), dt(t["first"]), dt(t["last"]), t["verdict"].days])
            return "csv", b.getvalue()
        out = {"exported": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "computer": os.environ.get("COMPUTERNAME"),
               "wifi": [{"ssid": a.ssid, "bssid": a.bssid, "vendor": a.vendor, "rssi": a.rssi, "freq": a.freq, "channel": a.channel, "width": a.width, "standard": a.std_long,
                         "security": a.security, "connected": a.connected, "ies": [{"id": x.label, "name": x.name, "summary": x.summary} for x in (a.ie.items if a.ie else [])],
                         "history": [[round(t), r] for t, r in a.history]} for a in aps],
               "bluetooth": [{"name": d.name, "address": d.address, "vendor": d.vendor, "rssi": d.rssi, "le": d.ble, "classic": d.classic, "paired": d.paired,
                              "decoded": [{"title": x.title, "lines": x.lines} for x in d.decoded], "manufacturer": {f"0x{k:04X}": v.hex() for k, v in d.manu.items()},
                              "service_data": {str(k): v.hex() for k, v in d.svc.items()}, "uuids": d.uuids, "raw": d.raw.hex()} for d in devs],
               "trackers": [{"type": t["type"], "address": t["address"], "flagged": t["verdict"].flagged, "reason": t["verdict"].reason, "trusted": t["trusted"],
                             "sightings": [[round(s), r] for s, r in t["sightings"]]} for t in tr],
               "radios": {k: v for k, v in self.info.items() if isinstance(v, (list, dict, str))}}
        return "json", json.dumps(out, indent=1, default=str)

    def export(self, kind: str, path: str | None = None):
        ext, data = self.export_data(kind)
        quiet = path is not None
        name = {"wifi": "wifi", "bt": "bluetooth", "trackers": "trackers"}.get(kind, "signals")
        path = path or os.path.join(self.export_dir(), f"{name}_{time.strftime('%Y%m%d_%H%M%S')}.{ext}")
        with open(path, "w", encoding="utf-8", newline="") as f: f.write(data)
        log(f"exported {path}")
        if not quiet:
            QMessageBox.information(self, "Exported", f"Saved to\n{path}")
        return path

    def handle_command(self, argv):
        if "--quit" in argv: self.close(); return
        self.showNormal(); self.raise_(); self.activateWindow()

    def run_test_hooks(self):
        a = self.args
        if a.tab is not None: self.tabs.setCurrentIndex(a.tab)
        if a.channels: self.view_btn.setChecked(True)
        delay = int(a.shot_after * 1000)
        if a.select:
            def pick():
                for lw in (self.wt, self.btt, self.tt):
                    t = lw.table
                    for r in range(t.rowCount()):
                        if any(a.select.lower() in (t.item(r, c).text().lower() if t.item(r, c) else "") for c in range(t.columnCount())):
                            lw.sel_key = t.item(r, 0).data(Qt.UserRole); break
                self.tick()
            QTimer.singleShot(max(0, delay - 1500), pick)
        for e in a.export or []:
            kind, _, path = e.partition(":") if ":" in e[:9] else ("json", "", e)
            QTimer.singleShot(delay, lambda k=kind, p=path: self.export(k, p))
        for k, spec in enumerate(a.shot or []):
            tab, _, path = spec.partition(":")
            sel = None
            if "@" in tab: tab, sel = tab.split("@", 1)
            def take(tab=int(tab), path=path, sel=sel):
                self.tabs.setCurrentIndex(tab)
                if sel:
                    lw = {0: self.wt, 1: self.btt, 2: self.tt}.get(tab)
                    if lw:
                        t = lw.table
                        for r in range(t.rowCount()):
                            if any(sel.lower() in (t.item(r, c).text().lower() if t.item(r, c) else "") for c in range(t.columnCount())):
                                lw.sel_key = t.item(r, 0).data(Qt.UserRole); break
                self.tick(); QApplication.processEvents()
                QTimer.singleShot(400, lambda: (self.grab().save(path), log(f"screenshot {path}")))
            QTimer.singleShot(delay + 300 + k * 1500, take)
        if a.screenshot:
            QTimer.singleShot(delay + 300, lambda: (self.tick(), self.grab().save(a.screenshot), log(f"screenshot {a.screenshot}")))
        if a.quit_after:
            QTimer.singleShot(int(a.quit_after * 1000), self.close)

    def closeEvent(self, e):
        self.wifi.stop_ev.set(); self.wifi.wake.set(); self.bt.stop()
        self.tray.hide()
        super().closeEvent(e)
        QApplication.quit()


def main():
    ap = argparse.ArgumentParser(prog="SignalScanner")
    ap.add_argument("--screenshot"); ap.add_argument("--shot", action="append", help="TAB[@select]:path (repeatable)"); ap.add_argument("--shot-after", type=float, default=20)
    ap.add_argument("--tab", type=int); ap.add_argument("--select"); ap.add_argument("--channels", action="store_true")
    ap.add_argument("--export", action="append", help="kind:path (wifi|bt|trackers|json)")
    ap.add_argument("--quit-after", type=float); ap.add_argument("--quit", action="store_true"); ap.add_argument("--no-activate", action="store_true")
    args, _ = ap.parse_known_args()
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Victor.SignalScanner")
        except Exception:
            pass
    app = QApplication(sys.argv)
    app.setApplicationName("Signal Scanner"); app.setStyle("Fusion"); app.setWindowIcon(app_icon())
    app.setQuitOnLastWindowClosed(True)
    pal = QPalette()
    for role, col in ((QPalette.Window, BG), (QPalette.Base, CARD), (QPalette.Text, TEXT), (QPalette.WindowText, TEXT), (QPalette.Button, "#1F2830"),
                      (QPalette.ButtonText, TEXT), (QPalette.Highlight, "#1E3440"), (QPalette.HighlightedText, TEXT), (QPalette.AlternateBase, "#1B2229")):
        pal.setColor(role, QColor(col))
    app.setPalette(pal)
    app.setStyleSheet(STYLE.replace("__CHECK_SVG__", _check_svg_path()))
    server_name = "SignalScanner-" + os.environ.get("USERNAME", os.environ.get("USER", "user"))
    sock = QLocalSocket(); sock.connectToServer(server_name)
    if sock.waitForConnected(500):
        sock.write("\x1f".join(sys.argv[1:] or ["--show"]).encode("utf-8")); sock.flush(); sock.waitForBytesWritten(1000); sock.disconnectFromServer()
        sys.exit(0)
    if args.quit: sys.exit(0)
    QLocalServer.removeServer(server_name)
    server = QLocalServer(); server.listen(server_name)
    w = MainWindow(args)
    def on_conn():
        c = server.nextPendingConnection()
        def read(): w.handle_command([x for x in bytes(c.readAll()).decode("utf-8", "ignore").split("\x1f") if x])
        c.readyRead.connect(read)
        if c.bytesAvailable(): read()
    server.newConnection.connect(on_conn)
    if args.no_activate:
        w.setAttribute(Qt.WA_ShowWithoutActivating, True)
    w.show()
    w.run_test_hooks()
    log(f"started {__version__}")
    sys.exit(app.exec())
