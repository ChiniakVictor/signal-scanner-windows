"""Small QPainter graphs: RSSI sparkline, Wi-Fi channel graph, tracker sighting timeline."""
from __future__ import annotations

import time

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QLinearGradient, QPainter, QPainterPath, QPen, QPolygonF
from PySide6.QtWidgets import QWidget

CYAN, GREEN, AMBER, ORANGE, RED, PURPLE = (QColor(c) for c in ("#4DD0E1", "#3DDC97", "#FFC857", "#FFA94D", "#FF6B6B", "#B39DFF"))
SUBC = QColor("#9AA4AE")
PALETTE = [QColor(c) for c in ("#4DD0E1", "#FF6B6B", "#3DDC97", "#FFC857", "#B39DFF", "#FFA94D", "#64B5F6", "#F48FB1", "#AED581", "#90A4AE", "#FFD54F", "#4DB6AC")]


def rssi_color(r) -> QColor:
    if r is None: return SUBC
    return GREEN if r >= -55 else QColor("#A5DE6A") if r >= -67 else AMBER if r >= -75 else ORANGE if r >= -85 else RED


def color_for(key: str) -> QColor:
    return PALETTE[sum(map(ord, key)) % len(PALETTE)]


class Sparkline(QWidget):
    """history: list of (t, value). Window in seconds; gaps longer than gap_s break the line."""
    def __init__(self, axes=True, window=600, lo=-100, hi=-30, gap_s=90, parent=None):
        super().__init__(parent)
        self.axes, self.window, self.lo, self.hi, self.gap = axes, window, lo, hi, gap_s
        self.data: list = []
        self.color = CYAN
        self.setMinimumHeight(140 if axes else 24)

    def set_data(self, data, color=None):
        self.data = data or []
        if color: self.color = color
        self.update()

    def paintEvent(self, e):
        p = QPainter(self); p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        padL = 40 if self.axes else 1; padB = 18 if self.axes else 1; padT = 6 if self.axes else 1
        gw, gh = w - padL - 4, h - padB - padT
        now = time.time()
        t0 = now - self.window
        def x(t): return padL + (t - t0) / self.window * gw
        def y(v): return padT + gh - (min(max(v, self.lo), self.hi) - self.lo) / (self.hi - self.lo) * gh
        if self.axes:
            p.setPen(QPen(QColor(255, 255, 255, 35), 1, Qt.DashLine))
            for i in range(4):
                v = self.lo + (self.hi - self.lo) * i / 3.5
                p.drawLine(QPointF(padL, y(v)), QPointF(w - 4, y(v)))
                p.setPen(SUBC); p.drawText(QRectF(0, y(v) - 8, padL - 4, 16), Qt.AlignRight | Qt.AlignVCenter, f"{v:.0f}")
                p.setPen(QPen(QColor(255, 255, 255, 35), 1, Qt.DashLine))
            p.setPen(SUBC)
            p.drawText(QRectF(padL, h - padB, 80, padB), Qt.AlignLeft | Qt.AlignVCenter, f"-{self.window // 60} min")
            p.drawText(QRectF(w - 80, h - padB, 76, padB), Qt.AlignRight | Qt.AlignVCenter, "now")
        pts = [(t, v) for t, v in self.data if t >= t0]
        if len(pts) >= 1:
            path = QPainterPath(); fill = QPainterPath()
            prev = None; seg_start = None
            for t, v in pts:
                pt = QPointF(x(t), y(v))
                if prev is None or t - prev > self.gap:
                    if seg_start is not None:
                        fill.lineTo(fill.currentPosition().x(), padT + gh); fill.closeSubpath()
                    path.moveTo(pt); fill.moveTo(pt.x(), padT + gh); fill.lineTo(pt); seg_start = pt
                else:
                    path.lineTo(pt); fill.lineTo(pt)
                prev = t
            fill.lineTo(fill.currentPosition().x(), padT + gh); fill.closeSubpath()
            g = QLinearGradient(0, padT, 0, padT + gh); c1 = QColor(self.color); c1.setAlpha(80); c2 = QColor(self.color); c2.setAlpha(5)
            g.setColorAt(0, c1); g.setColorAt(1, c2); p.fillPath(fill, g)
            p.setPen(QPen(self.color, 2 if self.axes else 1.3)); p.drawPath(path)
            if len(pts) == 1: p.setBrush(self.color); p.drawEllipse(QPointF(x(pts[0][0]), y(pts[0][1])), 2.5, 2.5)
        p.end()


class ChannelGraph(QWidget):
    """APs drawn as trapezoids over their occupied channel width, height = RSSI."""
    def __init__(self, band: str, parent=None):
        super().__init__(parent)
        self.band = band
        self.aps = []
        self.setMinimumHeight(230)

    def set_aps(self, aps):
        self.aps = [a for a in aps if a.band == self.band]
        self.update()

    def ranges(self):
        if self.band == "2.4 GHz": return 2400, 2495, [(c, 2407 + 5 * c) for c in range(1, 14)] + [(14, 2484)]
        if self.band == "6 GHz": return 5945, 7125, [(c, 5950 + 5 * c) for c in range(1, 234, 16)]
        return 5150, 5895, [(c, 5000 + 5 * c) for c in (36, 52, 64, 100, 116, 132, 149, 165, 177)]

    def paintEvent(self, e):
        p = QPainter(self); p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        padL, padB, padT = 40, 20, 26
        gw, gh = w - padL - 8, h - padB - padT
        f0, f1, ticks = self.ranges()
        def x(f): return padL + (f - f0) / (f1 - f0) * gw
        def y(v): return padT + gh - (min(max(v, -100), -20) + 100) / 80 * gh
        p.setPen(QPen(QColor(255, 255, 255, 30), 1, Qt.DashLine))
        for v in (-30, -50, -70, -90):
            p.drawLine(QPointF(padL, y(v)), QPointF(w - 8, y(v)))
            p.setPen(SUBC); p.drawText(QRectF(0, y(v) - 8, padL - 4, 16), Qt.AlignRight | Qt.AlignVCenter, str(v)); p.setPen(QPen(QColor(255, 255, 255, 30), 1, Qt.DashLine))
        p.setPen(SUBC)
        for c, f in ticks:
            p.drawText(QRectF(x(f) - 15, h - padB + 2, 30, padB - 2), Qt.AlignCenter, str(c))
        placed = []
        bold = QFont(self.font()); bold.setBold(True); p.setFont(bold)
        for a in sorted(self.aps, key=lambda a: a.rssi):
            col = color_for(a.ssid or a.bssid)
            half = a.width / 2
            xl, xr = x(a.center - half), x(a.center + half)
            yt, yb = y(a.rssi), padT + gh
            slope = min(10, (xr - xl) / 6)
            poly = QPolygonF([QPointF(xl, yb), QPointF(xl + slope, yt), QPointF(xr - slope, yt), QPointF(xr, yb)])
            fill = QColor(col); fill.setAlpha(45)
            p.setBrush(fill); p.setPen(QPen(col, 2 if a.connected else 1.3)); p.drawPolygon(poly)
            label = (a.ssid or "(hidden)") + (" ★" if a.connected else "")
            tw = p.fontMetrics().horizontalAdvance(label)
            lx = min(max(padL, (xl + xr) / 2 - tw / 2), w - tw - 4)
            ly = yt - 4
            while any(abs(ly - py) < 15 and lx < px + pw and px < lx + tw for px, py, pw in placed) and ly > 16:
                ly -= 15
            placed.append((lx, ly, tw))
            p.setPen(col); p.drawText(QPointF(lx, ly), label)
        if not self.aps:
            p.setPen(SUBC); p.drawText(self.rect(), Qt.AlignCenter, f"No {self.band} networks")
        p.end()


class Timeline(QWidget):
    """Sighting timeline for a tracker: dots at (time, rssi) over the whole sighting span."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.pts = []
        self.setMinimumHeight(120)

    def set_points(self, pts):
        self.pts = pts; self.update()

    def paintEvent(self, e):
        p = QPainter(self); p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height(); padL, padB, padT = 40, 18, 6
        gw, gh = w - padL - 8, h - padB - padT
        if not self.pts:
            p.setPen(SUBC); p.drawText(self.rect(), Qt.AlignCenter, "No sightings"); p.end(); return
        t0 = min(t for t, _ in self.pts); t1 = max(max(t for t, _ in self.pts), t0 + 60)
        def x(t): return padL + (t - t0) / (t1 - t0) * gw
        def y(v): return padT + gh - (min(max(v, -100), -30) + 100) / 70 * gh
        p.setPen(QPen(QColor(255, 255, 255, 30), 1, Qt.DashLine))
        for v in (-40, -60, -80, -100):
            p.drawLine(QPointF(padL, y(v)), QPointF(w - 8, y(v)))
            p.setPen(SUBC); p.drawText(QRectF(0, y(v) - 8, padL - 4, 16), Qt.AlignRight | Qt.AlignVCenter, str(v)); p.setPen(QPen(QColor(255, 255, 255, 30), 1, Qt.DashLine))
        p.setPen(SUBC)
        p.drawText(QRectF(padL, h - padB, 200, padB), Qt.AlignLeft, time.strftime("%a %H:%M", time.localtime(t0)))
        p.drawText(QRectF(w - 208, h - padB, 200, padB), Qt.AlignRight, time.strftime("%a %H:%M", time.localtime(t1)))
        p.setPen(Qt.NoPen)
        for t, v in self.pts:
            p.setBrush(rssi_color(v)); p.drawEllipse(QPointF(x(t), y(v)), 3, 3)
        p.end()
