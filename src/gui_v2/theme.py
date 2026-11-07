# -*- coding: utf-8 -*-
"""GUI v2 design system - one place for the palette, stylesheet and helpers.

Dark, portal-matched: the same design language as the mgmt/customer web portals
(deep navy cards, subtle borders, blue accent, green/red status). Every window
applies WINDOW_QSS at the top level, so backend-created dialogs (QMessageBox,
QProgressDialog) inherit the theme automatically through their parent.

Styling variants use Qt *dynamic properties* (``variant`` / ``role``), never
objectName selectors: objectNames are part of the v1 widget contract and must
stay exactly as the backend knows them.

Status colours are applied by the backend as item-level brushes (Qt.red /
Qt.green) and as fixed glyph pixmap colours; those override QSS by design, and
this palette is chosen to sit well beside them.
"""

from PyQt5 import QtCore, QtGui, QtWidgets
from kiosk_cursor import cursor as kiosk_cursor

# --- Palette (mirrors the web portals' CSS variables) -------------------------
BG      = "#0b0f14"   # window background
CARD    = "#131a22"   # panel / table background
CARD2   = "#182230"   # controls (buttons, inputs)
LINE    = "#253143"   # borders
LINE2   = "#1c2634"   # table gridlines (subtler than borders)
TEXT    = "#d6dee8"
MUTED   = "#8798ab"
ACCENT  = "#4aa3ff"
ACCENT2 = "#2b6fb3"
PRESSED = "#223045"
DANGER  = "#ef5b64"
DIM     = "#55647a"   # disabled/greyed-out elements
MONO    = "DejaVu Sans Mono"   # output panels; present on the Pi

WINDOW_QSS = f"""
QMainWindow, QWidget {{ background-color: {BG}; color: {TEXT}; }}

/* Explicit, compact typography: the v1 layout is tight (fixed 480x320 with
   hand-placed widths), so v2 pins sizes rather than inheriting ambient
   defaults that overflow them. */
QLabel {{ background: transparent; color: {TEXT}; font-size: 9pt; }}
QLabel[role="muted"] {{ color: {MUTED}; }}
QLabel[role="section"] {{ color: {ACCENT}; font-size: 10pt; }}
QLabel:disabled {{ color: {DIM}; }}

/* Cards: tables and output panels */
QTableWidget {{
    background-color: {CARD};
    border: 1px solid {LINE};
    border-radius: 8px;
    gridline-color: {LINE2};
    color: {TEXT};
    selection-background-color: {PRESSED};
    selection-color: {TEXT};
}}
QHeaderView {{ background: transparent; }}
QHeaderView::section {{
    background-color: {CARD};
    color: {MUTED};
    border: none;
    border-bottom: 1px solid {LINE};
    font-size: 9pt;
    font-weight: bold;
}}
QHeaderView::section:vertical {{
    color: {ACCENT};
    border-bottom: 1px solid {LINE2};
    border-right: 1px solid {LINE};
    padding-left: 4px;
}}
QTableCornerButton::section {{ background-color: {CARD}; border: none; }}

/* Buttons */
QPushButton {{
    background-color: {CARD2};
    color: {TEXT};
    border: 1px solid {LINE};
    border-radius: 7px;
    padding: 2px 4px;
    font-size: 9pt;
    font-weight: normal;
}}
QPushButton:pressed {{ background-color: {PRESSED}; border-color: {ACCENT}; }}
QPushButton:disabled {{ color: {MUTED}; background-color: {CARD}; }}
QPushButton[variant="primary"] {{ background-color: {ACCENT2}; border-color: {ACCENT2}; font-weight: 600; }}
QPushButton[variant="primary"]:pressed {{ background-color: {ACCENT}; border-color: {ACCENT}; }}
QPushButton[variant="danger"] {{ background: transparent; border-color: {DANGER}; color: {DANGER}; }}
QPushButton[variant="danger"]:pressed {{ background-color: {DANGER}; color: white; }}

/* Inputs */
QLineEdit, QComboBox {{
    background-color: {CARD2};
    color: {TEXT};
    border: 1px solid {LINE};
    border-radius: 6px;
    padding: 2px 6px;
    font-size: 9pt;
    selection-background-color: {ACCENT2};
}}
QLineEdit:focus, QComboBox:focus {{ border-color: {ACCENT}; }}
QLineEdit:read-only {{ color: {MUTED}; }}
QLineEdit:disabled {{ color: {DIM}; background-color: {CARD}; border-color: {LINE2}; }}
QComboBox::drop-down {{ border: none; width: 18px; }}
QComboBox::down-arrow {{
    width: 0; height: 0;
    border-left: 5px solid transparent;
    border-right: 5px solid transparent;
    border-top: 6px solid {MUTED};
    margin-right: 5px;
}}
QComboBox QAbstractItemView {{
    background-color: {CARD};
    color: {TEXT};
    border: 1px solid {LINE};
    selection-background-color: {PRESSED};
    outline: none;
}}

/* Toggles */
QCheckBox, QRadioButton {{ background: transparent; color: {TEXT}; spacing: 6px; font-size: 9pt; }}
QCheckBox:disabled, QRadioButton:disabled {{ color: {MUTED}; }}
QCheckBox::indicator, QRadioButton::indicator {{
    width: 14px; height: 14px;
    border: 1px solid {LINE};
    background-color: {CARD2};
}}
QCheckBox::indicator {{ border-radius: 4px; }}
QRadioButton::indicator {{ border-radius: 8px; }}
QCheckBox::indicator:checked, QRadioButton::indicator:checked {{
    background-color: {ACCENT};
    border-color: {ACCENT};
}}
QCheckBox::indicator:disabled, QRadioButton::indicator:disabled {{
    border-color: {LINE2}; background-color: {CARD};
}}

/* Output panels */
QTextEdit {{
    background-color: {CARD};
    color: {TEXT};
    border: 1px solid {LINE};
    border-radius: 8px;
    selection-background-color: {ACCENT2};
}}

/* Scrollbars: slim, dark */
QScrollBar:vertical {{ background: {CARD}; width: 8px; margin: 0; }}
QScrollBar::handle:vertical {{ background: {LINE}; border-radius: 4px; min-height: 24px; }}
QScrollBar:horizontal {{ background: {CARD}; height: 8px; margin: 0; }}
QScrollBar::handle:horizontal {{ background: {LINE}; border-radius: 4px; min-width: 24px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

/* Backend-created dialogs inherit through the parent window */
QMessageBox, QProgressDialog, QInputDialog {{ background-color: {CARD}; }}
QMessageBox QLabel, QProgressDialog QLabel, QInputDialog QLabel {{ color: {TEXT}; }}
QProgressBar {{
    background-color: {CARD2};
    border: 1px solid {LINE};
    border-radius: 6px;
    color: {TEXT};
    text-align: center;
}}
QProgressBar::chunk {{ background-color: {ACCENT2}; border-radius: 5px; }}

QStatusBar {{ background: transparent; color: {MUTED}; }}
QStatusBar::item {{ border: none; }}
"""


def apply_window(window, object_name):
    """Base window setup shared by every v2 page: size, cursor, theme."""
    window.setObjectName(object_name)
    window.resize(480, 320)
    window.setCursor(kiosk_cursor())
    window.setStyleSheet(WINDOW_QSS)


def font(point_size=None, bold=False, mono=False):
    f = QtGui.QFont()
    if mono:
        f.setFamily(MONO)
    if point_size is not None:
        f.setPointSize(point_size)
    f.setBold(bold)
    return f


def _paint_wifi(p, cx, cy, r):
    """Three arcs + a dot, opening upward.

    Scaled ~1.5x with the dot pushed low, so the glyph carries the same visual
    weight as the LAN jack beside it (the original arcs read undersized).
    """
    pen = p.pen()
    base_y = cy + r * 0.55
    for radius in (r * 1.5, r * 1.0, r * 0.5):
        rect = QtCore.QRectF(cx - radius, base_y - radius, radius * 2, radius * 2)
        p.drawArc(rect, 45 * 16, 90 * 16)
    p.setBrush(pen.color())
    p.drawEllipse(QtCore.QPointF(cx, base_y), 2.2, 2.2)


def _paint_lan(p, cx, cy, r):
    """An RJ45 jack: rounded outline, pins along the top, clip tab below."""
    w, h = r * 2.0, r * 1.6
    box = QtCore.QRectF(cx - w / 2, cy - h / 2, w, h)
    p.drawRoundedRect(box, 2.5, 2.5)
    pins = 4
    for i in range(pins):
        x = box.left() + w * (i + 1) / (pins + 1)
        p.drawLine(QtCore.QPointF(x, box.top() + 2), QtCore.QPointF(x, box.top() + h * 0.38))
    tab_w = w * 0.34
    p.drawLine(QtCore.QPointF(cx - tab_w / 2, box.bottom()),
               QtCore.QPointF(cx - tab_w / 2, box.bottom() + 3))
    p.drawLine(QtCore.QPointF(cx + tab_w / 2, box.bottom()),
               QtCore.QPointF(cx + tab_w / 2, box.bottom() + 3))
    p.drawLine(QtCore.QPointF(cx - tab_w / 2, box.bottom() + 3),
               QtCore.QPointF(cx + tab_w / 2, box.bottom() + 3))


def _paint_tools(p, cx, cy, r):
    """A screwdriver at 45 degrees: flat tip, thin shaft, thick round handle."""
    p.save()
    p.translate(cx, cy)
    p.rotate(45)
    scale = 1.15                                  # match the LAN glyph's presence
    tip_y = -r * scale
    # flat head
    tip = p.pen()
    tip.setWidthF(2.6)
    tip.setCapStyle(QtCore.Qt.RoundCap)
    p.setPen(tip)
    p.drawLine(QtCore.QPointF(-4.4, tip_y), QtCore.QPointF(4.4, tip_y))
    # shaft
    shaft = p.pen()
    shaft.setWidthF(3.4)
    shaft.setCapStyle(QtCore.Qt.FlatCap)
    p.setPen(shaft)
    p.drawLine(QtCore.QPointF(0, tip_y), QtCore.QPointF(0, r * 0.12 * scale))
    # handle
    handle = p.pen()
    handle.setWidthF(8.0)
    handle.setCapStyle(QtCore.Qt.RoundCap)
    p.setPen(handle)
    p.drawLine(QtCore.QPointF(0, r * 0.3 * scale), QtCore.QPointF(0, r * scale))
    p.restore()


def _paint_settings(p, cx, cy, r):
    """A gear: eight teeth around a ring with a centre hole."""
    tooth = p.pen()
    tooth.setWidthF(3.4)
    tooth.setCapStyle(QtCore.Qt.RoundCap)
    for i in range(8):
        p.save()
        p.translate(cx, cy)
        p.rotate(i * 45)
        p.setPen(tooth)
        p.drawLine(QtCore.QPointF(0, -r * 0.72), QtCore.QPointF(0, -r))
        p.restore()
    ring = p.pen()
    ring.setWidthF(2.6)
    p.setPen(ring)
    p.drawEllipse(QtCore.QPointF(cx, cy), r * 0.62, r * 0.62)
    p.drawEllipse(QtCore.QPointF(cx, cy), r * 0.22, r * 0.22)


def _paint_4g(p, cx, cy, r):
    """A cellular mast: an upright with a signal fan on each side of the tip.

    Not the WiFi fan. Both tiles are on the dashboard at once, so this one is
    symmetric about a mast - at tile size the fan's symmetry is the only cue
    that survives, and two one-sided fans would read as the same icon twice.
    """
    pen = p.pen()
    # The fan is measured from the tip, so the outer arc is what sets the glyph's
    # top edge - at 0.8r about a tip at 0.75r it lands above the pixmap and comes
    # out with its shoulders sliced off. These numbers keep it inside.
    tip_y = cy - r * 0.55
    p.drawLine(QtCore.QPointF(cx, tip_y), QtCore.QPointF(cx, cy + r))
    p.drawLine(QtCore.QPointF(cx - r * 0.4, cy + r), QtCore.QPointF(cx + r * 0.4, cy + r))
    for radius in (r * 0.42, r * 0.72):
        box = QtCore.QRectF(cx - radius, tip_y - radius, radius * 2, radius * 2)
        p.drawArc(box, -50 * 16, 100 * 16)
        p.drawArc(box, 130 * 16, 100 * 16)
    p.setBrush(pen.color())
    p.drawEllipse(QtCore.QPointF(cx, tip_y), 1.8, 1.8)


_NAV_PAINTERS = {"wifi": _paint_wifi, "lan": _paint_lan,
                 "tools": _paint_tools, "settings": _paint_settings,
                 "4g": _paint_4g}


def nav_icon(kind, caption, width, height):
    """A themed navigation glyph + caption rendered into a pixmap."""
    pix = QtGui.QPixmap(width, height)
    pix.fill(QtCore.Qt.transparent)
    p = QtGui.QPainter(pix)
    p.setRenderHint(QtGui.QPainter.Antialiasing)
    pen = QtGui.QPen(QtGui.QColor(TEXT))
    pen.setWidthF(2.4)
    pen.setCapStyle(QtCore.Qt.RoundCap)
    p.setPen(pen)
    p.setBrush(QtCore.Qt.NoBrush)
    glyph_cy = (height - 13) * 0.52          # leave room for the caption strip
    _NAV_PAINTERS[kind](p, width / 2.0, glyph_cy, min(width, height) * 0.30)
    cap_font = font(7)
    p.setFont(cap_font)
    p.setPen(QtGui.QColor(MUTED))
    p.drawText(QtCore.QRectF(0, height - 15, width, 14),
               QtCore.Qt.AlignHCenter | QtCore.Qt.AlignVCenter, caption)
    p.end()
    return pix


def nav_button(parent, geometry, kind, caption, radius=10):
    """A dashboard tile: themed vector glyph + caption on a rounded card."""
    button = QtWidgets.QPushButton(parent)
    button.setGeometry(geometry)
    button.setText("")
    button.setIcon(QtGui.QIcon(nav_icon(kind, caption,
                                        geometry.width() - 6, geometry.height() - 6)))
    button.setIconSize(QtCore.QSize(geometry.width() - 6, geometry.height() - 6))
    button.setStyleSheet(
        "QPushButton {"
        f" background-color: {CARD2};"
        f" border: 1px solid {LINE};"
        f" border-radius: {radius}px; }}"
        " QPushButton:pressed {"
        f" background-color: {PRESSED}; border-color: {ACCENT}; }}"
    )
    return button


def set_variant(widget, variant):
    """Tag a widget for QSS variant styling ("primary" / "danger")."""
    widget.setProperty("variant", variant)


def set_role(label_widget, role):
    """Tag a QLabel for QSS role styling ("muted" / "section")."""
    label_widget.setProperty("role", role)
