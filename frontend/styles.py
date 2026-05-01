"""
frontend/styles.py
──────────────────
QSS stylesheet for Antigravity IDS.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ENFORCEMENT RULES — VIOLATIONS ARE ARCHITECTURAL ERRORS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. NO raw pixel values anywhere in this file.
   ✗ padding: 0 12px;       ✓ padding: 0 {_s["lg"]}px;
   ✗ max-width: 38px;       ✓ max-width: {_cs["badge_w"]}px;
   ✗ border-radius: 6px;    ✓ border-radius: {_cs["border_radius_lg"]}px;
   ✗ letter-spacing: 2px;   ✓ letter-spacing: {_cs["letter_md"]}px;

2. NO arithmetic expressions on tokens.
   ✗ {_f["md"] - 1}px       ✓ {_f["sm_body"]}px

3. Token namespace rules:
   _c  → COLORS           (all color values)
   _f  → FONT             (all font sizes)
   _s  → SPACING          (all margins / paddings / gaps)
   _cs → COMPONENT_SIZES  (badges, borders, radii, letter-spacing, small padding)
   _ls → LAYOUT_SIZES     (structural dimensions — not used in QSS)

4. COMPONENT_SIZES is the correct source for:
   - border-radius values
   - badge widths and paddings
   - letter-spacing values
   - border widths
   - small inline padding overrides

Run scripts/enforce_tokens.py to catch violations automatically.
"""

from frontend.theme import COLORS as C, FONT as F, SPACING as S, COMPONENT_SIZES as CS

# Convenience aliases
_c  = C
_f  = F
_s  = S
_cs = CS


STYLESHEET = f"""

/* ═══════════════════════════════════════════════════════════
   GLOBAL
   ═══════════════════════════════════════════════════════════ */

* {{
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: {_f["md"]}px;
    color: {_c["text_primary"]};
}}

QMainWindow,
QWidget#centralWidget {{
    background-color: {_c["bg_base"]};
}}


/* ═══════════════════════════════════════════════════════════
   SIDEBAR — LEFT COLUMN
   ═══════════════════════════════════════════════════════════ */

QWidget#leftColumn {{
    background-color: {_c["bg_surface"]};
    border-right: {_cs["border_w"]}px solid {_c["border"]};
}}

/* Brand label */
QPushButton#brandLabel {{
    background-color: {_c["transparent"]};
    border: none;
    border-bottom: {_cs["border_w"]}px solid {_c["border"]};
    color: {_c["accent"]};
    font-size: {_f["sm"]}px;
    font-weight: 700;
    letter-spacing: {_cs["letter_md"]}px;
    padding-left: {_s["xl"]}px;
    text-align: left;
}}

/* Collapse / expand toggle */
QPushButton#toggleButton {{
    background-color: {_c["bg_raised"]};
    border: none;
    border-bottom: {_cs["border_w"]}px solid {_c["border"]};
    color: {_c["text_muted"]};
    font-size: {_f["lg"]}px;
    padding: 0 {_cs["toggle_padding_h"]}px;
    text-align: right;
}}
QPushButton#toggleButton:hover {{
    background-color: {_c["bg_hover"]};
    color: {_c["accent"]};
}}

/* Nav items */
QPushButton#navButton {{
    background-color: {_c["transparent"]};
    border: none;
    border-left: {_cs["nav_border_w"]}px solid {_c["transparent"]};
    color: {_c["text_muted"]};
    font-size: {_f["md"]}px;
    padding: 0 0 0 {_cs["nav_padding_l"]}px;
    text-align: left;
}}
QPushButton#navButton:hover {{
    background-color: {_c["bg_hover"]};
    color: {_c["text_primary"]};
    border-left-color: {_c["border"]};
}}
QPushButton#navButton:checked {{
    background-color: {_c["bg_active"]};
    color: {_c["accent"]};
    border-left-color: {_c["accent"]};
    font-weight: 600;
}}


/* ═══════════════════════════════════════════════════════════
   CONTENT STACK
   ═══════════════════════════════════════════════════════════ */

QStackedWidget#contentStack {{
    background-color: {_c["bg_base"]};
}}


/* ═══════════════════════════════════════════════════════════
   STATUS BAR
   ═══════════════════════════════════════════════════════════ */

QWidget#StatusBar {{
    background-color: {_c["bg_void"]};
    border-top: {_cs["border_w"]}px solid {_c["border"]};
}}
QLabel#statusLabel {{
    color: {_c["accent_green"]};
    font-size: {_f["sm"]}px;
    font-family: "Consolas", "Courier New", monospace;
    letter-spacing: {_cs["letter_half"]}px;
}}


/* ═══════════════════════════════════════════════════════════
   DASHBOARD PAGE
   ═══════════════════════════════════════════════════════════ */

QWidget#dashboardPage {{
    background-color: {_c["bg_base"]};
}}
QWidget#dashContent {{
    background-color: {_c["transparent"]};
}}

/* Page header strip */
QWidget#pageHeader {{
    background-color: {_c["bg_base"]};
    border-bottom: {_cs["border_w"]}px solid {_c["border"]};
}}
QLabel#pageHeaderTitle {{
    color: {_c["text_primary"]};
    font-size: {_f["md"]}px;
    font-weight: 700;
    letter-spacing: {_cs["letter_lg"]}px;
}}
QLabel#pageHeaderMeta {{
    color: {_c["text_dim"]};
    font-size: {_f["sm"]}px;
    font-family: "Consolas", "Courier New", monospace;
}}


/* ═══════════════════════════════════════════════════════════
   KPI TILES
   ═══════════════════════════════════════════════════════════ */

QWidget#kpiTile {{
    background-color: {_c["bg_surface"]};
    border: {_cs["border_w"]}px solid {_c["border"]};
    border-radius: {_cs["border_radius_lg"]}px;
}}
QLabel#kpiTitle {{
    color: {_c["text_muted"]};
    font-size: {_f["sm"]}px;
    font-weight: 600;
    letter-spacing: {_cs["letter_sm"]}px;
}}
QLabel#kpiUnit {{
    color: {_c["text_dim"]};
    font-size: {_f["sm_body"]}px;
    font-weight: 500;
}}

/* Value accent variants */
QLabel#kpiValue,
QLabel#kpiValueAccent {{
    color: {_c["accent"]};
    font-size: {_f["xxl"]}px;
    font-weight: 700;
    font-family: "Consolas", "Courier New", monospace;
}}
QLabel#kpiValueRed {{
    color: {_c["accent_red"]};
    font-size: {_f["xxl"]}px;
    font-weight: 700;
    font-family: "Consolas", "Courier New", monospace;
}}
QLabel#kpiValueAmber {{
    color: {_c["accent_amber"]};
    font-size: {_f["xxl"]}px;
    font-weight: 700;
    font-family: "Consolas", "Courier New", monospace;
}}
QLabel#kpiValueGreen {{
    color: {_c["accent_green"]};
    font-size: {_f["xxl"]}px;
    font-weight: 700;
    font-family: "Consolas", "Courier New", monospace;
}}


/* ═══════════════════════════════════════════════════════════
   SHARED PANEL CHROME
   ═══════════════════════════════════════════════════════════ */

QWidget#dashPanel {{
    background-color: {_c["bg_surface"]};
    border: {_cs["border_w"]}px solid {_c["border"]};
    border-radius: {_cs["border_radius_lg"]}px;
}}
QWidget#panelHeader {{
    background-color: {_c["bg_void"]};
    border-bottom: {_cs["border_w"]}px solid {_c["border"]};
    border-top-left-radius: {_cs["border_radius_lg"]}px;
    border-top-right-radius: {_cs["border_radius_lg"]}px;
}}
QLabel#panelTitle {{
    color: {_c["accent"]};
    font-size: {_f["sm"]}px;
    font-weight: 700;
    letter-spacing: {_cs["letter_sm"]}px;
}}
QLabel#panelSubtitle {{
    color: {_c["text_dim"]};
    font-size: {_f["sm"]}px;
    letter-spacing: {_cs["letter_xs"]}px;
}}
QWidget#scrollInner {{
    background-color: {_c["transparent"]};
}}

/* Themed scrollbar for alert feed and any other scroll areas */
QScrollArea#transparentScroll {{
    background-color: {_c["transparent"]};
}}
QScrollBar:vertical {{
    background-color: {_c["bg_surface"]};
    width: {_s["md"]}px;
    margin: {_s["none"]}px;
}}
QScrollBar::handle:vertical {{
    background-color: {_c["border"]};
    border-radius: {_cs["border_radius_sm"]}px;
    min-height: {_s["xxl"]}px;
}}
QScrollBar::handle:vertical:hover {{
    background-color: {_c["text_dim"]};
}}
QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical {{
    height: {_s["none"]}px;
}}


/* ═══════════════════════════════════════════════════════════
   FILTER BAR
   ═══════════════════════════════════════════════════════════ */

QWidget#filterBar {{
    background-color: {_c["bg_void"]};
    border-bottom: {_cs["border_w"]}px solid {_c["border"]};
}}

QLineEdit#filterInput {{
    background-color: {_c["bg_raised"]};
    border: {_cs["border_w"]}px solid {_c["border"]};
    border-radius: {_cs["border_radius_sm"]}px;
    color: {_c["text_primary"]};
    font-size: {_f["sm_body"]}px;
    padding: {_s["xs"]}px {_s["sm"]}px;
    selection-background-color: {_c["accent"]};
}}
QLineEdit#filterInput:focus {{
    border-color: {_c["accent"]};
}}
QLineEdit#filterInput::placeholder {{
    color: {_c["text_dim"]};
}}

QComboBox#filterCombo {{
    background-color: {_c["bg_raised"]};
    border: {_cs["border_w"]}px solid {_c["border"]};
    border-radius: {_cs["border_radius_sm"]}px;
    color: {_c["text_muted"]};
    font-size: {_f["sm"]}px;
    padding: {_s["xs"]}px {_s["sm"]}px;
    min-width: {_s["xxl"]}px;
}}
QComboBox#filterCombo:focus {{
    border-color: {_c["accent"]};
}}
QComboBox#filterCombo::drop-down {{
    border: none;
    width: {_s["lg"]}px;
}}
QComboBox#filterCombo QAbstractItemView {{
    background-color: {_c["bg_raised"]};
    border: {_cs["border_w"]}px solid {_c["border"]};
    color: {_c["text_primary"]};
    selection-background-color: {_c["bg_active"]};
}}


/* ═══════════════════════════════════════════════════════════
   ALERT FEED
   ═══════════════════════════════════════════════════════════ */

QWidget#alertEntry {{
    background-color: {_c["transparent"]};
    border-bottom: {_cs["border_w"]}px solid {_c["border"]};
}}
QWidget#alertEntry:hover {{
    background-color: {_c["bg_raised"]};
}}

/* Severity badges — colour rules only; geometry is set in Python via the
   badge container QWidget (setFixedSize). Do NOT add width, height, padding,
   or margin here — they would fight the Python-enforced fixed geometry. */
QLabel#severityBadgeCritical {{
    color: {_c["accent_red"]};
    font-size: {_f["sm"]}px;
    font-weight: 700;
    letter-spacing: {_cs["letter_xs"]}px;
    border: {_cs["border_w"]}px solid {_c["accent_red"]};
    border-radius: {_cs["border_radius_sm"]}px;
}}
QLabel#severityBadgeHigh {{
    color: {_c["accent_orange"]};
    font-size: {_f["sm"]}px;
    font-weight: 700;
    letter-spacing: {_cs["letter_xs"]}px;
    border: {_cs["border_w"]}px solid {_c["accent_orange"]};
    border-radius: {_cs["border_radius_sm"]}px;
}}
QLabel#severityBadgeMed {{
    color: {_c["accent_amber"]};
    font-size: {_f["sm"]}px;
    font-weight: 700;
    letter-spacing: {_cs["letter_xs"]}px;
    border: {_cs["border_w"]}px solid {_c["accent_amber"]};
    border-radius: {_cs["border_radius_sm"]}px;
}}
QLabel#severityBadgeLow {{
    color: {_c["accent_green"]};
    font-size: {_f["sm"]}px;
    font-weight: 700;
    letter-spacing: {_cs["letter_xs"]}px;
    border: {_cs["border_w"]}px solid {_c["accent_green"]};
    border-radius: {_cs["border_radius_sm"]}px;
}}
QLabel#severityBadgeInfo {{
    color: {_c["accent"]};
    font-size: {_f["sm"]}px;
    font-weight: 700;
    letter-spacing: {_cs["letter_xs"]}px;
    border: {_cs["border_w"]}px solid {_c["accent"]};
    border-radius: {_cs["border_radius_sm"]}px;
}}

/* Alert row labels */
QLabel#alertTimestamp {{
    color: {_c["text_dim"]};
    font-size: {_f["sm"]}px;
    font-family: "Consolas", "Courier New", monospace;
}}
QLabel#alertHost {{
    color: {_c["accent"]};
    font-size: {_f["sm"]}px;
    font-family: "Consolas", "Courier New", monospace;
}}
QLabel#alertDesc {{
    color: {_c["text_primary"]};
    font-size: {_f["sm_body"]}px;
}}

/* Empty-state label (shown when filter yields no results) */
QLabel#emptyLabel {{
    color: {_c["text_dim"]};
    font-size: {_f["sm_body"]}px;
    padding: {_s["lg"]}px;
}}

/* Waiting-for-traffic placeholder (shown before first real alert) */
QLabel#waitingLabel {{
    color: {_c["text_dim"]};
    font-size: {_f["sm_body"]}px;
    padding: {_s["lg"]}px;
}}


/* ═══════════════════════════════════════════════════════════
   RETRAIN BASELINE BUTTON
   ═══════════════════════════════════════════════════════════ */

QPushButton#retrainBaselineBtn {{
    background-color: {_c["bg_void"]};
    border: none;
    border-bottom: {_cs["border_w"]}px solid {_c["border"]};
    color: {_c["accent_amber"]};
    font-size: {_f["sm"]}px;
    font-weight: 700;
    letter-spacing: {_cs["letter_sm"]}px;
    padding: {_s["sm"]}px {_s["lg"]}px;
    text-align: left;
}}
QPushButton#retrainBaselineBtn:hover {{
    background-color: {_c["bg_hover"]};
    color: {_c["accent"]};
    border-bottom-color: {_c["accent_amber"]};
}}
QPushButton#retrainBaselineBtn:disabled {{
    color: {_c["text_dim"]};
    border-bottom-color: {_c["border"]};
}}


/* ═══════════════════════════════════════════════════════════
   HOST METRIC CARDS
   ═══════════════════════════════════════════════════════════ */

QWidget#hostCard {{
    background-color: {_c["bg_base"]};
    border: {_cs["border_w"]}px solid {_c["border"]};
    border-radius: {_cs["border_radius_md"]}px;
}}
QLabel#hostName {{
    color: {_c["accent"]};
    font-size: {_f["md"]}px;
    font-weight: 600;
    font-family: "Consolas", "Courier New", monospace;
}}
QLabel#metricLabel {{
    color: {_c["text_dim"]};
    font-size: {_f["xs"]}px;
    letter-spacing: {_cs["letter_xs"]}px;
}}
QLabel#metricValue {{
    color: {_c["text_primary"]};
    font-size: {_f["md"]}px;
    font-weight: 600;
    font-family: "Consolas", "Courier New", monospace;
}}
QWidget#sparklineBar {{
    background-color: {_c["sparkline_bg"]};
    border-radius: {_cs["border_radius_sm"]}px;
}}

/* Novelty badges — one per _classify_novelty() return value */

/* KNOWN — green: host has a trained baseline */
QPushButton#noveltyBadgeKnown {{
    background-color: {_c["transparent"]};
    border: {_cs["border_w"]}px solid {_c["accent_green"]};
    border-radius: {_cs["border_radius_sm"]}px;
    color: {_c["accent_green"]};
    font-size: {_f["xs"]}px;
    font-weight: 700;
    letter-spacing: {_cs["letter_xs"]}px;
    padding: {_cs["badge_padding_v"]}px {_cs["badge_padding_h"]}px;
}}
QPushButton#noveltyBadgeKnown:hover {{
    background-color: {_c["bg_hover"]};
}}

/* NEW — amber: first-seen host, below recurring threshold */
QPushButton#noveltyBadgeNew {{
    background-color: {_c["transparent"]};
    border: {_cs["border_w"]}px solid {_c["accent_amber"]};
    border-radius: {_cs["border_radius_sm"]}px;
    color: {_c["accent_amber"]};
    font-size: {_f["xs"]}px;
    font-weight: 700;
    letter-spacing: {_cs["letter_xs"]}px;
    padding: {_cs["badge_padding_v"]}px {_cs["badge_padding_h"]}px;
}}
QPushButton#noveltyBadgeNew:hover {{
    background-color: {_c["bg_hover"]};
    border-color: {_c["accent"]};
    color: {_c["accent"]};
}}

/* RECURRING — orange: seen frequently, above SYN threshold */
QPushButton#noveltyBadgeRecurring {{
    background-color: {_c["transparent"]};
    border: {_cs["border_w"]}px solid {_c["accent_orange"]};
    border-radius: {_cs["border_radius_sm"]}px;
    color: {_c["accent_orange"]};
    font-size: {_f["xs"]}px;
    font-weight: 700;
    letter-spacing: {_cs["letter_xs"]}px;
    padding: {_cs["badge_padding_v"]}px {_cs["badge_padding_h"]}px;
}}
QPushButton#noveltyBadgeRecurring:hover {{
    background-color: {_c["bg_hover"]};
    border-color: {_c["accent"]};
    color: {_c["accent"]};
}}

/* LOOPBACK — muted: 127.x.x.x / loopback traffic */
QPushButton#noveltyBadgeLoopback {{
    background-color: {_c["transparent"]};
    border: {_cs["border_w"]}px solid {_c["border"]};
    border-radius: {_cs["border_radius_sm"]}px;
    color: {_c["text_dim"]};
    font-size: {_f["xs"]}px;
    font-weight: 700;
    letter-spacing: {_cs["letter_xs"]}px;
    padding: {_cs["badge_padding_v"]}px {_cs["badge_padding_h"]}px;
}}
QPushButton#noveltyBadgeLoopback:hover {{
    background-color: {_c["bg_hover"]};
    border-color: {_c["text_muted"]};
    color: {_c["text_muted"]};
}}


/* ═══════════════════════════════════════════════════════════
   BASELINE POPUP DIALOG
   ═══════════════════════════════════════════════════════════ */

QDialog#baselinePopup {{
    background-color: {_c["bg_surface"]};
    border: {_cs["border_w"]}px solid {_c["border"]};
}}
QLabel#popupHostLabel {{
    color: {_c["accent"]};
    font-size: {_f["md"]}px;
    font-weight: 700;
    font-family: "Consolas", "Courier New", monospace;
    letter-spacing: {_cs["letter_sm"]}px;
}}
QFrame#popupSeparator {{
    color: {_c["border"]};
}}
QLabel#popupKey {{
    color: {_c["text_muted"]};
    font-size: {_f["sm_body"]}px;
}}
QLabel#popupValue {{
    color: {_c["text_primary"]};
    font-size: {_f["sm_body"]}px;
    font-weight: 600;
    font-family: "Consolas", "Courier New", monospace;
}}
QLabel#popupEmpty {{
    color: {_c["text_dim"]};
    font-size: {_f["sm_body"]}px;
    padding: {_s["lg"]}px;
}}


/* ═══════════════════════════════════════════════════════════
   SYSTEM LOGS PANEL
   ═══════════════════════════════════════════════════════════ */

QWidget#logsPanel {{
    background-color: {_c["transparent"]};
}}

QPushButton#logsToggleBtn {{
    background-color: {_c["bg_void"]};
    border: {_cs["border_w"]}px solid {_c["border"]};
    border-radius: {_cs["border_radius_sm"]}px;
    color: {_c["text_muted"]};
    font-size: {_f["sm"]}px;
    font-weight: 600;
    letter-spacing: {_cs["letter_xs"]}px;
    padding: 0 {_s["lg"]}px;
    text-align: left;
}}
QPushButton#logsToggleBtn:hover {{
    background-color: {_c["bg_hover"]};
    color: {_c["accent"]};
    border-color: {_c["accent"]};
}}

QWidget#logsBody {{
    background-color: {_c["bg_surface"]};
    border: {_cs["border_w"]}px solid {_c["border"]};
    border-top: none;
    border-bottom-left-radius: {_cs["border_radius_sm"]}px;
    border-bottom-right-radius: {_cs["border_radius_sm"]}px;
}}

QWidget#logEntry {{
    background-color: {_c["transparent"]};
    border-bottom: {_cs["border_w"]}px solid {_c["border"]};
}}
QWidget#logEntry:hover {{
    background-color: {_c["bg_raised"]};
}}

QLabel#logTimestamp {{
    color: {_c["text_dim"]};
    font-size: {_f["sm"]}px;
    font-family: "Consolas", "Courier New", monospace;
}}

/* Log level badges — colour-coded by severity */
QLabel#logLevelInfo {{
    color: {_c["accent"]};
    font-size: {_f["sm"]}px;
    font-weight: 700;
}}
QLabel#logLevelWarn {{
    color: {_c["accent_amber"]};
    font-size: {_f["sm"]}px;
    font-weight: 700;
}}
QLabel#logLevelErr {{
    color: {_c["accent_red"]};
    font-size: {_f["sm"]}px;
    font-weight: 700;
}}

QLabel#logText {{
    color: {_c["text_primary"]};
    font-size: {_f["sm_body"]}px;
}}


/* ═══════════════════════════════════════════════════════════
   BOTTOM BAR
   ═══════════════════════════════════════════════════════════ */

QWidget#dashBottomBar {{
    background-color: {_c["bg_void"]};
    border-top: {_cs["border_w"]}px solid {_c["border"]};
}}
QLabel#heartbeatPulse {{
    color: {_c["accent_green"]};
    font-size: {_f["sm_body"]}px;
}}
QLabel#heartbeatLabel {{
    color: {_c["text_muted"]};
    font-size: {_f["sm"]}px;
    font-family: "Consolas", "Courier New", monospace;
    letter-spacing: {_cs["letter_half"]}px;
}}
QLabel#noStallBadge {{
    color: {_c["accent_green"]};
    font-size: {_f["sm"]}px;
    font-weight: 700;
    letter-spacing: {_cs["letter_xs"]}px;
    border: {_cs["border_w"]}px solid {_c["accent_green"]};
    border-radius: {_cs["border_radius_sm"]}px;
    padding: {_cs["stall_badge_pv"]}px {_cs["stall_badge_ph"]}px;
}}
QLabel#stallBadge {{
    color: {_c["accent_red"]};
    font-size: {_f["sm"]}px;
    font-weight: 700;
    letter-spacing: {_cs["letter_xs"]}px;
    border: {_cs["border_w"]}px solid {_c["accent_red"]};
    border-radius: {_cs["border_radius_sm"]}px;
    padding: {_cs["stall_badge_pv"]}px {_cs["stall_badge_ph"]}px;
}}
QLabel#queueLabel {{
    color: {_c["text_dim"]};
    font-size: {_f["sm"]}px;
    font-family: "Consolas", "Courier New", monospace;
}}

"""