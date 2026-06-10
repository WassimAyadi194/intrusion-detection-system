"""
frontend/theme.py
─────────────────
Single source of truth for all design tokens.

Import everywhere as:
    from frontend.theme import COLORS, SPACING, FONT, LAYOUT_SIZES, COMPONENT_SIZES

"""

# ── Color Palette ──────────────────────────────────────────────────────────
#
# Naming convention:
#   bg_*      → surface / background layers (darkest → lightest)
#   border    → divider / outline tone
#   text_*    → foreground text roles
#   accent_*  → interactive / highlight colors

COLORS: dict[str, str] = {
    # Backgrounds (dark → mid)
    "bg_void":      "#080C16",   # deepest — status bar, panel headers, bottom bar
    "bg_base":      "#0B0F1A",   # primary page / content background
    "bg_surface":   "#0D1120",   # raised surfaces — sidebar, KPI tiles, panels
    "bg_raised":    "#111827",   # hover states, toggle button fill
    "bg_active":    "#162033",   # nav button checked state
    "bg_hover":     "#1A2236",   # general hover fill

    # Borders
    "border":       "#1E2A45",   # all dividers and outlines

    # Text roles
    "text_primary": "#E2E8F0",   # body / default label text
    "text_muted":   "#94A3B8",   # secondary labels, nav idle, heartbeat label
    "text_dim":     "#334155",   # de-emphasised text — timestamps, meta, subtitles

    # Accents
    "accent":       "#00D4FF",   # primary brand accent — active nav, panel titles, links
    "accent_green":  "#3ECC8A",   # success / running / low-severity
    "accent_amber":  "#fca800",   # warning / medium-severity (MED badge)
    "accent_orange": "#fc6203",   # high-severity (HIGH badge — darker orange)
    "accent_red":    "#EF4444",   # critical-severity (CRITICAL badge)

    # Structural
    "sparkline_bg": "#1E2A45",   # sparkline / mini-chart bar fill
    "transparent":  "transparent",
}


# ── Spacing Scale ──────────────────────────────────────────────────────────
#
# Used for setContentsMargins() and setSpacing() in all UI files.
# Normalize to nearest token — do not invent new values.
#
#   none=0  xs=2  sm=4  md=8  lg=12  xl=16  xxl=20

SPACING: dict[str, int] = {
    "none": 0,
    "xs":   2,
    "sm":   4,
    "md":   8,
    "lg":   12,
    "xl":   16,
    "xxl":  20,
}


# ── Font Size Scale ────────────────────────────────────────────────────────
#
# Used exclusively in styles.py via f-string injection into QSS.
# NEVER reference raw pixel sizes or arithmetic on tokens in QSS directly.
#
# Role mapping (enforce consistently across all components):
#   xs      → tiny/meta text: metric labels, sub-captions          (10px)
#   sm      → secondary labels: timestamps, badges, mono UI text   (11px)
#   sm_body → de-emphasised body: unit labels, feed descriptions   (12px)
#   md      → default body text: nav, headers, metric values       (13px)
#   lg      → important labels: toggle button icon                 (14px)
#   xl      → (reserved / future use)                              (16px)
#   xxl     → KPI big values                                       (28px)
#   display → large page titles                                     (32px)

FONT: dict[str, int] = {
    "xs":      10,
    "sm":      11,
    "sm_body": 12, 
    "md":      13,
    "lg":      14,
    "xl":      16,
    "xxl":     28,
    "display": 32,
}


# ── Layout Sizes ───────────────────────────────────────────────────────────
#
# Structural layout dimensions for containers, panels, rows, and sidebars.
# These govern the OUTER SHELL of UI regions — not internal component details.

LAYOUT_SIZES: dict[str, int] = {
    "panel_header_h":       40,   # shared height for all panel header bars
    "page_header_h":        64,   # top page breadcrumb / title strip
    "bottom_bar_h":         40,   # global bottom status / heartbeat bar
    "status_bar_h":         32,   # application-level status bar (main window)
    "kpi_tile_h":           96,   # KPI tile card height
    "row_h":                52,   # standard data-row height (alert feed, table rows)
    "card_h":              100,   # generic metric/host card height
    "logs_panel_h":        600,   # max height of the expanded collapsible logs panel
    "baseline_popup_w":    320,   # minimum width of the baseline detail popup dialog
    "sidebar_w_expanded":  300,   # sidebar at full width
    "sidebar_w_collapsed":  56,   # sidebar icon-only collapsed width
    "nav_button_h":         44,   # nav button and toggle button height
    "brand_label_h":        52,   # brand / app name label height
}


# ── Component Sizes ────────────────────────────────────────────────────────
#
# Small internal UI element constraints — NOT structural layout.
# Used inside components: badges, sparklines, icons, inline indicators.


COMPONENT_SIZES: dict[str, int] = {
    "badge_w":            38,   # severity badge visual width (HIGH / MED / LOW / INFO labels)
    "badge_w_lg":         64,   # severity badge visual width for longer labels (CRITICAL)
    "badge_col_w":        64,   # badge COLUMN reservation — every row uses this, keeps columns aligned
    "badge_h":            20,   # severity badge fixed height (all severity levels)
    "badge_padding_v":     1,   # severity badge vertical padding (px, QSS only)
    "badge_padding_h":     5,   # severity badge horizontal padding (px, QSS only)
    "baseline_badge_w":   90,   # fixed width for novelty badge (KNOWN / NEW / RECURRING / LOOPBACK)
    "stall_badge_pv":      2,   # NO STALL badge vertical padding
    "stall_badge_ph":      8,   # NO STALL badge horizontal padding
    "sparkline_h":         6,   # sparkline bar height inside host cards
    "timestamp_col_w":    68,   # fixed width: timestamp column in feed rows
    "host_col_w":        110,   # fixed width: host/IP column in feed rows
    "nav_border_w":        3,   # left-border accent on active nav items (px, QSS only)
    "border_w":            1,   # standard 1px border (dividers, outlines)
    "border_radius_lg":    6,   # panel / tile border-radius
    "border_radius_md":    5,   # host card border-radius
    "border_radius_sm":    3,   # badge / sparkline border-radius
    "letter_xs":           1,   # letter-spacing 1px   (badge, subtitle mono)
    "letter_sm":         1.5,   # letter-spacing 1.5px (panel title, KPI title)
    "letter_md":           2,   # letter-spacing 2px   (brand label)
    "letter_lg":           3,   # letter-spacing 3px   (page header title)
    "letter_xl":           4,   # letter-spacing 4px   (page display title)
    "letter_half":       0.5,   # letter-spacing 0.5px (status / heartbeat mono)
    "toggle_padding_h":   12,   # horizontal padding inside toggle button
    "nav_padding_l":      14,   # left-padding inside nav button items
    "metric_col_w":       72,   # fixed width for host card metric columns (label + value)
}