"""HTML template rendering for evals reports."""

from html import escape
from pathlib import Path
from string import Template

TEMPLATES_DIR = Path(__file__).parent


def _load(name: str) -> str:
    return (TEMPLATES_DIR / name).read_text()


_CSS = _load("base.css")
_JS = _load("base.js")


def render(title: str, body: str, extra_css: str = "") -> str:
    """Wrap a body HTML string in a full page with shared CSS/JS."""
    return Template("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>$title</title>
<style>
$css
$extra_css
</style>
</head>
<body>
$body
<script>
$js
</script>
</body>
</html>""").substitute(title=title, css=_CSS, extra_css=extra_css, js=_JS, body=body)


def score_histogram(buckets: dict[int, int], max_height: int = 200,
                    bar_width: int = 40, low_color: str = "#a5d6a7",
                    mid_color: str = "#fff176", high_color: str = "#ef5350") -> str:
    """Render a 0-10 score histogram as inline HTML bars."""
    bucket_max = max(buckets.values()) if buckets else 1
    bars = ""
    for b in range(10):
        count = buckets.get(b, 0)
        h = int((count / bucket_max) * max_height) if bucket_max else 0
        label = f"{b}-{b+1}" if b < 9 else "9-10"
        color = low_color if b <= 3 else mid_color if b <= 6 else high_color
        bars += (f'<div style="display:flex;flex-direction:column;align-items:center;gap:4px">'
                 f'<span style="font-size:12px">{count}</span>'
                 f'<div style="width:{bar_width}px;height:{h}px;background:{color};'
                 f'border-radius:4px 4px 0 0;min-height:2px"></div>'
                 f'<span style="font-size:11px;color:#666">{label}</span></div>\n')
    return f'<div style="display:flex;gap:4px;align-items:flex-end;padding:12px 0">{bars}</div>'


def risk_label_bars(dist: dict[str, int]) -> str:
    """Render risk label distribution as horizontal bars."""
    labels = ["none", "low", "medium", "high", "critical", "error"]
    colors = {"none": "#e0e0e0", "low": "#a5d6a7", "medium": "#fff176",
              "high": "#ffab91", "critical": "#ef5350", "error": "#bdbdbd"}
    rmax = max(dist.get(l, 0) for l in labels) or 1
    html = ""
    for label in labels:
        count = dist.get(label, 0)
        w = int((count / rmax) * 100)
        html += (f'<div style="display:flex;align-items:center;gap:8px;margin:4px 0">'
                 f'<span style="width:70px;text-align:right;font-size:13px">{label}</span>'
                 f'<div style="width:{w}%;min-width:2px;height:24px;background:{colors[label]};'
                 f'border-radius:4px;display:flex;align-items:center;padding-left:8px">'
                 f'<span style="font-size:12px;font-weight:600">{count}</span></div></div>\n')
    return html


def eco_filter_options(ecosystems: list[str]) -> str:
    return "".join(f'<option value="{eco}">{eco.upper()}</option>' for eco in ecosystems)
