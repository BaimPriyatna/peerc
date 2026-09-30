"""app/ui/widgets/rich_log.py — selectable chat log and clipboard helper (Phase 38).

SelectableRichLog is the drag-to-select RichLog used for the chat pane;
copy_to_system_clipboard is the platform clipboard shim behind /copy and Ctrl+C.
"""

import shutil
import subprocess

from rich.style import Style
from textual.selection import Selection
from textual.strip import Strip
from textual.widgets import RichLog


def apply_selection_to_strip(strip: Strip, start: int, end: int, style: Style) -> Strip:
    """Apply a visual highlight style to a span within a Textual Strip."""
    cell_len = strip.cell_length
    if cell_len == 0:
        return strip
    if end == -1 or end > cell_len:
        end = cell_len
    start = max(0, min(start, cell_len))
    end = max(0, min(end, cell_len))
    if start >= end:
        return strip

    cuts = []
    if start > 0:
        cuts.append(start)
    cuts.append(end)
    if end < cell_len:
        cuts.append(cell_len)

    parts = list(strip.divide(cuts))
    styled_parts = []
    idx = 0
    if start > 0:
        styled_parts.append(parts[idx])
        idx += 1
    styled_parts.append(parts[idx].apply_style(style))
    idx += 1
    if end < cell_len:
        styled_parts.append(parts[idx])
    return Strip.join(styled_parts)


class SelectableRichLog(RichLog):
    """RichLog with native mouse text selection and cursor offset tracking."""

    ALLOW_SELECT = True

    def get_selection(self, selection: Selection) -> tuple[str, str] | None:
        """Extract plain text lines under the user's mouse selection."""
        text = "\n".join(strip.text.rstrip() for strip in self.lines)
        return selection.extract(text), "\n"

    def render_line(self, y: int) -> Strip:
        """Render line with selection highlighting and character offset metadata."""
        scroll_x, scroll_y = self.scroll_offset
        line_idx = scroll_y + y
        width = self.scrollable_content_region.width

        if line_idx >= len(self.lines):
            return Strip.blank(width, self.rich_style)

        base_strip = self.lines[line_idx]

        selection = self.text_selection
        if selection is not None:
            span = selection.get_span(line_idx)
            if span is not None:
                start, end = span
                try:
                    sel_style = self.screen.get_component_rich_style("screen--selection")
                except Exception:
                    sel_style = None
                if not sel_style or (not sel_style.bgcolor and not sel_style.reverse):
                    sel_style = Style(reverse=True)
                base_strip = apply_selection_to_strip(base_strip, start, end, sel_style)

        line = base_strip.crop_extend(scroll_x, scroll_x + width, self.rich_style)
        line = line.apply_offsets(scroll_x, line_idx)
        return line.apply_style(self.rich_style)


def copy_to_system_clipboard(text: str) -> None:
    """Copy text to system clipboard using Wayland or X11 tools if available."""
    if shutil.which("wl-copy"):
        try:
            proc = subprocess.Popen(["wl-copy"], stdin=subprocess.PIPE)
            proc.communicate(input=text.encode("utf-8"), timeout=0.5)
            return
        except Exception:
            pass
    if shutil.which("xclip"):
        try:
            proc = subprocess.Popen(["xclip", "-selection", "clipboard"], stdin=subprocess.PIPE)
            proc.communicate(input=text.encode("utf-8"), timeout=0.5)
            return
        except Exception:
            pass
    if shutil.which("xsel"):
        try:
            proc = subprocess.Popen(["xsel", "-b", "-i"], stdin=subprocess.PIPE)
            proc.communicate(input=text.encode("utf-8"), timeout=0.5)
            return
        except Exception:
            pass
