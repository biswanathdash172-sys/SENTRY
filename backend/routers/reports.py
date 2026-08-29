"""
routers/reports.py
-------------------
Automated Reporting / Export to PPT (Item 4). Generates a real .pptx file
server-side using python-pptx, built ENTIRELY from live Supabase data via
the same queries analytics.py and employees.py use — no placeholder
numbers, no dummy chart data. If a section would otherwise be empty
(e.g. zero completed flags so far), the slide says so explicitly rather
than inventing a number.

Uses python-pptx's NATIVE chart support (CategoryChartData + embedded
XL_CHART_TYPE) — this produces a real, editable PowerPoint chart object,
not a pasted-in image, so the Organization can open it and the chart is
a first-class native PPT element.
"""

from __future__ import annotations

import io
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse

from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.chart.data import CategoryChartData
from pptx.enum.chart import XL_CHART_TYPE
from pptx.dml.color import RGBColor

from models import AdminUser
from routers.org_auth import require_admin
from routers.analytics import get_analytics

router = APIRouter(tags=["reports"])

# SENTRY brand colors, matching the dashboard's CSS variables
COLOR_BG = RGBColor(0x0A, 0x0E, 0x27)
COLOR_ACCENT = RGBColor(0x3B, 0x5B, 0xFF)
COLOR_CYAN = RGBColor(0x22, 0xD3, 0xEE)
COLOR_NOT_RISKY = RGBColor(0x22, 0xD3, 0xEE)
COLOR_PART_RISKY = RGBColor(0xF5, 0x9E, 0x0B)
COLOR_HIGH_RISKY = RGBColor(0xEF, 0x5B, 0x5B)
COLOR_TEXT = RGBColor(0xFF, 0xFF, 0xFF)
COLOR_MUTED = RGBColor(0x94, 0xA3, 0xB8)


def _add_title_slide(prs, org_id: str):
    slide = prs.slides.add_slide(prs.slide_layouts[6])  # blank layout
    bg = slide.background
    bg.fill.solid()
    bg.fill.fore_color.rgb = COLOR_BG

    title_box = slide.shapes.add_textbox(Inches(0.7), Inches(2.6), Inches(8.6), Inches(1.2))
    tf = title_box.text_frame
    tf.text = "SENTRY — Organizational Risk Report"
    tf.paragraphs[0].font.size = Pt(36)
    tf.paragraphs[0].font.bold = True
    tf.paragraphs[0].font.color.rgb = COLOR_TEXT

    sub_box = slide.shapes.add_textbox(Inches(0.7), Inches(3.7), Inches(8.6), Inches(0.8))
    sub_tf = sub_box.text_frame
    sub_tf.text = f"Organization: {org_id}  |  Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
    sub_tf.paragraphs[0].font.size = Pt(14)
    sub_tf.paragraphs[0].font.color.rgb = COLOR_MUTED


def _add_summary_slide(prs, analytics):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    slide.background.fill.solid()
    slide.background.fill.fore_color.rgb = COLOR_BG

    title_box = slide.shapes.add_textbox(Inches(0.5), Inches(0.4), Inches(9), Inches(0.7))
    title_box.text_frame.text = "Summary"
    title_box.text_frame.paragraphs[0].font.size = Pt(28)
    title_box.text_frame.paragraphs[0].font.bold = True
    title_box.text_frame.paragraphs[0].font.color.rgb = COLOR_CYAN

    lines = [
        f"Total risk items scanned: {analytics.total_scanned}",
        f"Not Risky: {analytics.tier_counts['not_risky']}",
        f"Part Risky: {analytics.tier_counts['part_risky']}",
        f"High Risky: {analytics.tier_counts['high_risky']}",
        "",
        f"Pending: {analytics.status_counts['pending']}",
        f"Completed: {analytics.status_counts['completed']}",
        "",
        f"Auto-approved: {analytics.resolution_breakdown['auto_approved']}",
        f"Admin-approved: {analytics.resolution_breakdown['admin_approved']}",
        f"Admin-denied: {analytics.resolution_breakdown['admin_denied']}",
        "",
        (f"Average resolution time: {analytics.avg_resolution_minutes} minutes"
         if analytics.avg_resolution_minutes is not None
         else "Average resolution time: no completed items yet — not enough "
              "data to compute a real average (shown honestly, not as 0)."),
    ]

    body_box = slide.shapes.add_textbox(Inches(0.7), Inches(1.3), Inches(8.5), Inches(5.5))
    tf = body_box.text_frame
    tf.word_wrap = True
    for i, line in enumerate(lines):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.text = line
        p.font.size = Pt(16)
        p.font.color.rgb = COLOR_TEXT


def _add_tier_chart_slide(prs, analytics):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    slide.background.fill.solid()
    slide.background.fill.fore_color.rgb = COLOR_BG

    title_box = slide.shapes.add_textbox(Inches(0.5), Inches(0.4), Inches(9), Inches(0.7))
    title_box.text_frame.text = "Risk Distribution by Tier"
    title_box.text_frame.paragraphs[0].font.size = Pt(28)
    title_box.text_frame.paragraphs[0].font.bold = True
    title_box.text_frame.paragraphs[0].font.color.rgb = COLOR_CYAN

    chart_data = CategoryChartData()
    chart_data.categories = ["Not Risky", "Part Risky", "High Risky"]
    chart_data.add_series("Risk Count", (
        analytics.tier_counts["not_risky"],
        analytics.tier_counts["part_risky"],
        analytics.tier_counts["high_risky"],
    ))

    x, y, cx, cy = Inches(0.7), Inches(1.4), Inches(8.5), Inches(5.2)
    graphic_frame = slide.shapes.add_chart(XL_CHART_TYPE.COLUMN_CLUSTERED, x, y, cx, cy, chart_data)
    chart = graphic_frame.chart
    chart.has_legend = False
    plot = chart.plots[0]
    plot.has_data_labels = True

    # Color each bar to match the dashboard's tier colors
    series = chart.series[0]
    tier_colors = [COLOR_NOT_RISKY, COLOR_PART_RISKY, COLOR_HIGH_RISKY]
    for i, point in enumerate(series.points):
        point.format.fill.solid()
        point.format.fill.fore_color.rgb = tier_colors[i]


def _add_trend_chart_slide(prs, analytics):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    slide.background.fill.solid()
    slide.background.fill.fore_color.rgb = COLOR_BG

    title_box = slide.shapes.add_textbox(Inches(0.5), Inches(0.4), Inches(9), Inches(0.7))
    title_box.text_frame.text = "Risk Frequency — Last 7 Days"
    title_box.text_frame.paragraphs[0].font.size = Pt(28)
    title_box.text_frame.paragraphs[0].font.bold = True
    title_box.text_frame.paragraphs[0].font.color.rgb = COLOR_CYAN

    chart_data = CategoryChartData()
    chart_data.categories = [d["date"] for d in analytics.daily_counts]
    chart_data.add_series("Risks Detected", tuple(d["count"] for d in analytics.daily_counts))

    x, y, cx, cy = Inches(0.7), Inches(1.4), Inches(8.5), Inches(5.2)
    graphic_frame = slide.shapes.add_chart(XL_CHART_TYPE.LINE_MARKERS, x, y, cx, cy, chart_data)
    graphic_frame.chart.has_legend = False


def _add_employee_slide(prs, employees):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    slide.background.fill.solid()
    slide.background.fill.fore_color.rgb = COLOR_BG

    title_box = slide.shapes.add_textbox(Inches(0.5), Inches(0.4), Inches(9), Inches(0.7))
    title_box.text_frame.text = "Employee Roster"
    title_box.text_frame.paragraphs[0].font.size = Pt(28)
    title_box.text_frame.paragraphs[0].font.bold = True
    title_box.text_frame.paragraphs[0].font.color.rgb = COLOR_CYAN

    if not employees:
        empty_box = slide.shapes.add_textbox(Inches(0.7), Inches(1.5), Inches(8), Inches(1))
        empty_box.text_frame.text = "No employees on record for this organization."
        empty_box.text_frame.paragraphs[0].font.color.rgb = COLOR_MUTED
        return

    rows = len(employees) + 1
    cols = 2
    table_shape = slide.shapes.add_table(rows, cols, Inches(0.7), Inches(1.4), Inches(8.5), Inches(0.5) * rows)
    table = table_shape.table
    table.cell(0, 0).text = "Employee ID"
    table.cell(0, 1).text = "Role"
    for r, emp in enumerate(employees, start=1):
        table.cell(r, 0).text = emp.employee_id
        table.cell(r, 1).text = "Admin" if emp.is_admin else "Employee"


@router.get("/reports/export")
def export_report(admin: AdminUser = Depends(require_admin)):
    """
    ADMIN ONLY. Builds a real .pptx in memory from live data and streams
    it back as a download — nothing is written to disk server-side.
    """
    from services.supabase_service import list_employees, SupabaseAuthError

    analytics = get_analytics(admin=admin)  # reuses the exact same real query as GET /analytics

    try:
        employees = list_employees(admin.org_id)
    except SupabaseAuthError as exc:
        raise HTTPException(status_code=500, detail=f"Could not load employee data for report: {exc}")

    prs = Presentation()
    prs.slide_width = Inches(10)
    prs.slide_height = Inches(6.25)

    _add_title_slide(prs, admin.org_id)
    _add_summary_slide(prs, analytics)
    _add_tier_chart_slide(prs, analytics)
    _add_trend_chart_slide(prs, analytics)
    _add_employee_slide(prs, employees)

    buffer = io.BytesIO()
    prs.save(buffer)
    buffer.seek(0)

    filename = f"sentry-report-{admin.org_id}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.pptx"
    return StreamingResponse(
        buffer,
        media_type="application/vnd.openxmlformats-officedocument.presentationml.presentation",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )