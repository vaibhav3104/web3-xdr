"""Incident export routes — PDF and CSV."""
from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import StreamingResponse
from typing import Optional
from datetime import datetime
import csv
import io
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/export", tags=["export"])


@router.get("/incidents/csv")
async def export_incidents_csv(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    limit: int = Query(default=1000, le=10000),
):
    """Export incidents as CSV."""
    incidents = await _get_incidents(severity, status, start_date, end_date, limit)

    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "Incident ID", "Title", "Severity", "Status", "Attack Type",
        "Confidence", "Total Loss (USD)", "Affected Chains",
        "Event Count", "Detection Latency (blocks)",
        "First Event", "Last Event", "Created At",
        "Acknowledged By", "Resolved By", "Resolution Notes",
    ])

    for inc in incidents:
        writer.writerow([
            inc.get("incident_id", inc.get("id", "")),
            inc.get("title", ""),
            inc.get("severity", ""),
            inc.get("status", ""),
            inc.get("attack_type", ""),
            inc.get("confidence", ""),
            inc.get("total_loss_usd", ""),
            ", ".join(inc.get("affected_chains", []) or []),
            inc.get("event_count", ""),
            inc.get("detection_latency_blocks", ""),
            inc.get("first_event_time", ""),
            inc.get("last_event_time", ""),
            inc.get("created_at", ""),
            inc.get("acknowledged_by", ""),
            inc.get("resolved_by", ""),
            inc.get("resolution_notes", ""),
        ])

    output.seek(0)
    filename = f"sentinel3_incidents_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/incidents/pdf")
async def export_incidents_pdf(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    limit: int = Query(default=100, le=1000),
):
    """Export incidents as PDF report."""
    incidents = await _get_incidents(severity, status, start_date, end_date, limit)

    pdf_bytes = _generate_pdf(incidents)
    filename = f"sentinel3_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/incident/{incident_id}/pdf")
async def export_single_incident_pdf(incident_id: str):
    """Export a single incident detail as PDF."""
    try:
        from src.database.service import DatabaseService
        incident = await DatabaseService.get_incident_by_id(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        incidents = [incident]
    except ImportError:
        incidents = [{"incident_id": incident_id, "title": "Incident Report", "severity": "unknown"}]

    pdf_bytes = _generate_pdf(incidents, single=True)
    filename = f"sentinel3_incident_{incident_id}.pdf"

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


async def _get_incidents(severity, status, start_date, end_date, limit):
    """Fetch incidents from DB with filters."""
    try:
        from src.database.service import DatabaseService
        incidents = await DatabaseService.get_incidents(
            severity=severity,
            status=status,
            limit=limit,
        )
        return incidents
    except Exception as e:
        logger.warning(f"Failed to fetch incidents for export: {e}")
        return []


def _generate_pdf(incidents: list, single: bool = False) -> bytes:
    """Generate PDF bytes from incident data using reportlab if available, else simple text PDF."""
    try:
        return _generate_pdf_reportlab(incidents, single)
    except ImportError:
        return _generate_pdf_simple(incidents, single)


def _generate_pdf_reportlab(incidents: list, single: bool = False) -> bytes:
    """Generate PDF using reportlab."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.colors import HexColor
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.units import inch

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle("Title", parent=styles["Title"], textColor=HexColor("#3B82F6"))

    elements = []
    elements.append(Paragraph("Sentinel3 — Incident Report", title_style))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]))
    elements.append(Paragraph(f"Total Incidents: {len(incidents)}", styles["Normal"]))
    elements.append(Spacer(1, 20))

    for inc in incidents:
        sev = str(inc.get("severity", "")).upper()
        title = inc.get("title", inc.get("attack_type", "Incident"))
        inc_id = inc.get("incident_id", inc.get("id", "N/A"))

        elements.append(Paragraph(f"<b>{title}</b> [{sev}]", styles["Heading2"]))

        data = [
            ["Field", "Value"],
            ["Incident ID", str(inc_id)],
            ["Severity", sev],
            ["Status", str(inc.get("status", ""))],
            ["Attack Type", str(inc.get("attack_type", ""))],
            ["Confidence", f"{float(inc.get('confidence', 0)):.0%}"],
            ["Total Loss", f"${float(inc.get('total_loss_usd', 0) or 0):,.2f}"],
            ["Chains", ", ".join(inc.get("affected_chains", []) or [])],
            ["Events", str(inc.get("event_count", ""))],
            ["First Event", str(inc.get("first_event_time", ""))],
            ["Last Event", str(inc.get("last_event_time", ""))],
        ]

        if inc.get("resolution_notes"):
            data.append(["Resolution", str(inc.get("resolution_notes", ""))])

        table = Table(data, colWidths=[2 * inch, 4 * inch])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1a1a2e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#FFFFFF")),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#2a2a4a")),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 16))

    doc.build(elements)
    return buffer.getvalue()


def _generate_pdf_simple(incidents: list, single: bool = False) -> bytes:
    """Fallback: generate a minimal PDF without reportlab."""
    lines = []
    lines.append("Sentinel3 Incident Report")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"Total Incidents: {len(incidents)}")
    lines.append("")

    for inc in incidents:
        lines.append(f"--- {inc.get('title', inc.get('attack_type', 'Incident'))} ---")
        lines.append(f"  ID: {inc.get('incident_id', inc.get('id', 'N/A'))}")
        lines.append(f"  Severity: {inc.get('severity', '')}")
        lines.append(f"  Status: {inc.get('status', '')}")
        lines.append(f"  Loss: ${float(inc.get('total_loss_usd', 0) or 0):,.2f}")
        lines.append(f"  Chains: {', '.join(inc.get('affected_chains', []) or [])}")
        lines.append("")

    text = "\n".join(lines)

    # Simple PDF structure
    objects = []

    # Header
    pdf = b"%PDF-1.4\n"

    # Catalog
    objects.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
    objects.append(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")

    stream = b"BT /F1 10 Tf 40 800 Td "
    for line in text.split("\n"):
        safe = line.encode("latin-1", errors="replace")
        stream += b"(" + safe.replace(b"(", b"\\(").replace(b")", b"\\)") + b") Tj 0 -14 Td "
    stream += b"ET"

    stream_obj = (
        b"4 0 obj\n<< /Length "
        + str(len(stream)).encode()
        + b" >>\nstream\n"
        + stream
        + b"\nendstream\nendobj\n"
    )

    objects.append(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842]"
        b" /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n"
    )
    objects.append(stream_obj)
    objects.append(b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj\n")

    offsets = []
    pos = len(pdf)
    for obj in objects:
        offsets.append(pos)
        pdf += obj
        pos += len(obj)

    xref_pos = pos
    pdf += b"xref\n0 6\n0000000000 65535 f \n"
    for off in offsets:
        pdf += f"{off:010d} 00000 n \n".encode()

    pdf += (
        b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n"
        + str(xref_pos).encode()
        + b"\n%%EOF"
    )

    return pdf
