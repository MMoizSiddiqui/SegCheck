"""Read-only PDF rendering for persisted SegCheck assessments."""

from io import BytesIO
import json
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

MAX_PDF_BYTES = 20 * 1024 * 1024
MAX_VALUE_CHARS = 3000
MAX_NESTING_DEPTH = 64


class AssessmentPDFError(ValueError):
    """The persisted assessment cannot safely be rendered as a PDF."""


def _display(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (str, int, float)):
        return str(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)


def _paragraph_text(value):
    text = _display(value)
    text = "".join(
        char for char in text
        if char in "\\t\\n\\r"
        or 0x20 <= ord(char) <= 0xD7FF
        or 0xE000 <= ord(char) <= 0xFFFD
        or 0x10000 <= ord(char) <= 0x10FFFF
    )
    chunks = [
        text[index:index + MAX_VALUE_CHARS]
        for index in range(0, max(len(text), 1), MAX_VALUE_CHARS)
    ]
    return "<br/>".join(escape(chunk) for chunk in chunks)


def _render_value(story, value, styles, depth=0, label=None):
    """Render every persisted field without interpreting it as markup."""
    if depth > MAX_NESTING_DEPTH:
        raise AssessmentPDFError("Assessment report nesting exceeds the export limit")

    if label is not None:
        story.append(Paragraph(_paragraph_text(label), styles["FieldLabel"]))

    if isinstance(value, dict):
        if not value:
            story.append(Paragraph("Empty object", styles["BodyText"]))
            return
        for key, child in value.items():
            if depth < 2:
                story.append(Paragraph(
                    _paragraph_text(str(key).replace("_", " ").title()),
                    styles["Section" if depth == 0 else "Subsection"],
                ))
            _render_value(story, child, styles, depth + 1, str(key))
        return

    if isinstance(value, list):
        if not value:
            story.append(Paragraph("No entries recorded.", styles["BodyText"]))
            return
        for index, child in enumerate(value, start=1):
            story.append(Paragraph(f"Entry {index}", styles["Subsection"]))
            _render_value(story, child, styles, depth + 1)
        return

    story.append(Paragraph(_paragraph_text(value), styles["BodyText"]))
    story.append(Spacer(1, 3))


def generate_assessment_pdf(record):
    """Build a PDF exclusively from one already-persisted assessment."""
    try:
        report = record.report
        if not isinstance(report, dict):
            raise AssessmentPDFError("Assessment report is not a valid object")

        buffer = BytesIO()
        document = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=17 * mm,
            leftMargin=17 * mm,
            topMargin=19 * mm,
            bottomMargin=19 * mm,
            title=f"SegCheck Assessment {record.id}",
            author="SegCheck",
            subject="Persisted network segmentation assessment",
        )

        base = getSampleStyleSheet()
        styles = {
            "Title": ParagraphStyle(
                "SegCheckTitle", parent=base["Title"],
                fontSize=20, leading=25, alignment=TA_CENTER,
                textColor=colors.HexColor("#17365D"), spaceAfter=8,
            ),
            "Subtitle": ParagraphStyle(
                "SegCheckSubtitle", parent=base["Normal"],
                fontSize=9, leading=13, alignment=TA_CENTER,
                textColor=colors.HexColor("#53657A"), spaceAfter=14,
            ),
            "Section": ParagraphStyle(
                "SegCheckSection", parent=base["Heading1"],
                fontSize=14, leading=18, textColor=colors.HexColor("#17365D"),
                spaceBefore=13, spaceAfter=6, keepWithNext=True,
            ),
            "Subsection": ParagraphStyle(
                "SegCheckSubsection", parent=base["Heading2"],
                fontSize=10, leading=13, textColor=colors.HexColor("#24527A"),
                spaceBefore=7, spaceAfter=3, keepWithNext=True,
            ),
            "FieldLabel": ParagraphStyle(
                "SegCheckField", parent=base["Normal"],
                fontSize=8, leading=10, textColor=colors.HexColor("#53657A"),
                spaceBefore=3, spaceAfter=1,
            ),
            "BodyText": ParagraphStyle(
                "SegCheckBody", parent=base["BodyText"],
                fontSize=8, leading=11, wordWrap="CJK",
                spaceAfter=3,
            ),
        }

        story = _analyst_story(record, report, styles)
        story.append(PageBreak())
        story.append(Paragraph("Appendix: complete saved record", styles["Section"]))
        story.append(Paragraph("Every field persisted for this assessment, reproduced for the audit trail.", styles["BodyText"]))
        # Compact, complete JSON of the saved record (audit trail), wrapped for print.
        appendix_style = ParagraphStyle("Appendix", parent=styles["BodyText"], fontName="Courier", fontSize=5.6, leading=6.6, wordWrap="CJK")
        raw = json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ": "), allow_nan=False)
        for start in range(0, len(raw), 6000):
            story.append(Paragraph(escape(raw[start:start + 6000]), appendix_style))

        story.append(Spacer(1, 12))
        story.append(HRFlowable(width="100%", color=colors.HexColor("#9AAFC5")))
        story.append(Paragraph(
            "This document reproduces the persisted assessment data. "
            "It does not execute probes, re-evaluate policy checks, authenticate "
            "firewall log senders, or certify compliance with any standard. "
            "Interpret evidence according to the trust limitations recorded "
            "in the assessment.",
            styles["BodyText"],
        ))

        def draw_footer(canvas, _document):
            canvas.saveState()
            canvas.setFont("Helvetica", 7)
            canvas.setFillColor(colors.HexColor("#64748B"))
            canvas.drawString(17 * mm, 10 * mm, "SegCheck · Read-only assessment export")
            canvas.drawRightString(
                A4[0] - 17 * mm, 10 * mm, f"Page {canvas.getPageNumber()}"
            )
            canvas.restoreState()

        document.build(story, onFirstPage=draw_footer, onLaterPages=draw_footer)
        result = buffer.getvalue()
        if not result.startswith(b"%PDF-") or len(result) > MAX_PDF_BYTES:
            raise AssessmentPDFError("Generated PDF exceeds the export limit")
        return result

    except AssessmentPDFError:
        raise
    except Exception as exc:
        raise AssessmentPDFError(
            "The saved assessment could not be rendered as a PDF"
        ) from exc



# --------------------------------------------------------------------------- analyst layout
INK = colors.HexColor("#1F2937")
MUTED = colors.HexColor("#6B7280")
LINE = colors.HexColor("#D9DEE5")
RESULT_FILL = {"FAIL": colors.HexColor("#FDE2E2"), "PASS": colors.HexColor("#DFF5E3"),
               "INCONCLUSIVE": colors.HexColor("#FFF3D6"), "NOT EXERCISED": colors.HexColor("#EEF0F3")}
RESULT_INK = {"FAIL": colors.HexColor("#B42318"), "PASS": colors.HexColor("#1E7B34"),
              "INCONCLUSIVE": colors.HexColor("#9A6700"), "NOT EXERCISED": colors.HexColor("#4B5563")}
STATUS_TEXT = {"violation": ("ACTION REQUIRED", colors.HexColor("#B42318")),
               "enforced": ("DENY ENFORCED", colors.HexColor("#1E7B34")),
               "unproven": ("EVIDENCE NEEDED", colors.HexColor("#9A6700"))}


def _p(text, style):
    return Paragraph(escape(str(text)), style)


def _table(rows, widths, header=True, extra=None):
    table = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    commands = [("FONT", (0, 0), (-1, -1), "Helvetica", 7.5), ("TEXTCOLOR", (0, 0), (-1, -1), INK),
                ("VALIGN", (0, 0), (-1, -1), "TOP"), ("GRID", (0, 0), (-1, -1), 0.4, LINE),
                ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
    if header:
        commands += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F3EEE9")), ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 7.5)]
    table.setStyle(TableStyle(commands + (extra or [])))
    return table


def _analyst_story(record, report, styles):
    from segcheck_web.services.report_analysis import analyse
    assessment = report.get("assessment") if isinstance(report.get("assessment"), dict) else {}
    environment = assessment.get("environment") if isinstance(assessment.get("environment"), dict) else {}
    analysis = analyse(report, environment.get("networks", {}))
    cell = ParagraphStyle("Cell", parent=styles["BodyText"], fontSize=7.2, leading=9, spaceAfter=0)
    small = ParagraphStyle("Small", parent=styles["BodyText"], fontSize=7, leading=9, textColor=MUTED)
    status_text, status_color = STATUS_TEXT[analysis["status"]]
    status_style = ParagraphStyle("Status", parent=styles["Section"], fontSize=12, textColor=status_color, spaceBefore=4)
    policy_name = record.policy.name if record.policy is not None else "Policy unavailable"
    story = [Paragraph("SegCheck Network Segmentation Assessment", styles["Title"]),
             _p(f"Assessment #{record.id} - {policy_name}", styles["Subtitle"]),
             HRFlowable(width="100%", color=LINE), Spacer(1, 6)]
    created = record.created_at.strftime("%Y-%m-%d %H:%M") if record.created_at else "-"
    version = f"v{record.policy_version.version_number}" if record.policy_version is not None else "-"
    identity = [["Organisation", environment.get("organization", "-"), "Site", environment.get("site", "-")],
                ["Probe source", f"{environment.get('source_ip', '-')} ({record.source_zone})", "Created (UTC)", created],
                ["Policy version", version, "Probe run", record.probe_run_id],
                ["Policy SHA-256", record.policy_version_sha256, "", ""]]
    story.append(_table([[_p(c, cell) for c in row] for row in identity], [28 * mm, 60 * mm, 26 * mm, 62 * mm], header=False,
                        extra=[("SPAN", (1, 3), (3, 3)), ("TEXTCOLOR", (0, 0), (0, -1), MUTED), ("TEXTCOLOR", (2, 0), (2, -1), MUTED)]))

    story += [Paragraph("Executive summary", styles["Section"]), Paragraph(status_text, status_style),
              _p(analysis["headline"], ParagraphStyle("Head", parent=styles["BodyText"], fontSize=10, leading=13, fontName="Helvetica-Bold")),
              _p(analysis["meaning"], styles["BodyText"])]
    counts = analysis["counts"]
    story.append(_table([["Checks", "Exercised", "Reachable (FAIL)", "Passed by firewall", "Block corroborated", "Unproven silence", "Not exercised"],
                         [counts["checks"], counts["exercised"], counts["fail"], counts["open_boundary"], counts["corroborated"],
                          counts["unproven"], counts["not_exercised"]]], [25 * mm] * 7))
    from segcheck_web.services.report_view import build as plain_view
    view = plain_view(report)
    verdict = view["verdict"]
    story += [Paragraph("Result in plain words", styles["Section"]),
              _p(f"{verdict['word']}: {verdict['title']}", ParagraphStyle("Verdict", parent=styles["BodyText"], fontSize=11, leading=14,
                                                                      fontName="Helvetica-Bold", textColor=status_color)),
              _p(verdict["sentence"], styles["BodyText"]),
              _p(f"{view['counts']['rules']} rules tested · {view['counts']['passed']} passed · {view['counts']['failed']} failed · "
                 f"{view['counts']['unproven']} no answer (not proven)", small)]
    rule_rows = [["Rule", "Target", "Probe sent", "Expected", "What happened", "Result"]]
    for rule in view["rules"]:
        happened = "; ".join(f"{'ping' if a['protocol'] == 'icmp' else str(a['port'])}: {a['label']}" for a in rule["attempts"]) or "-"
        rule_rows.append([_p(rule["name"], cell), _p(rule["host"], cell), _p(rule["service"], cell), _p(rule["expected"], cell),
                          _p(happened, cell), _p(f"{rule['outcome_label']}. {rule['why']}", cell)])
    story.append(_table(rule_rows, [36 * mm, 20 * mm, 22 * mm, 18 * mm, 34 * mm, 46 * mm]))
    if analysis["findings"]:
        story.append(Paragraph("Priority findings", styles["Subsection"]))
        story.append(_table([["Level", "Finding"]] + [[f["level"].upper(), _p(f["text"], cell)] for f in analysis["findings"]],
                            [22 * mm, 154 * mm]))

    networks = environment.get("networks", {}) if isinstance(environment.get("networks"), dict) else {}
    if networks:
        story.append(Paragraph("Scope and environment", styles["Section"]))
        story.append(_table([["Zone", "Role", "Subnet", "Gateway"]] +
                            [[key, str(value.get("role", "")).upper(), value.get("cidr", ""), value.get("gateway") or "-"]
                             for key, value in networks.items()], [40 * mm, 34 * mm, 56 * mm, 46 * mm]))
        devices = environment.get("devices") or []
        if devices:
            story.append(Paragraph("Declared boundary devices", styles["Subsection"]))
            story.append(_table([["Device", "Type", "Separates", "Log feed"]] +
                                [[_p(d.get("name"), cell), d.get("kind"), _p(", ".join(d.get("zones", [])), cell),
                                  f"{d.get('log_sender_ip')} -> :{d.get('log_port')}" if d.get("logging") else "not connected"] for d in devices],
                                [52 * mm, 24 * mm, 52 * mm, 48 * mm]))
    scope = assessment.get("scope")
    if isinstance(scope, dict) and scope.get("scope_warning"):
        story.append(_p(scope["scope_warning"], small))

    if analysis["controls"]:
        story.append(Paragraph("Control matrix", styles["Section"]))
        rows = [["Framework", "Control", "Checks", "Fail", "Pass", "Inconcl.", "Corrob.", "Not ex.", "Reading"]]
        extra = []
        for index, c in enumerate(analysis["controls"], start=1):
            exercised = c["checks"] - c["NOT EXERCISED"]
            reading = "Gap found" if c["FAIL"] else ("Supported" if exercised and c["corroborated"] == exercised else "Needs evidence")
            rows.append([c["framework"], _p(f"{c['control_id']} {c['title'] or ''}", cell), c["checks"], c["FAIL"], c["PASS"],
                         c["INCONCLUSIVE"], c["corroborated"], c["NOT EXERCISED"], reading])
            key = "FAIL" if reading == "Gap found" else ("PASS" if reading == "Supported" else "INCONCLUSIVE")
            extra.append(("BACKGROUND", (8, index), (8, index), RESULT_FILL[key]))
        story.append(_table(rows, [24 * mm, 50 * mm, 13 * mm, 11 * mm, 11 * mm, 14 * mm, 14 * mm, 14 * mm, 25 * mm], extra=extra))
        story.append(_p("Mappings are supporting traceability for the tested paths, not a statement that the whole control is met.", small))

    if analysis["heatmap"] and analysis["methods"]:
        story.append(Paragraph("Method coverage heatmap", styles["Section"]))
        methods = analysis["methods"]
        width = min(22 * mm, (176 * mm - 44 * mm) / max(1, len(methods)))
        rows, extra = [["Target"] + [m["label"] for m in methods]], []
        for r, target in enumerate(analysis["heatmap"], start=1):
            row = [_p(f"{target['host']} ({target['zone']})", cell)]
            for c, item in enumerate(target["cells"], start=1):
                if item is None:
                    row.append("")
                    continue
                result = item["result"]
                if result == "INCONCLUSIVE":
                    label = "BLOCK OK" if item["evidence"] == "corroborated" else ("FW PASS" if item["evidence"] == "passed" else "?")
                else:
                    label = "-" if result == "NOT EXERCISED" else result
                row.append(label)
                if result == "INCONCLUSIVE" and item["evidence"] == "corroborated":
                    fill = "PASS"
                elif item["evidence"] == "passed":
                    fill = "FAIL"
                else:
                    fill = result
                extra += [("BACKGROUND", (c, r), (c, r), RESULT_FILL.get(fill, RESULT_FILL["NOT EXERCISED"])),
                          ("TEXTCOLOR", (c, r), (c, r), RESULT_INK.get(fill, MUTED)), ("ALIGN", (c, r), (c, r), "CENTER")]
            rows.append(row)
        story.append(_table(rows, [44 * mm] + [width] * len(methods), extra=extra))
        story.append(_p("FAIL = target answered on a denied path. BLOCK OK = no answer and the firewall logged a block. "
                        "FW PASS = firewall let it through. ? = no answer without proof. - = not exercised.", small))

    story.append(Paragraph("Check results and analyst guidance", styles["Section"]))
    for item in analysis["checks"]:
        row = item["row"]
        if row.get("protocol") == "icmp":
            ports = "ICMP echo"
        else:
            ports = f"{str(row.get('protocol', '')).upper()} {', '.join(str(p) for p in row.get('ports') or [])}"
        line = (f"{row.get('source_zone')} -> {row.get('destination_zone')} {row.get('destination_host')} - {ports} - "
                f"expect {str(row.get('expected')).upper()} - firewall: {item['evidence'].replace('_', ' ')}")
        head = _table([[_p(f"{row.get('check_id')} - {row.get('check_name')}", cell), item["result"]], [_p(line, small), ""]],
                      [146 * mm, 30 * mm], header=False,
                      extra=[("SPAN", (1, 0), (1, 1)),
                             ("BACKGROUND", (1, 0), (1, 1), RESULT_FILL.get(item["result"], RESULT_FILL["NOT EXERCISED"])),
                             ("TEXTCOLOR", (1, 0), (1, 1), RESULT_INK.get(item["result"], MUTED)),
                             ("FONT", (1, 0), (1, 1), "Helvetica-Bold", 8), ("VALIGN", (1, 0), (1, 1), "MIDDLE"),
                             ("ALIGN", (1, 0), (1, 1), "CENTER")])
        guidance = [_p("- " + text, cell) for text in item["guidance"]]
        story.append(KeepTogether([head, Spacer(1, 2)] + guidance + [Spacer(1, 5)]))

    boundary = report.get("boundary_evidence")
    if isinstance(boundary, dict):
        summary = boundary.get("summary", {})
        story.append(Paragraph("Firewall log cross-check", styles["Section"]))
        story.append(_table([["Block confirmed", "Passed firewall", "No log match", "Not connected", "Contradictions", "Open at boundary"],
                             [summary.get("logged_block", 0), summary.get("logged_pass", 0), summary.get("no_matching_log", 0),
                              summary.get("not_connected", 0), summary.get("contradictions", 0), summary.get("open_at_boundary", 0)]],
                            [29 * mm] * 6))
        story.append(_p(boundary.get("note", ""), small))

    story += [Spacer(1, 8), HRFlowable(width="100%", color=LINE),
              _p("Decisions: a reply on a denied path is FAIL; silence, refusal or an unreachable route is INCONCLUSIVE and never a pass. "
                 "Firewall logs support, but never change, a decision. This report covers the configured checks only and "
                 "is not a compliance certification.", small)]
    return story
