"""History of audits: open a saved report, download it, or delete audits."""

import json
from io import BytesIO

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, send_file, url_for
from flask_login import current_user

from segcheck_web.extensions import db, login_manager
from segcheck_web.models import Assessment
from segcheck_web.services import history, report_view
from segcheck_web.services.assessment_pdf import AssessmentPDFError, generate_assessment_pdf
from segcheck_web.services.insights import assessment_breakdown
from segcheck_web.services.report_analysis import analyse


assessments_bp = Blueprint(
    "assessments",
    __name__,
    url_prefix="/assessments",
)


@assessments_bp.before_request
def require_authenticated_user():
    """Require authentication for every assessment route."""
    if not current_user.is_authenticated:
        return login_manager.unauthorized()


@assessments_bp.get("/")
def assessment_workspace():
    """History: every past audit, newest first."""
    return render_template("assessments/history.html", rows=history.audits())


def _data_dir():
    from segcheck.storage import resolve_data_dir
    try:
        return resolve_data_dir()
    except (ValueError, OSError):
        return None


@assessments_bp.post("/<int:assessment_id>/delete")
def delete_assessment(assessment_id):
    try:
        history.delete_report(assessment_id)
        flash(f"Audit #{assessment_id} deleted from this PC.", "success")
    except history.HistoryError as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return redirect(url_for("assessments.assessment_workspace"))


@assessments_bp.post("/runs/<int:job_id>/delete")
def delete_run(job_id):
    try:
        history.delete_run(job_id)
        flash("Run deleted.", "success")
    except history.HistoryError as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return redirect(url_for("assessments.assessment_workspace"))


@assessments_bp.post("/delete-all")
def delete_all():
    if request.form.get("confirm") != "DELETE":
        flash("Type DELETE to confirm deleting every audit.", "error")
        return redirect(url_for("assessments.assessment_workspace"))
    data_dir = None if current_app.config.get("TESTING") else _data_dir()
    try:
        removed = history.delete_all(data_dir, firewall_logs=request.form.get("firewall_logs") == "on",
                                     backups=request.form.get("backups") == "on")
        extra = f" Also removed: {', '.join(removed)}." if removed else ""
        flash("Every audit was deleted from this PC." + extra, "success")
    except history.HistoryError as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return redirect(url_for("assessments.assessment_workspace"))


@assessments_bp.get("/<int:assessment_id>")
def assessment_detail(assessment_id):
    """Display one immutable, previously persisted assessment report."""
    if assessment_id < 1:
        abort(404)

    record = db.session.get(Assessment, assessment_id)
    if record is None:
        abort(404)

    return render_template(
        "assessments/detail.html",
        record=record,
        report=record.report,
        results=record.report.get("results", []),
        report_summary=record.report.get("summary", {}),
        assessment_metadata=record.report.get("assessment", {}),
        breakdown=assessment_breakdown(record.report),
        analysis=_analysis(record.report),
        view=report_view.build(record.report),
        run_map=(run_map := report_view.map_data(record)),
        zone_names={zone["key"]: zone["name"] for zone in run_map["zones"]},
    )


def _analysis(report):
    environment = (report.get("assessment") or {}).get("environment") if isinstance(report.get("assessment"), dict) else None
    networks = environment.get("networks", {}) if isinstance(environment, dict) else {}
    result = analyse(report, networks)
    result["by_check"] = {item["row"].get("check_id"): item for item in result["checks"]}
    return result


@assessments_bp.get("/<int:assessment_id>/report.pdf")
def assessment_pdf(assessment_id):
    """Download a PDF rendering of an immutable persisted assessment."""
    if assessment_id < 1:
        abort(404)

    record = db.session.get(Assessment, assessment_id)
    if record is None:
        abort(404)

    try:
        pdf_data = generate_assessment_pdf(record)
    except AssessmentPDFError:
        abort(500)

    return send_file(
        BytesIO(pdf_data),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"segcheck-assessment-{record.id}.pdf",
        max_age=0,
    )


@assessments_bp.get("/<int:assessment_id>/report.json")
def assessment_json(assessment_id):
    """Export the exact saved report, without rerunning or re-evaluating it."""
    record = db.session.get(Assessment, assessment_id)
    if record is None:
        abort(404)
    response = send_file(
        BytesIO(json.dumps(record.report, ensure_ascii=False, allow_nan=False, indent=2).encode("utf-8")),
        mimetype="application/json", as_attachment=True,
        download_name=f"segcheck-assessment-{record.id}.json", max_age=0,
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@assessments_bp.get("/<int:assessment_id>/evidence.zip")
def assessment_evidence_bundle(assessment_id):
    """Download the assessor evidence bundle (PDF, JSON, policy, environment, manifest)."""
    from segcheck_web.services.evidence_bundle import build_bundle
    record = db.session.get(Assessment, assessment_id)
    if record is None:
        abort(404)
    try:
        data = build_bundle(record)
    except AssessmentPDFError:
        abort(500)
    response = send_file(BytesIO(data), mimetype="application/zip", as_attachment=True,
                         download_name=f"segcheck-evidence-{record.id}.zip", max_age=0)
    response.headers["Cache-Control"] = "no-store"
    return response
