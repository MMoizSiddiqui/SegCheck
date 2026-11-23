"""Authenticated SegCheck overview dashboard."""

from flask import Blueprint, jsonify, render_template
from flask_login import login_required, current_user
from sqlalchemy import func

from ..extensions import db
from ..models import Assessment, Asset, Policy, Zone
from ..services.environment import settings
from ..models.jobs import AssessmentJob
from ..models import utc_now
from ..services.assessment_jobs import expire_stale_jobs
from ..services.insights import assessment_breakdown, build_insights


dashboard_bp = Blueprint("dashboard", __name__)


def _count(query):
    """Return a safe scalar count."""
    return query.scalar() or 0


def result_totals():
    """Checks across every saved audit, counted the way each report counts them
    (a block proven by the firewall log is passed, not "no answer")."""
    totals = {"total": 0, "pass": 0, "fail": 0, "inconclusive": 0}
    for (report,) in db.session.query(Assessment.report).yield_per(50):
        counts = assessment_breakdown(report if isinstance(report, dict) else {})
        for key in ("pass", "fail", "inconclusive"):
            totals[key] += counts[key]
    totals["total"] = totals["pass"] + totals["fail"] + totals["inconclusive"]
    return totals


@dashboard_bp.get("/api/dashboard")
@login_required
def live_snapshot():
    expire_stale_jobs()
    totals = result_totals()
    recent = db.session.query(Assessment.id, Assessment.summary, Assessment.created_at).order_by(Assessment.id.desc()).limit(12).all()
    _, environment = settings()
    zones = db.session.query(Zone.zone_key, Zone.name, func.count(Asset.id)).outerjoin(Asset, (Asset.zone_id == Zone.id) & ~Asset.name.endswith(" interface")).group_by(Zone.id).order_by(Zone.id).limit(12).all()
    job = db.session.query(AssessmentJob).filter_by(actor_user_id=current_user.id).filter(AssessmentJob.status.in_(["queued", "running"])).order_by(AssessmentJob.id.desc()).first()
    response = jsonify({
        "metrics": {"policies": _count(db.session.query(func.count(Policy.id))),
                    "assessments": _count(db.session.query(func.count(Assessment.id))),
                    "zones": _count(db.session.query(func.count(Zone.id))),
                    "assets": _count(db.session.query(func.count(Asset.id)).filter(~Asset.name.endswith(" interface")))},
        "results": totals,
        "recent": [{"id": row.id, "summary": row.summary, "created_at": row.created_at.isoformat()} for row in reversed(recent)],
        "zones": [{"key": key, "name": name, "assets": count,
                   "cidr": environment.get("networks", {}).get(key, {}).get("cidr", "")} for key, name, count in zones],
        "source_ip": environment.get("source_ip", "Not configured"),
        "source_zone": environment.get("source_zone", "Not configured"),
        "active_job": {"id": job.id, "completed": job.completed, "total": job.total,
                       "url": f"/jobs/{job.id}"} if job else None,
        "insights": build_insights(environment, current_user.id),
        "roles": {key: value.get("role", "custom") for key, value in environment.get("networks", {}).items()},
        "generated_at": utc_now().isoformat(),
    })
    response.headers["Cache-Control"] = "no-store"
    return response


@dashboard_bp.get("/")
@login_required
def overview():
    """Render organisation and assessment metrics from persisted records."""

    policy_total = _count(db.session.query(func.count(Policy.id)))
    active_policies = _count(
        db.session.query(func.count(Policy.id)).filter(
            Policy.status == "active"
        )
    )
    draft_policies = _count(
        db.session.query(func.count(Policy.id)).filter(
            Policy.status == "draft"
        )
    )
    archived_policies = _count(
        db.session.query(func.count(Policy.id)).filter(
            Policy.status == "archived"
        )
    )

    assessment_total = _count(
        db.session.query(func.count(Assessment.id))
    )
    zone_total = _count(db.session.query(func.count(Zone.id)))
    asset_total = _count(db.session.query(func.count(Asset.id)).filter(~Asset.name.endswith(" interface")))

    recent_assessments = (
        db.session.query(Assessment)
        .order_by(Assessment.created_at.desc(), Assessment.id.desc())
        .limit(6)
        .all()
    )

    # "Latest audit" card: its verdict in the report's own words. "Current setup" card: what Step 2 holds now.
    latest = None
    if recent_assessments:
        from segcheck_web.services.report_view import build as plain_view
        record = recent_assessments[0]
        view = plain_view(record.report if isinstance(record.report, dict) else {})
        latest = {"id": record.id, "word": view["verdict"]["word"], "tone": view["verdict"]["tone"],
                  "title": view["verdict"]["title"], "name": record.policy.name if record.policy else f"Audit {record.id}",
                  "created_at": record.created_at}
    environment = settings()[1]
    zone_names = {zone.zone_key: zone.name for zone in db.session.query(Zone).all()}
    networks = environment.get("networks", {}) if isinstance(environment.get("networks"), dict) else {}
    setup = {"cde": sum(1 for n in networks.values() if isinstance(n, dict) and n.get("role") == "cde"),
             "here": zone_names.get(environment.get("source_zone", ""), environment.get("source_zone", ""))}

    return render_template(
        "dashboard/index.html",
        latest=latest,
        setup=setup,
        policy_total=policy_total,
        active_policies=active_policies,
        draft_policies=draft_policies,
        archived_policies=archived_policies,
        assessment_total=assessment_total,
        zone_total=zone_total,
        asset_total=asset_total,
        result_totals=result_totals(),
        recent_assessments=recent_assessments,
        environment=settings()[1],
    )


@dashboard_bp.get("/api/runs")
@login_required
def runs_list():
    """The latest audits, oldest first, for the map's run strip."""
    from ..services.report_view import build
    records = db.session.query(Assessment).order_by(Assessment.created_at.desc(), Assessment.id.desc()).limit(20).all()
    runs = [{"id": r.id, "name": r.policy.name if r.policy else f"Audit {r.id}",
             "created_at": r.created_at.isoformat() if r.created_at else None,
             "verdict": build(r.report)["verdict"]} for r in reversed(records)]
    response = jsonify({"runs": runs})
    response.headers["Cache-Control"] = "no-store"
    return response


@dashboard_bp.get("/api/runs/<int:assessment_id>/map")
@login_required
def run_map(assessment_id):
    from flask import abort
    from ..services.report_view import map_data
    record = db.session.get(Assessment, assessment_id)
    if record is None:
        abort(404)
    response = jsonify(map_data(record))
    response.headers["Cache-Control"] = "no-store"
    return response
