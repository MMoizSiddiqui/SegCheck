"""Launching and running: a second launch, a restart mid-run, and what Step 4 shows while an audit runs."""
from datetime import timedelta

from test_audit_flow import BASE, local, no_worker, post, setup_audit  # noqa: F401
from test_environment_workflow import app  # noqa: F401
from segcheck_web.extensions import db
from segcheck_web.models import Assessment
from segcheck_web.models.jobs import AssessmentJob, AssessmentLease
from segcheck_web.services import assessment_jobs


def _launch(client):
    return post(client, "/audit/launch", {"mode": "standard", "pack": "pci-cde-isolation", "groups": ["database"]})


def test_second_launch_is_refused_and_step4_links_to_the_running_audit(app, authenticated_client, local, no_worker):
    setup_audit(authenticated_client)
    first = _launch(authenticated_client)
    assert "/jobs/" in first.headers["Location"]
    second = _launch(authenticated_client)
    page = authenticated_client.get(second.headers["Location"], base_url=BASE).data
    assert b"Another audit is still running" in page
    assert b"An audit is running now" in page and first.headers["Location"].split("/jobs/")[1].encode() in page


def test_audit_running_when_segcheck_restarted_is_shown_as_interrupted_at_once(app, authenticated_client, local, no_worker,
                                                                                monkeypatch):
    setup_audit(authenticated_client)
    job_id = int(_launch(authenticated_client).headers["Location"].rsplit("/", 1)[1])
    # A new SegCheck process: the run was started before it, so no worker can still be running it.
    monkeypatch.setattr(assessment_jobs, "PROCESS_STARTED", assessment_jobs.utc_now() + timedelta(seconds=5))
    status = authenticated_client.get(f"/jobs/{job_id}/status", base_url=BASE).get_json()
    assert status["status"] == "interrupted" and "SegCheck stopped while this audit was running" in status["message"]
    with app.app_context():
        assert db.session.query(AssessmentLease).count() == 0, "a new audit can start straight away"
        assert db.session.query(Assessment).count() == 0, "no half report"
    page = authenticated_client.get("/audit/", base_url=BASE).data
    assert b"An audit is running now" not in page


def test_a_run_from_this_process_is_left_alone(app, authenticated_client, local, no_worker):
    setup_audit(authenticated_client)
    job_id = int(_launch(authenticated_client).headers["Location"].rsplit("/", 1)[1])
    with app.app_context():
        assessment_jobs.expire_stale_jobs()
        assert db.session.get(AssessmentJob, job_id).status in assessment_jobs.ACTIVE
