"""New audit: Step 1 where you are, Step 2 targets, Step 3 firewall, Step 4 checks and launch."""
import os
import secrets
from itertools import zip_longest

from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user

from segcheck.policy_engine import PolicyValidationError
from segcheck_web.extensions import db, login_manager
from segcheck_web.services import audit_setup as audit
from segcheck_web.services import history
from segcheck_web.services.assessment_execution import MAX_WEB_PROBE_ATTEMPTS, AssessmentExecutionError
from segcheck_web.services.assessment_jobs import JobBusy, create_job, running_job, start_worker
from segcheck_web.services.assessment_plan import build_plan
from segcheck_web.services.environment import EnvironmentError, settings
from segcheck_web.services.firewall_connector import evidence_directory, registry
from segcheck_web.services.policy_import import PolicyImportError, import_policy_content
from segcheck_web.services.policy_lifecycle import transition_policy_status
from segcheck_web.services.standard_packs import FAMILIES, PACKS, PROBE_GROUPS, PackError, build_multi_document, build_pack_documents, evaluate_pack

audit_bp = Blueprint("audit", __name__, url_prefix="/audit")


@audit_bp.before_request
def authenticate():
    if not current_user.is_authenticated:
        return login_manager.unauthorized()


def _sync():
    if not current_app.config.get("TESTING"):
        registry(current_app._get_current_object()).sync(settings()[1], evidence_directory())


def _back(step):
    return redirect(url_for("audit.page") + f"#step-{step}")


def _detected():
    from segcheck_web.services.network_discovery import DiscoveryUnavailable, discover_local_network
    try:
        interfaces = discover_local_network().get("interfaces", [])
    except DiscoveryUnavailable:
        return []
    interfaces = [i for i in interfaces if i.get("family") == "IPv4" or ":" not in i.get("source_ip", "")]
    return sorted(interfaces, key=lambda item: (not item.get("gateway"), item.get("interface", "")))


@audit_bp.get("/")
def page():
    audit.adopt_learned_address(registry(current_app._get_current_object()).status())
    data = audit.state()
    _, environment = settings()
    packs = []
    for pack in PACKS:
        status = evaluate_pack(pack, environment)
        packs.append({"pack": pack, "status": status,
                      "groups": [{"key": g, **PROBE_GROUPS[g], "cost": max(1, len(PROBE_GROUPS[g]["ports"]))} for g in pack["groups"]]})
    connectors = registry(current_app._get_current_object()).status()
    return render_template("audit/page.html", data=data, detected=_detected(), types=audit.NETWORK_TYPES,
                           services=audit.SERVICES, packs=packs, families=FAMILIES, connectors=connectors,
                           max_attempts=MAX_WEB_PROBE_ATTEMPTS, in_lab=os.environ.get("SEGCHECK_CONTAINER") == "1",
                           running=running_job())


# ---------------- Step 1 ----------------

@audit_bp.post("/here")
def here():
    form = request.form
    try:
        audit.set_here(form.get("name", ""), form.get("cidr", ""), form.get("ip", ""), form.get("gateway", ""),
                       form.get("type", "corporate"), form.get("organization", ""))
        _sync()
        flash("Step 1 saved: SegCheck will test from this PC.", "success")
        return _back(2)
    except EnvironmentError as exc:
        db.session.rollback()
        flash(f"Step 1: {exc}", "error")
        return _back(1)


# ---------------- Step 2 ----------------

@audit_bp.post("/targets")
def targets():
    form = request.form
    rows = [{"name": n, "cidr": c, "type": t, "hosts": h} for n, c, t, h in
            zip(form.getlist("t_name"), form.getlist("t_cidr"), form.getlist("t_type"), form.getlist("t_hosts"))][:20]
    try:
        added = audit.add_targets(rows)
        flash(f"Step 2: added {len(added)} target network(s).", "success")
    except EnvironmentError as exc:
        db.session.rollback()
        flash(f"Step 2: {exc}", "error")
    return _back(2)


@audit_bp.post("/targets/<zone_key>/hosts")
def add_hosts(zone_key):
    form = request.form
    try:
        addresses = audit._hosts_from_text(" ".join(form.getlist("hosts")))
        if not addresses:
            raise EnvironmentError("Type at least one host address first, e.g. 10.30.0.20 (several: separate with spaces).")
        names = {a: n for a, n in zip(form.getlist("host_for_name"), form.getlist("host_name")) if n}
        count = audit.add_hosts(zone_key, addresses, names)
        flash(f"Step 2: added {count} host(s)." if count else "Step 2: those hosts were already in the list.", "success")
    except EnvironmentError as exc:
        db.session.rollback()
        flash(f"Step 2: {exc}", "error")
    return _back(2)


@audit_bp.post("/targets/<zone_key>/remove")
def remove_target(zone_key):
    try:
        audit.remove_target(zone_key)
        _sync()
        flash("Step 2: target network removed.", "success")
    except EnvironmentError as exc:
        db.session.rollback()
        flash(f"Step 2: {exc}", "error")
    return _back(2)


@audit_bp.post("/hosts/<int:asset_id>/remove")
def remove_host(asset_id):
    try:
        audit.remove_host(str(asset_id))
        flash("Step 2: host removed.", "success")
    except EnvironmentError as exc:
        db.session.rollback()
        flash(f"Step 2: {exc}", "error")
    return _back(2)


def _target_network(zone_key):
    _, environment = settings()
    network = environment.get("networks", {}).get(zone_key)
    if network is None:
        return None, environment
    return network, environment


def _not_this_pc(hosts):
    """Discovery never offers this PC itself as a target."""
    from segcheck_web.services.environment import local_addresses
    _, environment = settings()
    mine = set(local_addresses()) | {environment.get("source_ip")}
    return [host for host in hosts if host["address"] not in mine]


@audit_bp.get("/targets/<zone_key>/known")
def known(zone_key):
    from segcheck_web.services.target_discovery import known_hosts
    network, environment = _target_network(zone_key)
    if network is None:
        return jsonify({"error": "That target network no longer exists. Reload the page."}), 404
    gateways = [n.get("gateway") for n in environment.get("networks", {}).values() if n.get("gateway")]
    response = jsonify({"network": network["cidr"], "hosts": _not_this_pc(known_hosts(network["cidr"], gateways))})
    response.headers["Cache-Control"] = "no-store"
    return response


@audit_bp.post("/targets/<zone_key>/sweep")
def sweep(zone_key):
    from segcheck_web.services.target_discovery import DiscoveryError, ping_sweep
    network, environment = _target_network(zone_key)
    if network is None:
        return jsonify({"error": "That target network no longer exists. Reload the page."}), 404
    try:
        # Discovery only builds a list to tick; the operating system picks the route. The audit's own
        # attempts are always bound to this PC's Step 1 address.
        result = ping_sweep(network["cidr"])
        result["hosts"] = _not_this_pc(result["hosts"])
    except DiscoveryError as exc:
        return jsonify({"error": str(exc)}), 400
    response = jsonify(result)
    response.headers["Cache-Control"] = "no-store"
    return response


# ---------------- Step 3 ----------------

@audit_bp.post("/firewall")
def firewall():
    form = request.form
    try:
        result = audit.set_firewall(form.get("mode", ""), form.get("kind", "pfsense"), form.get("firewall_ip", ""),
                                    form.get("logs") == "on", None, form.get("listen_ip", ""), form.get("sender_ip", ""),
                                    form.get("other_ips", ""))
        _sync()
        if form.get("mode") == "none":
            flash("Step 3 saved: no firewall. Silence will be reported as unproven, never as passed.", "success")
        elif result["port"]:
            flash(f"Step 3 saved: SegCheck listens for the firewall's logs on UDP port {result['port']}. "
                  "Set the firewall as shown below.", "success")
        else:
            flash("Step 3 saved: firewall without log feed.", "success")
        return _back(3)
    except EnvironmentError as exc:
        db.session.rollback()
        flash(f"Step 3: {exc}", "error")
        return _back(3)


@audit_bp.post("/firewall/rules")
def firewall_rules():
    """Optional: the firewall's rule export, to name the rule behind each result."""
    upload = request.files.get("export")
    text, name = "", ""
    if upload and upload.filename:
        raw = upload.read(1024 * 1024 + 1)
        encoding = "utf-16" if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8-sig"  # PowerShell ">" writes UTF-16
        text, name = raw.decode(encoding, "replace"), upload.filename
    else:
        text = request.form.get("export_text", "")
    try:
        count, kind = audit.set_ruleset(text, name)
        own = len((settings()[1].get("ruleset") or {}).get("input_rules") or [])
        extra = f" and {own} INPUT rule(s) for traffic to the firewall itself" if own else ""
        flash(f"Step 3: loaded {count} {'pfSense/OPNsense' if kind == 'pfsense' else 'Linux FORWARD'} rule(s){extra}. "
              "Reports now name the rule behind each result.", "success")
    except EnvironmentError as exc:
        db.session.rollback()
        flash(f"Step 3: {exc}", "error")
    return _back(3)


@audit_bp.post("/firewall/rules/remove")
def firewall_rules_remove():
    audit.clear_ruleset()
    flash("Step 3: rule export removed.", "success")
    return _back(3)


@audit_bp.get("/firewall/status")
def firewall_status():
    response = jsonify(registry(current_app._get_current_object()).status())
    response.headers["Cache-Control"] = "no-store"
    return response


@audit_bp.post("/firewall/sender")
def firewall_sender():
    try:
        audit.use_learned_sender(request.form.get("sender_ip", ""))
        _sync()
        flash("Step 3: firewall sender confirmed.", "success")
    except EnvironmentError as exc:
        db.session.rollback()
        flash(f"Step 3: {exc}", "error")
    return _back(3)


# ---------------- Step 4: checks and launch ----------------

def _document(form, here_name):
    if form.get("mode") == "custom":
        rows = [{"target": t, "service": s, "must": m, "protocol": p, "ports": ports, "targets": typed, "reason": reason}
                for t, s, m, p, ports, typed, reason in
                zip_longest(form.getlist("r_target"), form.getlist("r_service"), form.getlist("r_must"), form.getlist("r_protocol"),
                    form.getlist("r_ports"), form.getlist("r_targets"), form.getlist("r_reason"), fillvalue="")][:100]
        checks = audit.custom_policy(rows, here_name)
        return audit.policy_document(f"Own rules · from {here_name}", checks), "own rules"
    _, environment = settings()
    groups = form.getlist("groups")
    if form.get("scope") == "several":
        used, skipped, document = build_multi_document(form.getlist("pack"), environment, groups or None)
        names = ", ".join(sorted({pack["standard"] for pack in used}))
        document["name"] = f"{len(used)} standard checks ({names}) · from {here_name}"[:120]
        if skipped:
            flash("Not included: " + "; ".join(f"{pack['title']} ({reason})" for pack, reason in skipped), "info")
        return document, f"{len(used)} standard checks ({names})"
    pack, documents = build_pack_documents(form.get("pack", ""), environment, groups or None)
    if len(documents) > 1:
        raise EnvironmentError(f"This needs more than {MAX_WEB_PROBE_ATTEMPTS} attempts. Untick some probe kinds or remove hosts.")
    document = documents[0]
    document["name"] = f"{pack['standard']} · {pack['title']} · from {here_name}"[:120]
    return document, f"the {pack['standard']} standard '{pack['title']}'"


@audit_bp.post("/launch")
def launch():
    form = request.form
    data = audit.state()
    if not data["here"]:
        flash("Step 1 first: tell SegCheck where this PC is.", "error")
        return _back(1)
    policy = None
    try:
        document, what = _document(form, data["here"]["name"])
        policy = import_policy_content(audit.as_yaml(document))
        transition_policy_status(policy.id, "active", f"Launched from the guided audit ({what}).",
                                 actor_identifier=current_user.username)
        version = policy.versions[-1]
        plan = build_plan(version, "active")
        if not plan["ready"]:
            raise EnvironmentError("Not ready yet: " + " · ".join(plan["blockers"][:4]))
        job, _ = create_job(version, plan, current_user.id, secrets.token_hex(16))
        start_worker(current_app._get_current_object(), job.id)
        return redirect(url_for("jobs.detail", job_id=job.id))
    except (EnvironmentError, PackError, PolicyImportError, PolicyValidationError, AssessmentExecutionError, JobBusy) as exc:
        db.session.rollback()
        if policy is not None:
            try:
                history.discard_policy(policy.id)
            except Exception:  # noqa: BLE001 (the message below matters more than leftover cleanup)
                db.session.rollback()
        flash(f"Step 4: {exc}", "error")
        return _back(4)



@audit_bp.get("/rules-template.csv")
def rules_template():
    """An example access matrix the client's network team can fill in (one row per rule)."""
    from flask import Response
    lines = [",".join(audit.CSV_FIELDS),
             "HR department,10.30.0.0/28,db,,,blocked,HR must not reach the card databases (PCI DSS 1.3.1)",
             "HR department,10.70.0.10,files,,,work,HR needs the file server",
             "HR department,10.70.0.10-12,custom,tcp,8000-8100,blocked,No access to the application test ports",
             "*,10.30.0.10,admin,,,blocked,No department may administer the payment API",
             "Guest Wi-Fi,10.0.0.0/24,ping,,,blocked,Guests must not see internal hosts"]
    response = Response("\r\n".join(lines) + "\r\n", mimetype="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=segcheck-rules-template.csv"
    return response
