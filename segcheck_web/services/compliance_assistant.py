"""Compliance assistant: judge one audit against every chosen standard, control by control.

How it works (retrieval-augmented, fully offline):

1. Knowledge base: ``segcheck_web/knowledge/controls.json`` holds SegCheck's own short summaries of each
   control (what it asks, the evidence expected, the fix, an acceptable alternative) and remediation
   playbooks per kind of service. No standard text is copied; each framework links to its official source.
2. Retrieval: every tested rule becomes a short "finding" text (expected result, outcome, service, ports,
   source and destination zone types). A TF-IDF index over the knowledge base ranks the controls and
   playbooks most relevant to that finding, filtered by applicability (e.g. PCI 1.3.1 only for traffic into
   the CDE). Controls a standard explicitly mapped to a check are always attached.
3. Augmentation: the verdict per control is computed deterministically from the measured results (never by
   the text), then explained with the retrieved passages: why it matters, what failed, the fix and an
   alternative. One control can be met while another fails; each standard gets the worst of its controls.

No language model and no network access are used, so the output is reproducible and cannot invent facts.
"""
from __future__ import annotations

import json
import math
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path

KB_PATH = Path(__file__).resolve().parents[1] / "knowledge" / "controls.json"
ROLE_WORDS = {"cde": "cde cardholder card payment", "guest": "guest wifi untrusted visitor", "dmz": "dmz public web untrusted",
              "corporate": "corporate staff office users", "hr": "hr personal data sensitive", "server": "internal servers sensitive",
              "untrusted": "internet partner vpn untrusted", "management": "admin management network", "custom": ""}
ADMIN_PORTS = {22, 23, 3389, 5900, 5985, 5986, 161}
VERDICTS = {  # key: (label, tone, rank) – higher rank is worse
    "not_tested": ("Not tested from here", "skipped", 0),
    "met": ("Met", "pass", 1),
    "met_proven": ("Met, proven by firewall logs", "pass", 1),
    "met_unproven": ("Met, not proven", "unproven", 2),
    "attention": ("Attention: approved flow broken", "unproven", 3),
    "not_met": ("Not met", "fail", 4),
}


@lru_cache(maxsize=1)
def knowledge():
    data = json.loads(KB_PATH.read_text(encoding="utf-8"))
    docs = []
    for control in data["controls"]:
        text = " ".join([control["title"], control["summary"], control["fix"], control["alternative"], control["keywords"]])
        docs.append(("control", f"{control['framework']}:{control['control_id']}", text))
    for playbook in data["playbooks"]:
        docs.append(("playbook", playbook["id"], f"{playbook['title']} {playbook['text']}"))
    tokens = [_tokens(text) for _, _, text in docs]
    df = Counter(word for words in tokens for word in set(words))
    idf = {word: math.log((1 + len(docs)) / (1 + count)) + 1 for word, count in df.items()}
    vectors = [_vector(words, idf) for words in tokens]
    return data, docs, idf, vectors


def _tokens(text):
    return re.findall(r"[a-z0-9]+", text.lower())


def _vector(words, idf):
    counts = Counter(words)
    vec = {word: (count / len(words)) * idf.get(word, 0.0) for word, count in counts.items()} if words else {}
    norm = math.sqrt(sum(value * value for value in vec.values())) or 1.0
    return {word: value / norm for word, value in vec.items()}


def _cosine(a, b):
    return sum(value * b.get(word, 0.0) for word, value in a.items())


def retrieve(text, kind=None, limit=5):
    """[(score, kind, id)] best matches for a piece of text."""
    _, docs, idf, vectors = knowledge()
    query = _vector(_tokens(text), idf)
    scored = [(_cosine(query, vec), doc_kind, doc_id) for (doc_kind, doc_id, _), vec in zip(docs, vectors)
              if kind is None or doc_kind == kind]
    return sorted((item for item in scored if item[0] > 0), reverse=True)[:limit]


def _applies(control, rule, roles):
    rules = control.get("applies", {})
    if rule["expected_key"] not in rules.get("expected", ["deny", "allow"]):
        return False
    source_role, dest_role = roles
    hits = []
    if rules.get("dest_roles"):
        hits.append(dest_role in rules["dest_roles"])
    if rules.get("source_roles"):
        hits.append(source_role in rules["source_roles"])
    if rules.get("services"):
        hits.append(bool(rule["ports"] & ADMIN_PORTS))
    if rules.get("any_boundary"):
        hits.append(rule["zone"] != rule["source"])
    return any(hits) if hits else True


def _finding_text(rule, roles, playbooks):
    words = [("must be blocked denied" if rule["expected_key"] == "deny" else "approved must work allowed"),
             rule["outcome"], rule["protocol"], " ".join(str(p) for p in sorted(rule["ports"])),
             ROLE_WORDS.get(roles[0], ""), ROLE_WORDS.get(roles[1], "") + " destination",
             " ".join(book["title"] for book in playbooks)]
    return " ".join(words)


def _playbooks_for(rule):
    data, *_ = knowledge()
    out = []
    for book in data["playbooks"]:
        match = book["match"]
        if "ports" in match and rule["ports"] & set(match["ports"]) and rule["outcome"] in {"fail", "open"}:
            out.append(book)
        elif match.get("protocol") == "icmp" and rule["protocol"] == "icmp" and rule["outcome"] in {"fail", "open"}:
            out.append(book)
        elif match.get("outcome") == rule["outcome"]:
            out.append(book)
    return out


def _rule_verdict(rule):
    return {"fail": "not_met", "open": "not_met", "down": "attention", "proven": "met_proven",
            "unproven": "met_unproven", "pass": "met"}.get(rule["outcome"], "not_tested")


def assess(view: dict, results: list[dict]) -> dict:
    """The per-standard, per-control verdict for one report (view = report_view.build(report))."""
    data, *_ = knowledge()
    controls = {f"{c['framework']}:{c['control_id']}": c for c in data["controls"]}
    networks = view.get("networks", {}) or {}
    mapped_by_check = {}
    for row in results or []:
        if isinstance(row, dict):
            mapped_by_check[row.get("check_id")] = {f"{m.get('framework')}:{m.get('control_id')}"
                                                    for m in row.get("framework_mappings") or [] if isinstance(m, dict)}
    chosen = sorted({key.split(":")[0] for keys in mapped_by_check.values() for key in keys if key in controls})
    scope_label = "the standards chosen for this run" if chosen else "all standards (own rules are checked against every standard)"
    frameworks = chosen or list(data["frameworks"])

    attached = {key: [] for key in controls if key.split(":")[0] in frameworks}
    rule_notes = []
    for raw in view.get("rules", []):
        if raw["outcome"] == "skipped":
            continue
        ports = {a["port"] for a in raw["attempts"] if a.get("protocol") != "icmp" and isinstance(a.get("port"), int)}
        protocol = next((a["protocol"] for a in raw["attempts"]), "")
        rule = {**raw, "ports": ports, "protocol": protocol, "expected_key": "deny" if raw["expected"] == "Must be blocked" else "allow"}
        roles = (networks.get(raw.get("source"), {}).get("role", "custom"), networks.get(raw.get("zone"), {}).get("role", "custom"))
        books = _playbooks_for(rule)
        text = _finding_text(rule, roles, books)
        ranked = {doc_id: score for score, kind, doc_id in retrieve(text, "control", limit=len(controls))}
        mapped = mapped_by_check.get(raw["check_id"], set())
        for key, control in controls.items():
            if key not in attached:
                continue
            if key in mapped:
                basis = "mapped by the standard"
            elif _applies(control, rule, roles) and ranked.get(key, 0) > 0:
                basis = f"retrieved (relevance {ranked[key]:.2f})"
            else:
                continue
            attached[key].append({"rule": rule, "basis": basis, "score": ranked.get(key, 0), "playbooks": books})
        rule_notes.append({"check_id": raw["check_id"], "query": text,
                           "top": [(round(score, 2), kind, doc) for score, kind, doc in retrieve(text, limit=4)]})

    standards = []
    for framework in frameworks:
        meta = data["frameworks"][framework]
        rows = []
        for key, items in attached.items():
            if key.split(":")[0] != framework:
                continue
            control = controls[key]
            verdict = max((_rule_verdict(item["rule"]) for item in items), key=lambda v: VERDICTS[v][2], default="not_tested")
            if verdict == "met" and any(_rule_verdict(i["rule"]) == "met_unproven" for i in items):
                verdict = "met_unproven"
            failing = [i for i in items if _rule_verdict(i["rule"]) == "not_met"]
            broken = [i for i in items if _rule_verdict(i["rule"]) == "attention"]
            label, tone, _ = VERDICTS[verdict]
            fixes, seen_books = [], set()
            for item in failing + broken:
                for book in item["playbooks"]:
                    if book["id"] not in seen_books:
                        seen_books.add(book["id"])
                        fixes.append(book["text"])
            rows.append({
                "id": control["control_id"], "title": control["title"], "verdict": verdict, "label": label, "tone": tone,
                "summary": control["summary"], "evidence": control["evidence"],
                "checks": len(items), "failing": [_where(i["rule"]) for i in failing],
                "broken": [_where(i["rule"]) for i in broken],
                "basis": sorted({i["basis"].split(" (")[0] for i in items}),
                "fix": control["fix"] if failing or broken else "",
                "playbooks": fixes, "alternative": control["alternative"] if failing else "",
            })
        tested = [row for row in rows if row["verdict"] != "not_tested"]
        worst = max((row["verdict"] for row in tested), key=lambda v: VERDICTS[v][2], default="not_tested")
        if worst == "met" and any(row["verdict"] == "met_proven" for row in tested) and all(
                row["verdict"] in {"met", "met_proven"} for row in tested):
            worst = "met_proven" if all(row["verdict"] == "met_proven" for row in tested) else "met"
        label, tone, _ = VERDICTS[worst]
        standards.append({"framework": framework, "name": meta["name"], "source": meta["source"], "verdict": worst,
                          "label": label, "tone": tone, "controls": sorted(rows, key=lambda r: (-VERDICTS[r["verdict"]][2], r["id"])),
                          "not_met": sum(r["verdict"] == "not_met" for r in rows), "tested": len(tested)})
    return {"scope": scope_label, "standards": standards, "conclusion": _conclusion(standards),
            "notes": rule_notes, "kb_version": data["version"], "disclaimer": data["note"]}


def _where(rule):
    """Host, protocol and the ports that decided the result (answered for a breach, silent for a broken flow)."""
    if rule["outcome"] in {"fail", "open"}:
        hits = [a for a in rule["attempts"] if a.get("observed") == "reachable" or a.get("firewall") == "logged_pass"]
    elif rule["outcome"] == "down":
        hits = [a for a in rule["attempts"] if a.get("observed") != "reachable"]
    else:
        hits = rule["attempts"]
    ports = ", ".join(str(a["port"]) for a in hits if a.get("protocol") != "icmp" and isinstance(a.get("port"), int)) or (
        "ping" if any(a.get("protocol") == "icmp" for a in hits) else ", ".join(str(p) for p in sorted(rule["ports"])))
    return f"{rule['host']} {rule['protocol'].upper()} {ports}"


def _conclusion(standards):
    tested = [s for s in standards if s["verdict"] != "not_tested"]
    if not tested:
        return "Nothing in this run relates to the chosen standards' controls."
    failing = [s for s in tested if s["verdict"] == "not_met"]
    lines = []
    for item in tested:
        bad = [c for c in item["controls"] if c["verdict"] == "not_met"]
        lines.append(f"{item['name']}: {item['label'].upper()}" +
                     (f" ({', '.join(c['id'] for c in bad)} not met)" if bad else ""))
    text = "; ".join(lines) + "."
    if failing and len(failing) < len(tested):
        ok = ", ".join(s["name"] for s in tested if s not in failing)
        text += (f" The standards disagree because the failing path only falls under the controls of "
                 f"{', '.join(s['name'] for s in failing)}; {ok} {'has' if len(tested) - len(failing) == 1 else 'have'} "
                 "no control covering it, or only paths that held.")
    elif failing:
        text += " Every chosen standard is affected: fix the failing path(s) first, then re-run this audit."
    else:
        text += " No chosen standard has a failing control in this run."
    return text
