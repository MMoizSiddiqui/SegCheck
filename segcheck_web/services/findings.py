"""Explain next steps without changing the evaluator's decision."""


def attach_guidance(report, evaluated_ids):
    for finding in report["results"]:
        if finding["check_id"] not in evaluated_ids:
            finding["recommended_action"] = "Not tested from this source. Run a separate authorized assessment from the check's actual source zone."
        elif finding["result"] == "FAIL" and finding["expected"] == "deny":
            finding["recommended_action"] = "Confirm the asset and zone assignment, then review boundary rules and approved paths. Investigate the demonstrated unauthorized reachability; do not change firewall rules without approval."
        elif finding["result"] == "INCONCLUSIVE":
            finding["recommended_action"] = "Verify the target service is listening, the selected source address and routing are correct, and relevant firewall evidence is available. A timeout or refusal alone does not prove an enforced deny rule."
        else:
            finding["recommended_action"] = "Retain the version-bound observation and confirm the expected connection remains authorized. This result covers the selected path only."
