"""IaC (Infrastructure as Code) scanning via Checkov.

This file does NOT contain any detection logic of its own — unlike
sast_scanner.py, which has custom AST rules we wrote ourselves, this
file just RUNS an existing, external tool (checkov) and translates
its results into our own Finding shape, so IaC findings look and
behave exactly like SAST and SCA findings in the final report.
"""
import json
import subprocess
from scanner.findings import Finding


def run_iac_scan(target_dir="infra/"):
    """
    Runs checkov against target_dir (our Terraform folder) and returns
    a list of Finding objects — same return type as check_security_misconfig()
    and every other rule function, so demo.py can treat IaC findings
    exactly the same way as SAST findings (just extend the same list).

    This function is designed to NEVER crash the whole scan. If checkov
    isn't installed, hangs, or produces output we can't read, we just
    return an empty list and move on — same "additive, not load-bearing"
    principle used for the AI enrichment layer in threat_model.py.
    """
    findings = []

    try:
        #subprocess.run() lets Python run another program (checkov) as if
        #we'd typed the command ourselves in a terminal, and capture
        #whatever it prints out. We ask checkov for --output json
        #specifically, because JSON is structured and predictable to
        #read in code — checkov's default output is meant for humans to
        #read in a terminal.
        result = subprocess.run(
            ["checkov", "-d", target_dir, "--framework", "terraform", "--output", "json"],
            capture_output=True,   #capture what checkov prints, instead of it just appearing on screen
            text=True,             #get that output back as a normal string, not raw bytes
            timeout=60,            #give up after 60s if checkov hangs — same missing-timeout risk as Rule 11
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        #FileNotFoundError happens if checkov isn't installed on this
        #machine/CI runner at all — Python can't even find the program
        #to run. TimeoutExpired happens if checkov started but never
        #finished within 60 seconds. Both are real possibilities on a
        #CI runner, and neither should break the rest of the scan.
        print(f"IaC scan skipped: {e}")
        return findings

    #Checkov exits with a non-zero "error" status any time it finds even
    #one failed check — that's completely normal and expected, NOT a
    #sign something is broken (unlike most programs, where a non-zero
    #exit usually does mean something went wrong). The only real signal
    #that something's actually wrong is if checkov printed nothing at all.
    if not result.stdout.strip():
        return findings

    try:
        #Turn the raw JSON text checkov gave us into an actual Python
        #object (a dict or list) we can work with, instead of just text.
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        #If checkov printed a warning or error message BEFORE the JSON
        #body (this can happen if something's misconfigured on its end),
        #json.loads() will fail here. Skip quietly rather than crashing —
        #same defensive pattern as the AI layer's "choices" key check.
        print("IaC scan: could not parse checkov output as JSON")
        return findings

    #Depending on checkov's version and how many frameworks it scanned,
    #it can hand back either ONE result object, or a LIST of result
    #objects. This line just makes sure we always end up with a list to
    #loop over either way, so the code below doesn't need two versions.
    results_list = data if isinstance(data, list) else [data]

    for framework_result in results_list:
        #Checkov's JSON has both PASSED and FAILED checks recorded — we
        #only want the failed ones, since those are the actual problems
        #worth reporting. .get(...) with a default {} / [] means this
        #won't crash even if checkov's JSON shape is slightly different
        #than expected — it'll just find nothing instead of erroring.
        failed_checks = framework_result.get("results", {}).get("failed_checks", [])

        for check in failed_checks:
            #Build one Finding per failed check, translating checkov's
            #own field names into ours. Same Finding shape as every
            #other rule in this project (rule_id, severity, etc.).
            findings.append(Finding(
                rule_id=f"IAC-{check.get('check_id', 'UNKNOWN')}",   
                severity=check.get("severity") or "Medium",           #checkov doesn't always set this, so fall back to Medium
                attack_type_exposure="Infrastructure Misconfiguration",
                file_path=check.get("file_path", target_dir),
                line=check.get("file_line_range", [1])[0],            #checkov gives a [start, end] range — we just take the first line
                message=check.get("check_name", "Infrastructure misconfiguration detected."),
                standard_ref="OWASP Top 10:2025 A02 – Security Misconfiguration",
            ))

    return findings