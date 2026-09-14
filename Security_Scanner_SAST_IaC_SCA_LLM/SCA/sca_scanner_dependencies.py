"""Thir Party Libraries vulnerability analysis."""

"""SCA (Software Composition Analysis) — checks requirements.txt
packages against the OSV (Open Source Vulnerabilities) database.
No AST needed here — this is just reading a text file and asking an
external API, same connectivity shape as the AI enrichment layer.
"""

import requests
from scanner.findings import Finding

OSV_API_URL = "https://api.osv.dev/v1/query"


def parse_requirements(requirements_path="../requirements.txt"):
    """
    Reads requirements.txt line by line and pulls out (name, version)
    pairs. Only handles lines shaped like "package==version" — skips
    comments (#), blank lines, and any package with no pinned version
    (can't ask OSV about a version we don't know).
    """
    packages = []
    with open(requirements_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            #Skip blank lines and comment lines
            if not line or line.startswith("#"):
                continue

            #No "==" means no pinned version (e.g. just "requests" with
            #nothing after it) — skip, matches our documented scope limit
            if "==" not in line:
                continue

            #Split "django==5.1.3" into "django" and "5.1.3"
            name, version = line.split("==", 1)
            packages.append((name.strip(), version.strip()))

    return packages


def query_osv(package_name, version):
    """
    Sends one package+version to the OSV API and asks "any known
    vulnerabilities for this?". Returns a list of vulnerability records
    (empty list if none, or if anything goes wrong). Never crashes —
    same "fail quietly, keep going" pattern as checkov in IaC.py.
    """
    try:
        response = requests.post(
            OSV_API_URL,
            json={
                "package": {"name": package_name, "ecosystem": "PyPI"},
                "version": version,
            },
            timeout=10,  #don't wait forever if OSV is slow/down
        )

        #Anything other than 200 means the request didn't succeed —
        #just return no results instead of crashing
        if response.status_code != 200:
            return []

        data = response.json()
        #OSV puts any found vulnerabilities under the "vulns" key —
        #.get(...) with a default [] means no crash if that key is missing
        return data.get("vulns", [])

    except requests.exceptions.RequestException:
        #Network problem (no internet, DNS failure, etc) — skip quietly
        return []


def run_sca_scan(requirements_path="../requirements.txt"):
    """Runs the full SCA pillar. Returns a list of Finding objects,
    same shape as every other rule in the project."""
    findings = []
    packages = parse_requirements(requirements_path)

    #Ask OSV about each package ONE AT A TIME (this is why timeout=10
    #matters — with many packages, this could add up if OSV is slow)
    for package_name, version in packages:
        vulns = query_osv(package_name, version)

        #A package can have MULTIPLE known vulnerabilities — one
        #Finding per vulnerability found, not one per package
        for vuln in vulns:
            findings.append(Finding(
                rule_id=f"SCA-{vuln.get('id', 'UNKNOWN')}",
                severity="High",  #OSV doesn't always give a clean severity value
                attack_type_exposure="Known Vulnerability (CVE)",
                file_path=requirements_path,
                line=1,  #no line-tracking built — same "no line to point to" idea as presence checks
                message=f"{package_name}=={version} has a known vulnerability: {vuln.get('summary', 'No summary available.')}",
                standard_ref="OWASP Top 10:2025 A03 – Software Supply Chain Failures",
            ))

    return findings