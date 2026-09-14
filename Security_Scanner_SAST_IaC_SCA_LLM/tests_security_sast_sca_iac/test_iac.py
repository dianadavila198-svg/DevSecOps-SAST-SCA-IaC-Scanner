#IaC Scanner testing using pytest

"""
Tests for the IaC pillar. Uses @patch to replace the real subprocess
call to checkov with a fake one — so tests don't need checkov
actually installed, and run instantly.
"""
import json
import pytest
from unittest.mock import patch, Mock
from IaC.IaC import run_iac_scan


def make_checkov_result(failed_checks):
    """Builds a fake JSON string, shaped exactly like real checkov
    output, containing whatever failed checks we want for this test."""
    return json.dumps({"results": {"failed_checks": failed_checks}})


# --- UC-IAC-1: does it correctly report a REAL misconfiguration? ---

@patch("IaC.IaC.subprocess.run")
def test_run_iac_scan_builds_finding_from_failed_check(mock_run):
    #Fake what subprocess.run(...) would normally return — pretending
    #checkov ran for real and found one problem
    mock_result = Mock()
    mock_result.stdout = make_checkov_result([
        {
            "check_id": "CKV_AWS_16",
            "severity": "Medium",
            "file_path": "/demo.tf",
            "file_line_range": [64, 70],
            "check_name": "Ensure all data stored in the RDS is securely encrypted at rest",
        }
    ])
    mock_run.return_value = mock_result

    findings = run_iac_scan("infra/")
    assert len(findings) == 1
    assert findings[0].rule_id == "IAC-CKV_AWS_16"
    assert findings[0].line == 64


# --- UC-IAC-2: does it correctly report NOTHING for safe resources? ---

@patch("IaC.IaC.subprocess.run")
def test_run_iac_scan_returns_no_findings_when_all_checks_pass(mock_run):
    mock_result = Mock()
    #Empty list = checkov ran fine, found zero problems
    mock_result.stdout = make_checkov_result([])
    mock_run.return_value = mock_result

    findings = run_iac_scan("infra/")
    assert findings == []


# --- UC-IAC-3: does it survive checkov not being available? ---

@patch("IaC.IaC.subprocess.run")
def test_run_iac_scan_handles_checkov_not_installed(mock_run):
    #Simulate: the operating system can't find "checkov" as a program
    #at all (exactly the error we hit locally, blocked by Smart App Control)
    mock_run.side_effect = FileNotFoundError("checkov not found")

    findings = run_iac_scan("infra/")
    #assert: no crash — just an empty result, same graceful behavior
    assert findings == []


@patch("IaC.IaC.subprocess.run")
def test_run_iac_scan_handles_timeout(mock_run):
    import subprocess
    #Simulate: checkov started but never finished within our time limit
    mock_run.side_effect = subprocess.TimeoutExpired(cmd="checkov", timeout=60)

    findings = run_iac_scan("infra/")
    assert findings == []


@patch("IaC.IaC.subprocess.run")
def test_run_iac_scan_handles_invalid_json_output(mock_run):
    mock_result = Mock()
    #Simulate: checkov printed something that isn't valid JSON
    mock_result.stdout = "not valid json {{{"
    mock_run.return_value = mock_result

    findings = run_iac_scan("infra/")
    assert findings == []