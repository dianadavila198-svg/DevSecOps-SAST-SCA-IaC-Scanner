#SCA Scanner testing using pytest

"""
Tests for the SCA pillar. @patch swaps the real network call
(requests.post) for a fake one that we defined — only during testing.
Tests run fast and don't need the internet, since the objective is testing the
code, not whether OSV's website is working.
"""
import pytest
from unittest.mock import patch, Mock
from SCA.sca_scanner_dependencies import parse_requirements, query_osv, run_sca_scan


def write_requirements(tmp_path, content):
    """tmp_path is provided automatically by pytest — a temporary,
    throwaway folder that gets deleted after the test finishes. We
    write a fake requirements.txt into it, just for this one test."""
    path = tmp_path / "requirements.txt"
    path.write_text(content, encoding="utf-8")
    return str(path)


# --- UC-SCA-3: does parsing correctly skip lines it shouldn't check? ---

def test_parse_requirements_extracts_pinned_packages(tmp_path):
    req_path = write_requirements(tmp_path, "Django==5.1.3\npillow==12.2.0\n")
    packages = parse_requirements(req_path)

    #assert: we expect the EXACT list back — both packages, in order,
    #with their names and versions split apart correctly
    assert packages == [("Django", "5.1.3"), ("pillow", "12.2.0")]


def test_parse_requirements_skips_unpinned_package(tmp_path):
    #"requests" has no ==version — nothing to check against OSV
    req_path = write_requirements(tmp_path, "Django==5.1.3\nrequests\n")
    packages = parse_requirements(req_path)
    assert ("requests", "") not in packages
    assert len(packages) == 1


def test_parse_requirements_skips_comments_and_blank_lines(tmp_path):
    req_path = write_requirements(tmp_path, "# a comment\n\nDjango==5.1.3\n")
    packages = parse_requirements(req_path)
    assert packages == [("Django", "5.1.3")]


# --- UC-SCA-1: does it correctly report a REAL vulnerability? ---

@patch("SCA.sca_scanner_dependencies.requests.post")
def test_query_osv_returns_vulnerabilities_on_match(mock_post):
    #Build a FAKE response object, pretending to be what OSV's real
    #server would send back — so we don't need real internet access
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "vulns": [{"id": "GHSA-test-1234", "summary": "Test vulnerability"}]
    }
    #Tell the mock: whenever the code calls requests.post(...),
    #hand back the fake response instead of making a real request
    mock_post.return_value = mock_response

    vulns = query_osv("Django", "5.1.3")
    assert len(vulns) == 1
    assert vulns[0]["id"] == "GHSA-test-1234"


@patch("SCA.sca_scanner_dependencies.query_osv")
def test_run_sca_scan_builds_finding_from_vulnerability(mock_query, tmp_path):
    req_path = write_requirements(tmp_path, "Django==5.1.3\n")

    #This time fake out query_osv() itself (one level higher up),
    #so I don't even need to fake the HTTP response underneath it
    mock_query.return_value = [{"id": "GHSA-test-1234", "summary": "Test vulnerability"}]

    findings = run_sca_scan(req_path)
    assert len(findings) == 1
    assert findings[0].rule_id == "SCA-GHSA-test-1234"
    assert "Django==5.1.3" in findings[0].message


# --- UC-SCA-2: does it survive the network failing? ---

@patch("SCA.sca_scanner_dependencies.requests.post")
def test_query_osv_returns_empty_list_on_non_200(mock_post):
    #Fake a server error response (500), instead of a successful one
    mock_response = Mock()
    mock_response.status_code = 500
    mock_post.return_value = mock_response

    vulns = query_osv("Django", "5.1.3")

    #assert: even on a server error,  expect an EMPTY list back —
    #not a crash, not a fake finding, just "nothing found"
    assert vulns == []


@patch("SCA.sca_scanner_dependencies.requests.post")
def test_query_osv_returns_empty_list_on_network_error(mock_post):
    import requests
    #side_effect makes the mock RAISE an exception instead of
    #returning a value — simulating no internet connection at all
    mock_post.side_effect = requests.exceptions.ConnectionError("no network")

    vulns = query_osv("Django", "5.1.3")
    assert vulns == []


@patch("SCA.sca_scanner_dependencies.query_osv")
def test_run_sca_scan_returns_no_findings_when_package_is_clean(mock_query, tmp_path):
    req_path = write_requirements(tmp_path, "Django==5.1.3\n")
    #Pretend OSV found nothing wrong with this package
    mock_query.return_value = []

    findings = run_sca_scan(req_path)
    assert findings == []