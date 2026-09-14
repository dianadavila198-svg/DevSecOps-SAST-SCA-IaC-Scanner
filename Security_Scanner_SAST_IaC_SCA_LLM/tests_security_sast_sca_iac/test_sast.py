#SAST Scanner testing using pytest

"""
Tests for the SAST pillar. Each test builds a tiny fake piece of Python
code, runs our real rule function against it, and checks (using assert)
whether the rule reacted the way we expect.
"""
import ast
import pytest
from scanner.sast_scanner import (
    check_security_misconfig,
    check_hardcoded_secrets,
    check_unsafe_eval_exec,
)


def parse(code):
    """Turns a string of Python code into an AST tree — what
    the scanner does to a file, done on a small
    string instead of a whole file."""
    return ast.parse(code)


# --- Use Case 1-SAST-1: does the rule correctly catch a REAL problem? ---

def test_debug_true_is_flagged():
    #Build a fake settings.py containing just one dangerous line
    tree = parse("DEBUG = True")

    #Run the real rule function against it
    findings = check_security_misconfig(tree, "settings.py")

    #Pull out just the rule_id from each finding, so I can check
    #if the one I expect is in there
    rule_ids = [f.rule_id for f in findings]

    #assert: I EXPECT this specific rule_id to be present.
    #If it's not, the test fails — meaning the rule stopped
    #detecting something it's supposed to detect.
    assert "SEC-MISCONFIG-DEBUG" in rule_ids


def test_hardcoded_secret_key_fallback_is_flagged():
    tree = parse('SECRET_KEY = os.getenv("SECRET_KEY", "django-insecure-abc123")')
    findings = check_security_misconfig(tree, "settings.py")
    rule_ids = [f.rule_id for f in findings]
    assert "SEC-MISCONFIG-SECRET-KEY-FALLBACK" in rule_ids


def test_allowed_hosts_wildcard_is_flagged():
    tree = parse("ALLOWED_HOSTS = ['*']")
    findings = check_security_misconfig(tree, "settings.py")
    rule_ids = [f.rule_id for f in findings]
    assert "SEC-MISCONFIG-ALLOWED-HOSTS-WILDCARD" in rule_ids


def test_hardcoded_password_is_flagged():
    tree = parse('DB_PASSWORD = "supersecret123"')
    findings = check_hardcoded_secrets(tree, "settings.py")

    #assert: expect EXACTLY 1 finding — not 0, not 2. This
    #confirms the rule fires once, correctly, for this one bad line.
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-MISCONFIG-HARDCODED-SECRET"


def test_eval_call_is_flagged():
    tree = parse("eval(user_input)")
    findings = check_unsafe_eval_exec(tree, "views.py")
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-UNSAFE-EVAL-EXEC"


# --- Use Case 2-SAST-2: does the rule correctly IGNORE safe code? ---
# (Just as important as catching bad code — a rule that flags
# EVERYTHING, even safe code, would be useless / annoying to use)

def test_debug_false_is_not_flagged():
    tree = parse("DEBUG = False")
    findings = check_security_misconfig(tree, "settings.py")
    rule_ids = [f.rule_id for f in findings]

    #assert: this time expect the rule_id to NOT be present —
    #the opposite check from before, using "not in"
    assert "SEC-MISCONFIG-DEBUG" not in rule_ids


def test_secret_key_from_env_with_no_fallback_is_not_flagged():
    #This is the SAFE version — no hardcoded fallback string
    tree = parse('SECRET_KEY = os.environ["SECRET_KEY"]')
    findings = check_security_misconfig(tree, "settings.py")
    rule_ids = [f.rule_id for f in findings]
    assert "SEC-MISCONFIG-SECRET-KEY-FALLBACK" not in rule_ids


def test_allowed_hosts_explicit_domain_is_not_flagged():
    tree = parse("ALLOWED_HOSTS = ['sensemap.abdn.ac.uk']")
    findings = check_security_misconfig(tree, "settings.py")
    rule_ids = [f.rule_id for f in findings]
    assert "SEC-MISCONFIG-ALLOWED-HOSTS-WILDCARD" not in rule_ids


def test_ast_literal_eval_is_not_flagged():
    #ast.literal_eval is the SAFE alternative to eval() — should
    #never be flagged, since it can only parse plain data, not code
    tree = parse("ast.literal_eval(user_input)")
    findings = check_unsafe_eval_exec(tree, "views.py")

    #assert: expect the whole findings list to be completely
    #empty — nothing at all should have been flagged
    assert findings == []


# --- Use Case 3-SAST-3: does the rule flag things it CAN'T fully verify? ---

def test_allowed_hosts_dynamic_construction_is_flagged_for_review():
    #A dynamically-built ALLOWED_HOSTS — the scanner can't know its
    #real runtime value, so it should flag it for a human to check
    tree = parse(
        '_ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "*")\n'
        "ALLOWED_HOSTS = [h.strip() for h in _ALLOWED_HOSTS.split(',')]"
    )
    findings = check_security_misconfig(tree, "settings.py")
    rule_ids = [f.rule_id for f in findings]
    assert "SEC-MISCONFIG-ALLOWED-HOSTS-DYNAMIC" in rule_ids

    #Find that ONE specific finding out of the list, so I can check
    #a detail about it (its severity) — next() grabs the first match
    dynamic_finding = next(f for f in findings if f.rule_id == "SEC-MISCONFIG-ALLOWED-HOSTS-DYNAMIC")
    assert dynamic_finding.severity == "Medium"