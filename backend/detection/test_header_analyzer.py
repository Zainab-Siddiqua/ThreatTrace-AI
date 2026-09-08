import os
from header_analyzer import parse_eml_file, compute_final_threat_score

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")

def test_phish_failing():
    data = parse_eml_file(os.path.join(SAMPLES_DIR, "phish_failing.eml"))
    assert data["auth_results"] == {"spf": "fail", "dkim": "fail", "dmarc": "fail"}
    # Base score 60 + 50 penalty = 100 max
    assert compute_final_threat_score(60, data["auth_results"]) == 100

def test_legit_passing():
    data = parse_eml_file(os.path.join(SAMPLES_DIR, "legit_passing.eml"))
    assert data["auth_results"] == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
    # Base score 10 + 0 penalty = 10
    assert compute_final_threat_score(10, data["auth_results"]) == 10

def test_spf_softfail():
    data = parse_eml_file(os.path.join(SAMPLES_DIR, "spf_softfail.eml"))
    assert data["auth_results"]["spf"] == "softfail"
    assert data["auth_results"]["dkim"] == "pass"
    # Base score 30 + 8 penalty = 38
    assert compute_final_threat_score(30, data["auth_results"]) == 38

def test_missing_auth():
    data = parse_eml_file(os.path.join(SAMPLES_DIR, "missing_auth.eml"))
    assert data["auth_results"] == {"spf": "none", "dkim": "none", "dmarc": "none"}
    # Base score 20 + 0 penalty = 20
    assert compute_final_threat_score(20, data["auth_results"]) == 20

def test_dmarc_fail_only():
    data = parse_eml_file(os.path.join(SAMPLES_DIR, "dmarc_fail_only.eml"))
    assert data["auth_results"]["dmarc"] == "fail"
    # Base score 50 + 20 penalty = 70
    assert compute_final_threat_score(50, data["auth_results"]) == 70