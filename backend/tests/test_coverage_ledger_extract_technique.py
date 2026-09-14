"""extract_technique() parses (technique_id, technique_name) out of a rule's
header comment. See coverage_ledger.py's _MITRE_NAME docstring for the
literal-escaped-newline bug this guards against, confirmed live 2026-08-31
against a real hunt whose technique_name ended up as an entire embedded
YARA rule body."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detection_pipeline"))

import coverage_ledger


def test_extract_technique_parses_id_and_name_with_real_newlines():
    content = (
        "// Title:       Suspicious Scheduled Task Creation\n"
        "// MITRE ATT&CK: T1053.005 - Scheduled Task/Job\n"
        "// Author:       Ethan Andrews\n"
    )
    assert coverage_ledger.extract_technique(content) == (
        "T1053.005", "Scheduled Task/Job",
    )


def test_extract_technique_stops_at_escaped_newline_not_just_real_one():
    # Simulates content whose newlines arrived already escaped to a literal
    # backslash-n (two characters), not a real linefeed -- the exact shape
    # confirmed live 2026-08-31 (hunt #44's technique_name).
    content = (
        "// Title:       Suspicious QR Phishing PDF\\n"
        "// MITRE ATT&CK: T1566.001 - Phishing: Spearphishing Attachment\\n"
        "// Author:       Ethan Andrews\\n"
        "// Reference:    https://detections.ai/workspace/team/x/knowledge\\n"
        "\\nrule Suspicious_QR_Phishing_PDF {\\n"
        '    strings:\\n        $landing = "highnationservices.com" nocase\\n'
        "    condition:\\n        $pdf_magic at 0\\n}"
    )
    technique_id, technique_name = coverage_ledger.extract_technique(content)
    assert technique_id == "T1566.001"
    assert technique_name == "Phishing: Spearphishing Attachment"
    assert "rule Suspicious_QR_Phishing_PDF" not in technique_name


def test_extract_technique_stops_at_comma_for_multi_technique_header():
    content = "// MITRE ATT&CK: T1606 - Forge Web Credentials, T1528 - Steal Application Access Token\n"
    technique_id, technique_name = coverage_ledger.extract_technique(content)
    assert technique_id == "T1606"
    assert technique_name == "Forge Web Credentials"


def test_extract_technique_caps_length_as_defense_in_depth():
    content = "// MITRE ATT&CK: T1053.005 - " + ("x" * 500) + "\n"
    _, technique_name = coverage_ledger.extract_technique(content)
    assert len(technique_name) <= 120


def test_extract_technique_returns_none_without_mitre_header():
    assert coverage_ledger.extract_technique("// Title: No MITRE line here\n") is None
