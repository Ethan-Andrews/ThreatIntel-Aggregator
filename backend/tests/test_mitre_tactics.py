"""Tests for mitre_tactics.py -- the technique->tactic lookup that makes
Sentinel hunt attackTechniques/attackTactics pass ARM validation. See
sentinel_hunting.py's upsert_hunt() docstring for the exact ARM error this
guards against."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detection_pipeline"))

import mitre_tactics


def test_base_technique_strips_subtechnique_suffix():
    assert mitre_tactics.base_technique("T1053.005") == "T1053"


def test_base_technique_passes_through_bare_technique():
    assert mitre_tactics.base_technique("T1053") == "T1053"


def test_tactics_for_techniques_maps_subtechnique_via_parent_and_returns_base_id():
    # Sub-technique ids are stripped to their base id in the returned list --
    # Microsoft.SecurityInsights/hunts' attackTechniques rejects dotted
    # sub-technique ids even with a matching attackTactics entry, confirmed
    # live 2026-08-31 (see mitre_tactics.tactics_for_techniques docstring).
    mapped, tactics = mitre_tactics.tactics_for_techniques(["T1053.005"])
    assert mapped == ["T1053"]
    assert set(tactics) == {"Execution", "Persistence", "PrivilegeEscalation"}


def test_tactics_for_techniques_unions_across_multiple_techniques():
    mapped, tactics = mitre_tactics.tactics_for_techniques(["T1053.005", "T1059.001"])
    assert set(mapped) == {"T1053", "T1059"}
    assert set(tactics) == {"Execution", "Persistence", "PrivilegeEscalation"}


def test_tactics_for_techniques_dedupes_subtechniques_sharing_a_base():
    mapped, _ = mitre_tactics.tactics_for_techniques(["T1053.005", "T1053.002"])
    assert mapped == ["T1053"]


def test_tactics_for_techniques_drops_unmapped_technique():
    mapped, tactics = mitre_tactics.tactics_for_techniques(["T9999.999"])
    assert mapped == []
    assert tactics == []


def test_tactics_for_techniques_drops_only_the_unmapped_entry():
    mapped, tactics = mitre_tactics.tactics_for_techniques(["T1053.005", "T9999.999"])
    assert mapped == ["T1053"]
    assert set(tactics) == {"Execution", "Persistence", "PrivilegeEscalation"}
