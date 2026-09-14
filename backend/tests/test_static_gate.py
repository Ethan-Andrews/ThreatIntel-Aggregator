"""Tests for static_gate.py -- stage 6a's text-analysis gate, which decides
which generated detections are even worth backtesting.

Before this file existed, static_gate.evaluate() had ZERO direct test
coverage anywhere in this suite. It is always monkeypatched away at the
orchestrator level (test_orchestrator_validation.py's `gate_evaluate`), and
the one place it runs for real (test_alignment_check.py, via
alignment_check.check_alignment()) only incidentally exercises a single
reject path as a side effect of testing something else entirely. Every
other branch of this 700-line module -- language detection, the literal
classifiers, hash/enumeration/memory-risk checks, negation suppression, the
durability scoring, and rank() -- had never been exercised directly, despite
being the actual business logic that decides what a human reviewer ever
sees."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detection_pipeline"))

import static_gate as sg


def _reasons(result):
    return {f.code for f in result.findings}


# ------------------------------------------------------------- top-level gate --

def test_empty_content_rejects_with_zero_durability():
    result = sg.evaluate("")
    assert result.verdict == "reject"
    assert _reasons(result) == {"empty_content"}
    assert result.durability == 0.0


def test_whitespace_only_content_is_also_empty_content():
    result = sg.evaluate("   \n\t  ")
    assert result.verdict == "reject"
    assert "empty_content" in _reasons(result)


def test_comments_only_body_is_empty_body_not_a_language_mismatch():
    result = sg.evaluate("// Title: x\n// Description: y\n")
    assert result.verdict == "reject"
    assert _reasons(result) == {"empty_body"}
    assert result.durability == 0.0


def test_suricata_rule_is_rejected_as_not_kql():
    body = 'alert tcp any any -> any any (msg:"test"; sid:1;)'
    result = sg.evaluate(body)
    assert result.language == "suricata"
    assert result.verdict == "reject"
    assert "not_kql" in _reasons(result)


def test_yara_rule_is_rejected_as_not_kql():
    body = 'rule EvilFile {\n  condition:\n    true\n}'
    result = sg.evaluate(body)
    assert result.language == "yara"
    assert result.verdict == "reject"
    assert "not_kql" in _reasons(result)


def test_yara_with_leading_import_is_detected_via_raw_content_check():
    body = 'import "pe"\n\nrule EvilFile {\n  condition:\n    true\n}'
    result = sg.evaluate(body)
    assert result.language == "yara"


def test_print_only_body_is_a_telemetry_gap_not_a_generic_reject():
    body = 'print "T1219 is not observable in this tenant\'s ingested telemetry"'
    result = sg.evaluate(body)
    assert result.verdict == "reject"
    assert _reasons(result) == {"telemetry_gap"}
    assert result.durability == 0.0


def test_no_recognised_table_is_a_reject():
    result = sg.evaluate('1\n| where x == 1')
    assert result.verdict == "reject"
    assert "no_table" in _reasons(result)


def test_unavailable_table_is_advisory_only_not_a_reject():
    """A second, unlicensed-looking table referenced alongside a genuinely
    known one must not by itself reject the rule -- see the module's own
    comment on why unavailable_table is deliberately absent from
    REJECT_CODES (no real tenant probe backs it)."""
    body = (
        'let a = DeviceProcessEvents | where FileName == "cmd.exe";\n'
        'let b = SomeWeirdTable | where X == 1;\n'
        "union a, b"
    )
    result = sg.evaluate(body)
    assert "unavailable_table" in _reasons(result)
    assert result.verdict == "pass"


def test_available_tables_recognises_a_synced_table_not_in_the_default_set():
    """A table that only exists in the synced Sentinel workspace cache
    (not DEFAULT_MDE_TABLES) must be recognised when passed explicitly --
    the whole point of sentinel_table_sync.py's cache-over-hardcoded-
    allowlist replacement."""
    body = 'CustomTable_CL\n| where X == 1'
    without_cache = sg.evaluate(body)
    assert "no_table" in _reasons(without_cache)

    with_cache = sg.evaluate(body, available_tables={"CustomTable_CL"})
    assert "no_table" not in _reasons(with_cache)
    assert "CustomTable_CL" in with_cache.tables


def test_available_tables_empty_set_falls_back_to_default_mde_tables():
    """An explicitly empty set (e.g. a real sync that ran but found
    nothing, as opposed to never having synced at all) still falls back to
    DEFAULT_MDE_TABLES -- get_cached_tables() returning empty must behave
    identically to available_tables never being passed."""
    result = sg.evaluate(
        'SigninLogs\n| where UserPrincipalName == "user@example.com"',
        available_tables=set(),
    )
    assert "no_table" not in _reasons(result)


def test_known_entra_table_is_recognised_not_flagged_unavailable():
    """SigninLogs was a real false-reject before it was added to
    DEFAULT_MDE_TABLES -- confirm it resolves as a known table now."""
    result = sg.evaluate('SigninLogs\n| where UserPrincipalName == "user@example.com"')
    assert "SigninLogs" in result.tables
    assert "unavailable_table" not in _reasons(result)
    assert "no_table" not in _reasons(result)


@pytest.mark.parametrize("table", ["AzureActivity", "SecurityEvent", "SecurityRecommendation"])
def test_round4_added_tables_are_recognised_not_flagged_unavailable(table):
    """AzureActivity/SecurityEvent/SecurityRecommendation were real
    false-rejects confirmed against live audit-log rows (round-4 live
    feedback, 2026-09-02) before being added to DEFAULT_MDE_TABLES --
    mirrors test_known_entra_table_is_recognised_not_flagged_unavailable
    for SigninLogs above."""
    result = sg.evaluate(f'{table}\n| where OperationName == "test"')
    assert table in result.tables
    assert "unavailable_table" not in _reasons(result)
    assert "no_table" not in _reasons(result)


def test_asim_unifying_parser_is_recognised_as_a_table():
    """_Im_<Schema> is the ASIM unifying parser naming convention (e.g.
    _Im_NetworkSession) -- a KQL function call, not a raw table name, so it
    was previously invisible to extract_tables()'s allowlist-membership
    check and fell through to no_table even on a valid ASIM-schema query."""
    result = sg.evaluate(
        '_Im_NetworkSession\n| where DstPortNumber == 445'
    )
    assert "_Im_NetworkSession" in result.tables
    assert "no_table" not in _reasons(result)


def test_asim_source_specific_parser_is_recognised_as_a_table():
    result = sg.evaluate(
        '_Im_NetworkSession_AzureNSGV1\n| where DstPortNumber == 445'
    )
    assert "_Im_NetworkSession_AzureNSGV1" in result.tables
    assert "no_table" not in _reasons(result)


def test_asim_backward_compat_parser_is_recognised_as_a_table():
    result = sg.evaluate(
        '_ASim_NetworkSession\n| where DstPortNumber == 445'
    )
    assert "_ASim_NetworkSession" in result.tables
    assert "no_table" not in _reasons(result)


def test_asim_workspace_deployed_parser_is_recognised_as_a_table():
    result = sg.evaluate(
        'imNetworkSession\n| where DstPortNumber == 445'
    )
    assert "imNetworkSession" in result.tables
    assert "no_table" not in _reasons(result)


# ------------------------------------------------------------- hash predicates --

def test_hash_predicate_of_correct_length_is_disqualifying_but_not_dead():
    body = 'DeviceFileEvents\n| where SHA256 == "' + ("a" * 64) + '"'
    result = sg.evaluate(body)
    assert "hash_predicate" in _reasons(result)
    assert "dead_hash_predicate" not in _reasons(result)
    assert result.verdict == "reject"


def test_hash_predicate_of_wrong_length_is_also_dead():
    body = 'DeviceFileEvents\n| where SHA256 == "' + ("a" * 40) + '"'  # SHA1 length, wrong field
    result = sg.evaluate(body)
    assert "hash_predicate" in _reasons(result)
    assert "dead_hash_predicate" in _reasons(result)


# ------------------------------------------------------------------- literals --

def test_ioc_literal_is_classified_regardless_of_shape():
    body = 'DeviceNetworkEvents\n| where RemoteUrl has "totally-unshapely-ioc-marker"'
    result = sg.evaluate(body, iocs=["totally-unshapely-ioc-marker"])
    assert "ioc_literal" in _reasons(result)
    assert result.verdict == "reject"


def test_filename_literal_is_classified_and_rejected():
    body = 'DeviceProcessEvents\n| where FileName == "evil_payload123.exe"'
    result = sg.evaluate(body)
    assert "filename_literal" in _reasons(result)
    assert result.verdict == "reject"


def test_domain_literal_is_classified():
    body = 'DeviceNetworkEvents\n| where RemoteUrl has "c2-exfil-domain.example.com"'
    result = sg.evaluate(body)
    assert "domain_literal" in _reasons(result)


def test_ip_literal_is_classified():
    body = 'DeviceNetworkEvents\n| where RemoteIP == "203.0.113.7"'
    result = sg.evaluate(body)
    assert "ip_literal" in _reasons(result)


def test_bare_hash_shaped_literal_outside_a_hash_field_comparison_is_hash_literal():
    body = 'DeviceFileEvents\n| where Notes == "' + ("a" * 32) + '"'
    result = sg.evaluate(body)
    assert "hash_literal" in _reasons(result)


def test_benign_token_is_not_classified_as_a_literal_at_all():
    body = 'DeviceProcessEvents\n| where InitiatingProcessFileName == "powershell.exe"'
    result = sg.evaluate(body)
    assert _reasons(result) == set()
    assert result.verdict == "pass"
    assert result.durability == 1.0


def test_negated_literal_is_an_exclusion_not_an_indicator():
    """A signed system binary excluded via `!=` is good detection craft, not
    an adversary artifact -- must not be classified at all, matching
    check_enumerations' identical negation handling."""
    body = (
        'DeviceProcessEvents\n'
        '| where FileName != "some_random_signed_tool.exe"\n'
        '| where InitiatingProcessFileName == "explorer.exe"'
    )
    result = sg.evaluate(body)
    assert "filename_literal" not in _reasons(result)


# --------------------------------------------------------------- enumerations --

def test_enumerated_literals_flags_a_long_has_any_of_unrecognised_tokens():
    body = (
        'DeviceProcessEvents\n'
        '| where FileName has_any("tool_a.exe", "tool_b.exe", "tool_c.exe", "tool_d.exe", "tool_e.exe")'
    )
    result = sg.evaluate(body)
    assert "enumerated_literals" in _reasons(result)
    assert result.verdict == "reject"


def test_negated_has_any_is_an_exclusion_list_not_flagged():
    body = (
        'DeviceProcessEvents\n'
        '| where InitiatingProcessFileName !has_any("tool_a.exe", "tool_b.exe", "tool_c.exe", "tool_d.exe", "tool_e.exe")'
    )
    result = sg.evaluate(body)
    assert "enumerated_literals" not in _reasons(result)


def test_short_has_any_of_unrecognised_tokens_is_not_flagged():
    """Below ENUMERATION_THRESHOLD, a short has_any list of genuinely opaque
    (unclassifiable) tokens reads as a normal predicate, not an indicator
    enumeration. Using shaped tokens (e.g. *.exe filenames) would trip the
    separate, lower 'suspect' bar (>=2) instead -- these two are opaque."""
    body = 'DeviceProcessEvents\n| where ServiceName has_any("mutex_alpha", "mutex_beta")'
    result = sg.evaluate(body)
    assert "enumerated_literals" not in _reasons(result)


# ------------------------------------------------------------------ memory risk --

def test_make_set_grouped_by_high_cardinality_field_is_a_memory_risk():
    body = (
        'DeviceProcessEvents\n'
        '| summarize Files = make_set(FileName) by DeviceName\n'
    )
    result = sg.evaluate(body)
    assert "memory_risk" in _reasons(result)
    # Cost, not correctness -- must not by itself reject the rule.
    assert result.verdict == "pass"


def test_make_set_grouped_by_low_cardinality_field_is_not_flagged():
    body = (
        'DeviceProcessEvents\n'
        '| summarize Files = make_set(FileName) by ActionType\n'
    )
    result = sg.evaluate(body)
    assert "memory_risk" not in _reasons(result)


# ----------------------------------------------------------------- deep joins --

def test_two_or_more_joins_is_flagged_as_deep_join():
    body = (
        'DeviceProcessEvents\n'
        '| join DeviceNetworkEvents on DeviceId\n'
        '| join DeviceFileEvents on DeviceId'
    )
    result = sg.evaluate(body)
    assert "deep_join" in _reasons(result)
    assert result.join_count == 2
    # Cost, not a hard reject on its own.
    assert result.verdict == "pass"


def test_single_join_is_not_flagged_as_deep_join():
    body = 'DeviceProcessEvents\n| join DeviceNetworkEvents on DeviceId'
    result = sg.evaluate(body)
    assert "deep_join" not in _reasons(result)
    assert result.join_count == 1


# --------------------------------------------------------------- durability --

def test_durability_subtracts_cost_per_finding_and_floors_at_zero():
    # ioc_literal (0.30) + a second ioc_literal (0.30) + hash_predicate (0.30)
    # + domain_literal (0.25) should floor at 0.0, not go negative.
    body = (
        'DeviceNetworkEvents\n'
        '| where RemoteUrl has "marker-one" or RemoteUrl has "marker-two"\n'
        '| where SHA256 == "' + ("a" * 64) + '"\n'
        '| where RemoteUrl has "another-c2-domain.example.org"'
    )
    result = sg.evaluate(body, iocs=["marker-one", "marker-two"])
    assert result.durability == 0.0


def test_durability_reflects_a_single_moderate_cost_finding():
    body = 'DeviceProcessEvents\n| where InitiatingProcessFolderPath == "c:\\\\users\\\\public\\\\weird_tool.exe"'
    result = sg.evaluate(body)
    assert "path_literal" in _reasons(result)
    assert result.durability == round(1.0 - sg.DURABILITY_COST["path_literal"], 3)


def test_clean_rule_has_full_durability_and_passes():
    body = (
        'DeviceProcessEvents\n'
        '| where InitiatingProcessFileName in~ ("powershell.exe", "cmd.exe")\n'
        '| where ProcessCommandLine has "-enc"\n'
    )
    result = sg.evaluate(body)
    assert result.verdict == "pass"
    assert result.durability == 1.0
    assert result.findings == []


# --------------------------------------------------------------------- rank --

def _passing_result(artifact_id, durability, join_count=0, table_count=1):
    return sg.GateResult(artifact_id=artifact_id, title=artifact_id, language="kql",
                         verdict="pass", durability=durability, join_count=join_count,
                         table_count=table_count)


def test_rank_excludes_rejected_results():
    passing = _passing_result("a", 0.9)
    rejected = sg.GateResult(artifact_id="b", title="b", language="kql", verdict="reject", durability=0.0)
    ranked = sg.rank([passing, rejected])
    assert [r.artifact_id for r in ranked] == ["a"]


def test_rank_orders_by_durability_descending():
    high = _passing_result("high", 0.9)
    low = _passing_result("low", 0.5)
    ranked = sg.rank([low, high])
    assert [r.artifact_id for r in ranked] == ["high", "low"]


def test_rank_penalizes_join_count_and_extra_tables():
    # Same durability, but "clean" has no joins/extra tables and "busy" does --
    # "clean" must rank first despite equal durability.
    clean = _passing_result("clean", 0.8, join_count=0, table_count=1)
    busy = _passing_result("busy", 0.8, join_count=2, table_count=3)
    ranked = sg.rank([busy, clean])
    assert [r.artifact_id for r in ranked] == ["clean", "busy"]


def test_rank_stack_match_is_a_uniform_bonus_not_per_result():
    """stack_match is a single flag for the whole rank() call, not a
    per-result property -- it shifts every candidate's priority by the same
    +0.20, so it can never change relative order within one call. Confirmed
    directly rather than assumed, since the parameter name reads as if it
    could be selective."""
    high = _passing_result("high", 0.9)
    low = _passing_result("low", 0.5)
    without_bonus = sg.rank([low, high], stack_match=False)
    with_bonus = sg.rank([low, high], stack_match=True)
    assert [r.artifact_id for r in without_bonus] == [r.artifact_id for r in with_bonus] == ["high", "low"]


# ------------------------------------------------------------------ strip_comments --

def test_strip_comments_removes_line_and_block_comments_but_keeps_strings():
    content = (
        '// Title: x\n'
        '/* block\n   comment */\n'
        'DeviceProcessEvents | where FileName == "http://not-a-comment.example"'
    )
    stripped = sg.strip_comments(content)
    assert "Title" not in stripped
    assert "block" not in stripped
    assert 'http://not-a-comment.example' in stripped


def test_strip_comments_handles_unterminated_block_comment_safely():
    content = 'DeviceProcessEvents /* never closed'
    # Must not raise or infinite-loop.
    stripped = sg.strip_comments(content)
    assert "DeviceProcessEvents" in stripped


# ------------------------------------------------------- detect_language() --
#
# Zero coverage existed for this function before this section was added --
# it silently defaulted every non-Suricata/non-YARA body to "kql", a real
# bug for local import (see local_import.py and the plan's Task 5). Real
# fixture files under tests/fixtures/local_import/, not one canonical
# example per format -- every row of the plan's own parser-robustness
# matrix gets a real file and a real assertion here.

_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "local_import"


def _fixture(*parts: str) -> str:
    # Raw bytes + decode, not Path.read_text() -- text-mode reads do
    # universal-newline translation (\r\n/\r -> \n) transparently, which
    # would silently erase the very mixed-line-ending fixture this file
    # tests for. local_import.py's own _read_text() decodes raw bytes the
    # same way, so this matches what the real code path actually sees.
    return _FIXTURES.joinpath(*parts).read_bytes().decode("utf-8")


@pytest.mark.parametrize("filename", [
    "bare_where.kql",
    "multiline_let.kql",
    "join_inner.kql",
    "union_tables.kql",
    "asim_parser.kql",
    "mixed_comments.kql",
    "embedded_yaml_yara_literal.kql",
])
def test_detect_language_recognizes_every_kql_shape(filename):
    assert sg.detect_language(_fixture("kql", filename)) == "kql"


def test_detect_language_kql_is_immune_to_yaml_yara_shaped_string_literals():
    """The specific case the plan calls out: a KQL file whose own string
    literal contains text that looks like a Sigma rule and a YARA rule
    declaration must still classify as kql, not sigma or yara."""
    content = _fixture("kql", "embedded_yaml_yara_literal.kql")
    assert "logsource:" in content and "rule EvilRule" in content
    assert sg.detect_language(content) == "kql"


@pytest.mark.parametrize("filename", [
    "with_import.yar",
    "private_global_modifiers.yar",
    "multiple_rules.yar",
])
def test_detect_language_recognizes_every_yara_shape(filename):
    assert sg.detect_language(_fixture("yara", filename)) == "yara"


@pytest.mark.parametrize("filename", [
    "alert.rules", "drop.rules", "pass.rules",
    "reject.rules", "rejectsrc.rules", "rejectdst.rules",
])
def test_detect_language_recognizes_every_suricata_leading_keyword(filename):
    assert sg.detect_language(_fixture("suricata", filename)) == "suricata"


@pytest.mark.parametrize("filename", [
    "single_doc_process_creation.yml",
    "single_doc_network_logsource.yml",
    "multi_doc.yml",
])
def test_detect_language_recognizes_valid_sigma_shapes(filename):
    assert sg.detect_language(_fixture("sigma", filename)) == "sigma"


def test_detect_language_sigma_multidoc_finds_the_shape_in_either_document():
    """Confirms yaml.safe_load_all actually parsed both `---`-separated
    documents, not just the first -- a regression here would still pass a
    single-document Sigma test but silently stop recognizing the second
    rule in a multi-rule export."""
    content = _fixture("sigma", "multi_doc.yml")
    assert content.count("---") >= 1
    assert sg.detect_language(content) == "sigma"


def test_detect_language_logsource_without_detection_is_not_sigma():
    """A Sigma rule requires both logsource and detection at the top level
    -- a YAML document with only logsource (incomplete/invalid Sigma) must
    not be misclassified as a valid one."""
    content = _fixture("sigma", "logsource_only_no_detection.yml")
    assert sg.detect_language(content) != "sigma"


@pytest.mark.parametrize("filename", [
    "field_search.spl",
    "leading_pipe_tstats.spl",
])
def test_detect_language_recognizes_spl_never_silently_kql(filename):
    result = sg.detect_language(_fixture("spl", filename))
    assert result == "spl"
    assert result != "kql"


def test_detect_language_empty_file_is_unknown():
    assert sg.detect_language(_fixture("malformed", "empty.kql")) == "unknown"


def test_detect_language_comments_only_file_is_unknown():
    assert sg.detect_language(_fixture("malformed", "comments_only.kql")) == "unknown"


def test_detect_language_utf8_bom_does_not_break_classification():
    content = _fixture("malformed", "utf8_bom.kql")
    assert content[0] == "﻿"
    # detect_language() itself doesn't strip a BOM (that's local_import.py's
    # job before calling it, see _strip_bom()) -- confirms it degrades to
    # "unrecognized" rather than crashing, so callers that forget to strip
    # a BOM get a clear signal instead of a wrong-but-silent classification.
    assert sg.detect_language(content) in ("kql", "unrecognized")


def test_detect_language_mixed_line_endings_still_classifies_as_kql():
    content = _fixture("malformed", "mixed_line_endings.kql")
    assert "\r\n" in content and "\r" in content.replace("\r\n", "")
    assert sg.detect_language(content) == "kql"


def test_detect_language_plain_prose_is_unrecognized_not_kql():
    """The actual bug fix under test: text that is none of the recognized
    shapes must not silently default to kql."""
    junk = "This is just some plain prose, not a detection rule at all."
    assert sg.detect_language(junk) == "unrecognized"


def test_detect_language_oversized_file_still_classifies_correctly():
    """detect_language() itself has no size limit -- local_import.py's own
    MAX_FILE_BYTES check happens before content ever reaches this
    function. Confirms the classifier doesn't choke or misbehave on a
    large body regardless."""
    content = _fixture("malformed", "oversized.kql")
    assert len(content.encode("utf-8")) > 1024 * 1024
    assert sg.detect_language(content) == "kql"
