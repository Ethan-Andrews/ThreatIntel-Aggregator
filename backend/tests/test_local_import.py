"""Tests for local_import.py -- the Local Detections Import feature (see
docs/superpowers/plans/2026-09-14-public-release-parity-and-local-
detections.md, Task 5). Exercises the parts of the plan's parser-
robustness matrix that need a real filesystem and a real database, not
just detect_language() in isolation (see test_static_gate.py for that
half): sidecar resolution, Microsoft native-export JSON, path-safety
(traversal and symlink escape), and idempotent re-import.

import_folder() opens its own DB connection (pgcompat.connect(), same
pattern as orchestrator.run()) rather than taking one as a parameter, so
these tests use the db_conn fixture only to get a truncated database and
PG_DSN set, then inspect the result through that same connection
afterward.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection_pipeline import local_import

_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "local_import"


@pytest.fixture
def import_dir(tmp_path, monkeypatch, db_conn):
    monkeypatch.setenv("LOCAL_IMPORT_DIR", str(tmp_path))
    return tmp_path


def _run_import(sub_path: str = "") -> dict:
    job_id = local_import.create_job()
    local_import.import_folder(job_id, sub_path)
    return local_import.get_job(job_id)


def _result_for(job: dict, path: str) -> dict:
    matches = [r for r in job["results"] if r["path"] == path]
    assert matches, f"no result for {path!r} in {[r['path'] for r in job['results']]}"
    return matches[0]


# --------------------------------------------------------------- sidecars --

def test_valid_sidecar_attaches_title_description_and_technique(import_dir, db_conn):
    (import_dir / "content.kql").write_text(
        (_FIXTURES / "sidecars" / "valid_content.kql").read_text(encoding="utf-8")
    )
    (import_dir / "sidecar.json").write_text(
        (_FIXTURES / "sidecars" / "valid_sidecar.json")
        .read_text(encoding="utf-8").replace("valid_content.kql", "content.kql")
    )

    job = _run_import()
    result = _result_for(job, "content.kql")
    assert result["status"] == "imported"
    assert result["language"] == "kql"
    assert result["technique_id"] == "T1140"

    row = db_conn.execute(
        "SELECT name, description FROM analytics WHERE id = ?", (result["analytic_id"],)
    ).fetchone()
    assert row["name"] == "Certutil Decode Abuse"
    assert "certutil" in row["description"].lower() or "decode" in row["description"].lower()


def test_sidecar_referencing_missing_file_is_a_per_file_error(import_dir):
    (import_dir / "sidecar.json").write_text(
        (_FIXTURES / "sidecars" / "missing_target.json").read_text(encoding="utf-8")
    )

    job = _run_import()
    result = _result_for(job, "sidecar.json")
    assert result["status"] == "error"
    assert "does_not_exist.kql" in result["detail"]
    assert job["failed"] == 1
    assert job["completed"] == 0


def test_sidecar_with_invalid_technique_id_falls_back_to_uncategorized(import_dir):
    (import_dir / "content2.kql").write_text(
        (_FIXTURES / "sidecars" / "invalid_technique_content.kql").read_text(encoding="utf-8")
    )
    (import_dir / "sidecar.json").write_text(
        (_FIXTURES / "sidecars" / "invalid_technique.json")
        .read_text(encoding="utf-8").replace("invalid_technique_content.kql", "content2.kql")
    )

    job = _run_import()
    result = _result_for(job, "content2.kql")
    assert result["status"] == "imported"
    assert result["technique_id"] is None  # invalid id -> Uncategorized, not blocked


def test_sidecar_with_extra_fields_is_rejected_not_silently_accepted(import_dir):
    """Pydantic's extra='forbid' should reject the whole sidecar rather
    than silently ignoring the unexpected field and using the rest --
    per backend/CLAUDE.md's strict input-validation rule. A rejected
    sidecar falls through to "not a recognized shape", so the content
    file it would have described is imported on its own instead (no
    sidecar metadata, no error) -- confirms this is a graceful
    degradation, not a hard failure for the whole folder."""
    (import_dir / "valid_content.kql").write_text(
        (_FIXTURES / "sidecars" / "valid_content.kql").read_text(encoding="utf-8")
    )
    (import_dir / "sidecar.json").write_text(
        (_FIXTURES / "sidecars" / "extra_fields.json").read_text(encoding="utf-8")
    )

    job = _run_import()
    result = _result_for(job, "valid_content.kql")
    assert result["status"] == "imported"
    # No sidecar metadata applied -- title falls back to the file stem.
    assert result["technique_id"] is None


def test_unrelated_json_file_is_not_misinterpreted_as_a_sidecar(import_dir):
    (import_dir / "package.json").write_text(
        (_FIXTURES / "sidecars" / "package.json").read_text(encoding="utf-8")
    )

    job = _run_import()
    # An ignored file isn't "importable" at all -- it produces no result
    # and doesn't count toward the job total, the same as a sidecar file
    # whose target resolved successfully.
    assert job["total"] == 0
    assert job["results"] == []


def test_sidecar_target_is_not_also_imported_a_second_time_via_the_walk(import_dir, db_conn):
    """Regression test for a real bug found while building this feature:
    a sidecar's target file was being imported twice -- once via the
    sidecar (with metadata attached) and once again when the walk
    reached the .kql file directly (without it) -- because
    register_analytic()'s artifact_id dedup only prevented a duplicate
    *row*, not a duplicate, wasted, metadata-losing second result entry.
    """
    (import_dir / "content.kql").write_text(
        (_FIXTURES / "sidecars" / "valid_content.kql").read_text(encoding="utf-8")
    )
    (import_dir / "sidecar.json").write_text(
        (_FIXTURES / "sidecars" / "valid_sidecar.json")
        .read_text(encoding="utf-8").replace("valid_content.kql", "content.kql")
    )

    job = _run_import()
    matches = [r for r in job["results"] if r["path"] == "content.kql"]
    assert len(matches) == 1
    assert matches[0]["technique_id"] == "T1140"

    count = db_conn.execute(
        "SELECT count(*) AS n FROM analytics WHERE origin = 'local_import'"
    ).fetchone()["n"]
    assert count == 1


# ---------------------------------------------------------- native export --

def test_scheduled_native_export_imports_as_kql_with_its_own_technique(import_dir):
    (import_dir / "scheduled_rule.json").write_text(
        (_FIXTURES / "native_export" / "scheduled_rule.json").read_text(encoding="utf-8")
    )

    job = _run_import()
    result = _result_for(job, "scheduled_rule.json")
    assert result["status"] == "imported"
    assert result["language"] == "kql"
    assert result["technique_id"] == "T1059.001"


def test_non_scheduled_native_export_is_skipped_not_misread(import_dir):
    (import_dir / "fusion_rule.json").write_text(
        (_FIXTURES / "native_export" / "fusion_rule.json").read_text(encoding="utf-8")
    )

    job = _run_import()
    result = _result_for(job, "fusion_rule.json")
    assert result["status"] == "skipped"
    assert "Fusion" in result["detail"]


# --------------------------------------------------------------- sigma/spl --

def test_standalone_sigma_file_is_cataloged_with_static_analysis_skipped(import_dir):
    (import_dir / "rule.yml").write_text(
        (_FIXTURES / "sigma" / "single_doc_process_creation.yml").read_text(encoding="utf-8")
    )

    job = _run_import()
    result = _result_for(job, "rule.yml")
    assert result["status"] == "imported"
    assert result["language"] == "sigma"
    assert result["static_gate_verdict"] is None
    assert result["static_gate_durability"] is None
    assert result["control_plan"] is None
    assert "not available for sigma" in result["detail"]


def test_unrecognized_content_is_rejected_with_a_clear_per_file_error(import_dir):
    (import_dir / "notes.txt").write_text(
        "This is just some plain prose, not a detection rule at all."
    )

    job = _run_import()
    result = _result_for(job, "notes.txt")
    assert result["status"] == "error"
    assert result["language"] == "unrecognized"
    assert job["failed"] == 1


# --------------------------------------------------------------- malformed --

def test_binary_non_utf8_file_is_a_per_file_error_not_a_crash(import_dir):
    (import_dir / "binary.dat").write_bytes(
        (_FIXTURES / "malformed" / "binary_non_utf8.dat").read_bytes()
    )

    job = _run_import()
    result = _result_for(job, "binary.dat")
    assert result["status"] == "error"
    assert job["status"] == "completed"  # one bad file doesn't fail the whole job


def test_oversized_file_is_rejected_not_read_in_full(import_dir):
    (import_dir / "oversized.kql").write_bytes(
        (_FIXTURES / "malformed" / "oversized.kql").read_bytes()
    )

    job = _run_import()
    result = _result_for(job, "oversized.kql")
    assert result["status"] == "error"
    assert str(local_import.MAX_FILE_BYTES) in result["detail"]


def test_empty_and_comments_only_files_are_skipped_not_errors(import_dir):
    (import_dir / "empty.kql").write_bytes(b"")
    (import_dir / "comments_only.kql").write_text("// just a header\n// nothing else\n")

    job = _run_import()
    for name in ("empty.kql", "comments_only.kql"):
        result = _result_for(job, name)
        assert result["status"] == "skipped"
        assert result["language"] == "unknown"
    assert job["failed"] == 0


# ------------------------------------------------------------ path safety --

def test_import_folder_rejects_a_sub_path_that_escapes_the_root(import_dir):
    job_id = local_import.create_job()
    local_import.import_folder(job_id, "../../etc")
    job = local_import.get_job(job_id)
    assert job["status"] == "failed"
    assert any("escapes" in r["detail"] for r in job["results"])


def test_import_folder_rejects_a_symlink_that_escapes_the_root(tmp_path, monkeypatch, db_conn):
    outside = tmp_path.parent / "outside_root_for_symlink_test"
    outside.mkdir(exist_ok=True)
    (outside / "secret.kql").write_text("DeviceProcessEvents | where 1 == 1")
    root = tmp_path / "root"
    root.mkdir()
    (root / "escape_link").symlink_to(outside)
    monkeypatch.setenv("LOCAL_IMPORT_DIR", str(root))

    job_id = local_import.create_job()
    local_import.import_folder(job_id, "escape_link")
    job = local_import.get_job(job_id)
    assert job["status"] == "failed"
    assert any("escapes" in r["detail"] for r in job["results"])


def test_sidecar_file_field_escaping_the_root_is_rejected(import_dir):
    outside = import_dir.parent / "outside_root_for_sidecar_test"
    outside.mkdir(exist_ok=True)
    (outside / "secret.kql").write_text("DeviceProcessEvents | where 1 == 1")
    (import_dir / "evil.json").write_text(
        '{"file": "../outside_root_for_sidecar_test/secret.kql", "title": "Evil"}'
    )

    job = _run_import()
    result = _result_for(job, "evil.json")
    assert result["status"] == "error"
    assert "escapes" in result["detail"]


def test_local_import_dir_not_configured_fails_the_job_cleanly(monkeypatch, db_conn):
    monkeypatch.delenv("LOCAL_IMPORT_DIR", raising=False)
    job_id = local_import.create_job()
    local_import.import_folder(job_id)
    job = local_import.get_job(job_id)
    assert job["status"] == "failed"
    assert any("LOCAL_IMPORT_DIR" in r["detail"] for r in job["results"])


# -------------------------------------------------------- idempotent re-import --

@pytest.mark.parametrize("fixture_dir,filename", [
    ("kql", "bare_where.kql"),
    ("sigma", "single_doc_process_creation.yml"),
])
def test_reimporting_the_same_folder_does_not_duplicate_rows(
    import_dir, db_conn, fixture_dir, filename,
):
    (import_dir / filename).write_text(
        (_FIXTURES / fixture_dir / filename).read_text(encoding="utf-8")
    )

    first = _run_import()
    second = _run_import()

    first_result = _result_for(first, filename)
    second_result = _result_for(second, filename)
    assert first_result["hunt_id"] == second_result["hunt_id"]
    assert first_result["analytic_id"] == second_result["analytic_id"]

    hunt_count = db_conn.execute(
        "SELECT count(*) AS n FROM hunts WHERE origin = 'local_import'"
    ).fetchone()["n"]
    analytic_count = db_conn.execute(
        "SELECT count(*) AS n FROM analytics WHERE origin = 'local_import'"
    ).fetchone()["n"]
    assert hunt_count == 1
    assert analytic_count == 1


def test_reimporting_the_native_export_format_does_not_duplicate_rows(import_dir, db_conn):
    (import_dir / "scheduled_rule.json").write_text(
        (_FIXTURES / "native_export" / "scheduled_rule.json").read_text(encoding="utf-8")
    )

    first = _run_import()
    second = _run_import()
    assert _result_for(first, "scheduled_rule.json")["analytic_id"] == \
        _result_for(second, "scheduled_rule.json")["analytic_id"]

    analytic_count = db_conn.execute(
        "SELECT count(*) AS n FROM analytics WHERE origin = 'local_import'"
    ).fetchone()["n"]
    assert analytic_count == 1


# ---------------------------------------------------------- alignment check --
# Same gating orchestrator.py's own process_one() uses, mirrored here:
# only a static-gate pass gets an alignment check, and only when an AI
# provider is actually configured. sentinel_client is always None from
# local_import.py (see _import_content()'s own comment on why).

def test_alignment_check_runs_when_ai_client_configured_and_gate_passes(import_dir, monkeypatch):
    monkeypatch.setattr(local_import, "_build_ai_client", lambda: object())
    calls = {}

    def _fake_check_alignment(ai_client, sentinel_client, conn, strategy_id, analytic_id=None):
        calls["strategy_id"] = strategy_id
        calls["analytic_id"] = analytic_id
        calls["sentinel_client"] = sentinel_client
        return None

    monkeypatch.setattr(local_import, "check_alignment", _fake_check_alignment)

    (import_dir / "rule.kql").write_text(
        (_FIXTURES / "kql" / "bare_where.kql").read_text(encoding="utf-8")
    )
    job = _run_import()
    result = _result_for(job, "rule.kql")

    assert result["status"] == "imported"
    assert result["static_gate_verdict"] == "pass"
    assert calls["analytic_id"] == result["analytic_id"]
    assert calls["strategy_id"] is not None
    assert calls["sentinel_client"] is None


def test_alignment_check_skipped_when_ai_client_not_configured(import_dir, monkeypatch):
    monkeypatch.setattr(local_import, "_build_ai_client", lambda: None)

    def _should_not_be_called(*args, **kwargs):
        raise AssertionError("check_alignment must not run without an AI client")

    monkeypatch.setattr(local_import, "check_alignment", _should_not_be_called)

    (import_dir / "rule.kql").write_text(
        (_FIXTURES / "kql" / "bare_where.kql").read_text(encoding="utf-8")
    )
    job = _run_import()
    result = _result_for(job, "rule.kql")
    assert result["status"] == "imported"  # registration still happens regardless


def test_alignment_check_never_fails_the_import_on_error(import_dir, monkeypatch):
    monkeypatch.setattr(local_import, "_build_ai_client", lambda: object())

    def _boom(*args, **kwargs):
        raise RuntimeError("simulated alignment-check failure")

    monkeypatch.setattr(local_import, "check_alignment", _boom)

    (import_dir / "rule.kql").write_text(
        (_FIXTURES / "kql" / "bare_where.kql").read_text(encoding="utf-8")
    )
    job = _run_import()
    result = _result_for(job, "rule.kql")
    assert result["status"] == "imported"
    assert job["failed"] == 0


def test_alignment_check_skipped_for_non_kql_language(import_dir, monkeypatch):
    """No static-gate verdict at all for a recognized-but-not-KQL language
    (e.g. sigma) -- there's nothing to gate a "pass" on, so alignment
    checking must never even attempt to run."""
    monkeypatch.setattr(local_import, "_build_ai_client", lambda: object())

    def _should_not_be_called(*args, **kwargs):
        raise AssertionError("check_alignment must not run for non-KQL content")

    monkeypatch.setattr(local_import, "check_alignment", _should_not_be_called)

    (import_dir / "rule.yml").write_text(
        (_FIXTURES / "sigma" / "single_doc_process_creation.yml").read_text(encoding="utf-8")
    )
    job = _run_import()
    result = _result_for(job, "rule.yml")
    assert result["status"] == "imported"
    assert result["static_gate_verdict"] is None


# ------------------------------------------------------- rejected-but-imported --
# Direct user instruction: an "improper" KQL rule must still be imported
# (browsable, cataloged) rather than silently dropped -- but the reason
# must be surfaced clearly, not just implied by a bare "reject" badge.

def test_rejected_kql_is_still_imported_not_dropped(import_dir, db_conn):
    (import_dir / "bad_rule.kql").write_text(
        (_FIXTURES / "kql" / "rejected_hash_predicate.kql").read_text(encoding="utf-8")
    )

    job = _run_import()
    result = _result_for(job, "bad_rule.kql")

    # Imported, not skipped and not an error -- an "improper" rule is a
    # real, browsable catalog entry, not a rejected import.
    assert result["status"] == "imported"
    assert result["static_gate_verdict"] == "reject"
    assert result["hunt_id"] is not None
    assert result["analytic_id"] is not None

    row = db_conn.execute(
        "SELECT review_state FROM analytics WHERE id = ?", (result["analytic_id"],)
    ).fetchone()
    assert row["review_state"] == "rejected"


def test_rejected_kql_detail_explains_why_not_just_the_verdict(import_dir):
    (import_dir / "bad_rule.kql").write_text(
        (_FIXTURES / "kql" / "rejected_hash_predicate.kql").read_text(encoding="utf-8")
    )

    job = _run_import()
    result = _result_for(job, "bad_rule.kql")

    assert result["static_gate_verdict"] == "reject"
    # detail must carry the actual reason, not stay blank -- a caller
    # (or a UI) must not have to separately fetch static_gate_findings
    # from the database to understand why this was flagged.
    assert result["detail"] != ""
    assert "invalid" in result["detail"].lower() or "flagged" in result["detail"].lower()
    assert result["static_gate_findings"]
    assert any(f["code"] == "hash_predicate" for f in result["static_gate_findings"])


def test_job_flagged_count_tracks_rejected_kql_separately_from_failed(import_dir):
    (import_dir / "bad_rule.kql").write_text(
        (_FIXTURES / "kql" / "rejected_hash_predicate.kql").read_text(encoding="utf-8")
    )
    (import_dir / "good_rule.kql").write_text(
        (_FIXTURES / "kql" / "bare_where.kql").read_text(encoding="utf-8")
    )
    (import_dir / "junk.txt").write_text("not a detection rule at all")

    job = _run_import()

    # One genuinely bad file (error, not imported), one flagged-but-
    # imported file, one clean import -- all three must be distinguishable
    # from the job's own top-level counters alone, without inspecting
    # every row in `results`.
    assert job["failed"] == 1        # junk.txt: unrecognized
    assert job["flagged"] == 1       # bad_rule.kql: imported, static-gate reject
    assert job["completed"] == 2     # bad_rule.kql + good_rule.kql both "completed" (imported)

    bad = _result_for(job, "bad_rule.kql")
    good = _result_for(job, "good_rule.kql")
    junk = _result_for(job, "junk.txt")
    assert bad["status"] == "imported" and bad["static_gate_verdict"] == "reject"
    assert good["status"] == "imported" and good["static_gate_verdict"] == "pass"
    assert junk["status"] == "error"


# ---------------------------------------------------------------- origin --

def test_imported_hunt_and_analytic_are_tagged_local_import_origin(import_dir, db_conn):
    (import_dir / "rule.kql").write_text(
        (_FIXTURES / "kql" / "bare_where.kql").read_text(encoding="utf-8")
    )

    job = _run_import()
    result = _result_for(job, "rule.kql")

    hunt_origin = db_conn.execute(
        "SELECT origin FROM hunts WHERE id = ?", (result["hunt_id"],)
    ).fetchone()["origin"]
    analytic_origin = db_conn.execute(
        "SELECT origin FROM analytics WHERE id = ?", (result["analytic_id"],)
    ).fetchone()["origin"]
    assert hunt_origin == "local_import"
    assert analytic_origin == "local_import"


# ------------------------------------------------------- extensive stress tests --
# One real-world-shaped folder mixing every supported format plus every
# known-bad shape at once, to prove nothing cross-contaminates (a bad file
# never blocks or corrupts a good one) and nothing that should fail
# silently succeeds instead.

def test_mixed_folder_with_every_format_and_every_bad_shape_at_once(import_dir, db_conn):
    layout = {
        "good/kql_bare.kql": ("kql", "bare_where.kql"),
        "good/kql_multiline.kql": ("kql", "multiline_let.kql"),
        "good/kql_join.kql": ("kql", "join_inner.kql"),
        "good/yara_rule.yar": ("yara", "with_import.yar"),
        "good/suricata_rule.rules": ("suricata", "alert.rules"),
        "good/sigma_rule.yml": ("sigma", "single_doc_process_creation.yml"),
        "good/spl_rule.spl": ("spl", "field_search.spl"),
        "good/native_export.json": ("native_export", "scheduled_rule.json"),
        "bad/rejected_kql.kql": ("kql", "rejected_hash_predicate.kql"),
        "bad/non_scheduled_export.json": ("native_export", "fusion_rule.json"),
        "bad/empty.kql": ("malformed", "empty.kql"),
        "bad/comments_only.kql": ("malformed", "comments_only.kql"),
        "bad/binary.dat": ("malformed", "binary_non_utf8.dat"),
        "bad/oversized.kql": ("malformed", "oversized.kql"),
        "bad/prose.txt": None,  # written directly below, not from a fixture
    }
    for rel, source in layout.items():
        dest = import_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        if source is None:
            dest.write_text("Just some plain prose, not a detection rule.")
        elif source[0] == "malformed" and source[1] == "binary_non_utf8.dat":
            dest.write_bytes((_FIXTURES / source[0] / source[1]).read_bytes())
        else:
            dest.write_bytes((_FIXTURES / source[0] / source[1]).read_bytes())

    job = _run_import()
    assert job["status"] == "completed"  # the batch itself never aborts

    by_path = {r["path"]: r for r in job["results"]}

    # Every "good" file imported cleanly.
    for rel in ["good/kql_bare.kql", "good/kql_multiline.kql", "good/kql_join.kql",
                "good/yara_rule.yar", "good/suricata_rule.rules",
                "good/sigma_rule.yml", "good/spl_rule.spl", "good/native_export.json"]:
        assert by_path[rel]["status"] == "imported", f"{rel}: {by_path[rel]}"

    # Every "bad" file is handled per its own specific failure mode --
    # none of them silently succeed as if nothing were wrong, and none of
    # them crash the batch or affect a sibling file's outcome.
    assert by_path["bad/rejected_kql.kql"]["status"] == "imported"
    assert by_path["bad/rejected_kql.kql"]["static_gate_verdict"] == "reject"
    assert by_path["bad/non_scheduled_export.json"]["status"] == "skipped"
    assert by_path["bad/empty.kql"]["status"] == "skipped"
    assert by_path["bad/comments_only.kql"]["status"] == "skipped"
    assert by_path["bad/binary.dat"]["status"] == "error"
    assert by_path["bad/oversized.kql"]["status"] == "error"
    assert by_path["bad/prose.txt"]["status"] == "error"
    assert by_path["bad/prose.txt"]["language"] == "unrecognized"

    # Job-level counters add up exactly: nothing double-counted, nothing
    # dropped from the tally.
    assert job["total"] == len(layout)
    assert job["completed"] + job["failed"] == job["total"]
    assert job["flagged"] == 1  # only rejected_kql.kql

    # No cross-contamination in the database: exactly the 9 genuinely
    # imported rows (8 good + 1 rejected-but-imported) exist, no more, no
    # fewer, and every one is correctly tagged.
    imported_count = db_conn.execute(
        "SELECT count(*) AS n FROM analytics WHERE origin = 'local_import'"
    ).fetchone()["n"]
    assert imported_count == 9


def test_deeply_nested_directories_are_walked(import_dir):
    deep = import_dir / "a" / "b" / "c" / "d" / "e"
    deep.mkdir(parents=True)
    (deep / "buried.kql").write_text(
        (_FIXTURES / "kql" / "bare_where.kql").read_text(encoding="utf-8")
    )

    job = _run_import()
    result = _result_for(job, "a/b/c/d/e/buried.kql")
    assert result["status"] == "imported"


def test_folder_with_only_subdirectories_and_no_files_imports_nothing(import_dir):
    (import_dir / "empty_subdir").mkdir()
    (import_dir / "another" / "nested").mkdir(parents=True)

    job = _run_import()
    assert job["status"] == "completed"
    assert job["total"] == 0
    assert job["results"] == []


def test_unicode_and_special_characters_in_filenames_are_handled(import_dir):
    (import_dir / "règle-detection-üñïçødé_🔥.kql").write_text(
        (_FIXTURES / "kql" / "bare_where.kql").read_text(encoding="utf-8")
    )

    job = _run_import()
    result = _result_for(job, "règle-detection-üñïçødé_🔥.kql")
    assert result["status"] == "imported"


def test_many_files_at_once_all_import_independently(import_dir, db_conn):
    n = 40
    for i in range(n):
        (import_dir / f"rule_{i:03d}.kql").write_text(
            f"DeviceProcessEvents\n| where ProcessId == {i}\n"
        )

    job = _run_import()
    assert job["total"] == n
    assert job["completed"] == n
    assert job["failed"] == 0

    count = db_conn.execute(
        "SELECT count(*) AS n FROM analytics WHERE origin = 'local_import'"
    ).fetchone()["n"]
    assert count == n


def test_null_byte_in_content_does_not_crash_the_import(import_dir):
    # A null byte is valid UTF-8-decodable (U+0000) but Postgres text
    # columns reject it outright -- confirms this surfaces as a clean
    # per-file error rather than crashing the whole batch.
    (import_dir / "nullbyte.kql").write_bytes(
        b"DeviceProcessEvents\n| where ProcessCommandLine has \"\x00\"\n"
    )

    job = _run_import()
    result = _result_for(job, "nullbyte.kql")
    assert result["status"] == "error"
    assert job["status"] == "completed"  # doesn't abort the batch


def test_duplicate_filenames_in_different_subdirectories_do_not_collide(import_dir, db_conn):
    (import_dir / "team-a").mkdir()
    (import_dir / "team-b").mkdir()
    (import_dir / "team-a" / "rule.kql").write_text(
        "DeviceProcessEvents\n| where ProcessId == 1\n"
    )
    (import_dir / "team-b" / "rule.kql").write_text(
        "DeviceProcessEvents\n| where ProcessId == 2\n"
    )

    job = _run_import()
    a = _result_for(job, "team-a/rule.kql")
    b = _result_for(job, "team-b/rule.kql")
    assert a["status"] == "imported" and b["status"] == "imported"
    assert a["hunt_id"] != b["hunt_id"]
    assert a["analytic_id"] != b["analytic_id"]

    count = db_conn.execute(
        "SELECT count(*) AS n FROM analytics WHERE origin = 'local_import'"
    ).fetchone()["n"]
    assert count == 2


def test_kql_shaped_garbage_that_only_superficially_matches_is_still_gated(import_dir):
    """A body containing a KQL pipe-operator keyword but otherwise
    nonsensical still gets classified as kql (detect_language() is a
    shape heuristic, not a real parser) -- the point of this test is that
    static_gate.evaluate() then runs on it and produces *some* real
    verdict rather than crashing, and the file is still imported either
    way."""
    (import_dir / "garbage.kql").write_text(
        "asdkjasdkj | where !!! this is not really valid anything askdj\n"
    )

    job = _run_import()
    result = _result_for(job, "garbage.kql")
    assert result["language"] == "kql"
    assert result["status"] == "imported"
    assert result["static_gate_verdict"] in ("pass", "reject")
