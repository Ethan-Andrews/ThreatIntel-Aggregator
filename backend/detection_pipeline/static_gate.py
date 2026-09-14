"""Stage 6a: static gate for generated detections.

Rejects detections that cannot or should not be backtested, before any MDE
advanced hunting quota is spent. Every check here is pure text analysis: no
network, no database, no query execution.

The gate answers three questions:

  1. Is this even KQL? The detections.ai API returns Suricata and YARA for some
     opportunities regardless of the requested language, and neither can run in
     MDE advanced hunting.
  2. Does it key on adversary-chosen artifacts? A rule matching a literal
     filename, service name, domain or hash detects one intrusion, not a
     mechanism. Renaming the file defeats it.
  3. Is it evaluable? A reference to a table the tenant does not license, or a
     hash literal of the wrong length for its field, can never match.

Surviving detections carry a durability score and cost metrics so stage 6b can
rank them when the daily hunting budget binds.

Text analysis is deliberate, not a shortcut waiting to be replaced: a real KQL
parser buys precision this gate does not need, since every verdict is advisory
input to a human review rather than an automatic merge. The known limits are
listed in KNOWN_LIMITS at the bottom of this module.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# --------------------------------------------------------------- language

# Suricata and Snort rules open with an action keyword and a protocol.
_SURICATA_START = re.compile(r"^(alert|drop|pass|reject|rejectsrc|rejectdst)\s+\w+", re.I)
# YARA opens with an import or a rule declaration.
_YARA_START = re.compile(r'^(import\s+"|(private\s+|global\s+)*rule\s+\w+)')

# Splunk SPL's own pipe-chain syntax superficially resembles KQL's `|`
# closely enough that it needs an explicit positive check rather than
# merely falling through when nothing else matches (see detect_language()).
# A KQL query can never syntactically start with a bare `|` -- the pipe
# operator requires a left-hand tabular expression before it -- while SPL
# commands like `| tstats ...`/`| makeresults` routinely do; checked only
# against the first non-blank line, same discipline as _SURICATA_START/
# _YARA_START, so a string literal deeper in the body can't trigger this.
_SPL_LEADING_PIPE = re.compile(r"^\s*\|\s*\w+")
# Splunk's field-value search syntax (index=/sourcetype=) and a handful of
# commands with no KQL equivalent at all -- distinctive enough to check
# against the first line even without a leading pipe (e.g.
# `index=main sourcetype=access_combined | stats count by src_ip`).
_SPL_MARKERS = re.compile(
    r"\b(index\s*=|sourcetype\s*=|tstats\b|makeresults\b|eventstats\b|"
    r"streamstats\b|mvexpand\b|inputlookup\b|outputlookup\b)",
    re.I,
)

# KQL's own pipe-operator keywords -- checked only once Sigma/SPL have
# already been ruled out, since by then a `|`-shaped body is far more
# likely to actually be KQL than to be SPL text coincidentally containing
# one of these words (SPL has its own `where`/`join` etc., but genuine SPL
# almost always also carries index=/sourcetype=/a leading pipe, checked
# first).
_KQL_PIPE_OP = re.compile(
    r"\|\s*(where|project|extend|summarize|join|union|take|top|sort|"
    r"order\s+by|render|parse|mv-expand|distinct|count|evaluate)\b",
    re.I,
)
_KQL_LET = re.compile(r"^\s*let\s+\w+\s*=", re.M)

# ------------------------------------------------------------------ tables

# MDE advanced hunting tables. Availability varies by licensing and by which
# products are onboarded, so this is a starting set: probe the tenant once and
# override via available_tables rather than trusting this list.
DEFAULT_MDE_TABLES = {
    "AlertEvidence", "AlertInfo",
    "DeviceEvents", "DeviceFileCertificateInfo", "DeviceFileEvents",
    "DeviceImageLoadEvents", "DeviceInfo", "DeviceLogonEvents",
    "DeviceNetworkEvents", "DeviceNetworkInfo", "DeviceProcessEvents",
    "DeviceRegistryEvents", "DeviceTvmSoftwareInventory",
    # Identity* tables come from Defender for Identity sensors (on-prem AD
    # signals), not from Entra ID itself -- see the Entra block below for that.
    "IdentityDirectoryEvents", "IdentityLogonEvents", "IdentityInfo",
    "IdentityQueryEvents",
    "EmailEvents", "EmailAttachmentInfo", "EmailUrlInfo", "EmailPostDeliveryEvents",
    "CloudAppEvents", "UrlClickEvents",
    # Entra ID (Azure AD) sign-in and audit tables, populated via the Entra ID
    # diagnostic-settings connector into Log Analytics. Confirmed missing on a
    # WHfB/FIDO2 article: detections.ai correctly targeted SigninLogs for a
    # sign-in-based technique, and this gate rejected it as "no recognised
    # table" purely because the table wasn't in this set -- a false reject
    # caused by an incomplete allowlist, not a rule defect.
    "SigninLogs", "AADNonInteractiveUserSignInLogs",
    "AADServicePrincipalSignInLogs", "AADManagedIdentitySignInLogs",
    "AADProvisioningLogs", "AuditLogs", "ADFSSignInLogs",
    # Sentinel-native tables that are neither MDE nor Entra-specific, but are
    # equally real, licensed Log Analytics tables the gate previously had no
    # way to recognise -- confirmed via a batch of real audit-log rejections
    # on live articles that correctly targeted these, purely because they
    # were missing from this allowlist (round-4 live feedback, 2026-09-02).
    "AzureActivity", "SecurityEvent", "SecurityRecommendation",
}

# ASIM (Advanced Security Information Model) normalization parsers are KQL
# *function calls*, not raw table names -- a query built against a schema
# like "ASIM Network Session" opens with `_Im_NetworkSession`,
# `_Im_NetworkSession_AzureNSGV1` (source-specific), `_ASim_NetworkSession`
# (backward-compat alias), or `imNetworkSession` (workspace-deployed unifying
# parser), never with a capitalised table identifier. extract_tables()'s
# allowlist-membership check can never match these -- they don't start with
# an uppercase letter the way DEFAULT_MDE_TABLES entries do -- so a
# perfectly valid ASIM-schema query was falling through to `no_table` even
# though it plainly does reference real, queryable data. Naming convention
# confirmed against Microsoft's own docs (learn.microsoft.com/azure/sentinel/
# normalization-parsers-overview, normalization-about-workspace-parsers).
_ASIM_PARSER = re.compile(
    r"\b_Im_[A-Za-z][A-Za-z0-9_]*\b"     # unifying + source-specific, e.g. _Im_NetworkSession[_AzureNSGV1]
    r"|\b_ASim_[A-Za-z][A-Za-z0-9_]*\b"  # backward-compat alias, e.g. _ASim_NetworkSession
    r"|\bim[A-Z][A-Za-z0-9]*\b"          # workspace-deployed unifying, e.g. imNetworkSession
)

# ------------------------------------------------------------------ hashes

# Field name -> required hex length. A literal of any other length in a
# comparison against that field is dead code: it can never be true.
HASH_FIELD_LENGTHS = {"MD5": 32, "SHA1": 40, "SHA256": 64}

# ---------------------------------------------------------------- allowlist

# Signed Windows binaries and framework paths. A rule naming these is keying on
# the platform, not on the adversary, so they do not count as literals.
BENIGN_TOKENS = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe", "regsvr32.exe",
    "mshta.exe", "wscript.exe", "cscript.exe", "schtasks.exe", "sc.exe",
    "reg.exe", "services.exe", "svchost.exe", "lsass.exe", "winlogon.exe",
    "explorer.exe", "msiexec.exe", "wmic.exe", "certutil.exe", "bitsadmin.exe",
    "net.exe", "net1.exe", "netsh.exe", "taskkill.exe", "tasklist.exe",
    "whoami.exe", "curl.exe", "wget.exe", "bash.exe", "wsl.exe",
    "msbuild.exe", "installutil.exe", "dllhost.exe", "conhost.exe",
    "werfault.exe", "spoolsv.exe", "smss.exe", "csrss.exe", "wininit.exe",
    "userinit.exe",
    # Defender, Search, backup and update agents. These show up constantly in
    # exclusion clauses because they generate high-volume benign file and
    # process activity.
    "msmpeng.exe", "mssense.exe", "sensendr.exe", "searchindexer.exe",
    "searchprotocolhost.exe", "searchfilterhost.exe",
    "robocopy.exe", "xcopy.exe", "esentutl.exe", "backup.exe",
    "onedrive.exe", "filesyncconfig.exe",
    "trustedinstaller.exe", "tiworker.exe", "compattelrunner.exe",
    "sppsvc.exe", "wuauclt.exe", "usoclient.exe", "sedsvc.exe",
    "dwm.exe", "sihost.exe", "runtimebroker.exe", "backgroundtaskhost.exe",
    "audiodg.exe", "ctfmon.exe", "fontdrvhost.exe",
    "ntdll.dll", "kernel32.dll", "advapi32.dll", "user32.dll", "ole32.dll",
    "amsi.dll", "clr.dll", "mscoree.dll",
    # WHfB/FIDO2 platform components. webauthn.dll is a signed OS DLL that any
    # legitimate WebAuthn/passkey ceremony loads; a rule detecting unusual
    # *loading behavior* around it is not keying on an adversary artifact the
    # way a malware-specific filename would be. Confirmed false-positive on a
    # real rule: "Unusual Process Loading webauthn.dll With NGC Key Container".
    "webauthn.dll",
    # Legitimate runtime/tooling binaries used as a process-ancestry anchor --
    # identifying which application spawned a shell, not an adversary artifact.
    # Confirmed false positive: a TeamCity-shell-spawn rule (CVE-2024-27198)
    # flagged for naming java.exe (TeamCity runs as a JVM process, so java.exe
    # is exactly the parent process this class of rule should scope by) and
    # powershell_ise.exe (a signed, shipped-with-Windows PowerShell host).
    "java.exe", "javaw.exe", "powershell_ise.exe",
}

BENIGN_PATH_FRAGMENTS = (
    r"\windows\\", r"\program files", r"\programdata\microsoft",
    r"\system32", r"\syswow64", r"/usr/", r"/etc/", r"/bin/",
)

# ----------------------------------------------------------------- patterns

_FILENAME = re.compile(
    r"^[\w.\-]+\.(exe|dll|bat|cmd|ps1|psm1|vbs|js|scr|sys|jar|py|sh|msi|hta)$", re.I
)
_DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.){1,}[a-z]{2,}$", re.I)
_IPV4 = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_HEXBLOB = re.compile(r"^[0-9a-f]{32,}$", re.I)
_HASH_CMP = re.compile(
    r"\b(MD5|SHA1|SHA256)\b\s*(?:==|=~|has|contains|in~?)\s*\(?\s*[\"']([0-9a-fA-F]{4,})[\"']",
    re.I,
)
_HAS_ANY = re.compile(r"\bhas_any\s*\(([^)]*)\)", re.I)
# A literal reached through one of these is an exclusion: the rule author
# suppressing known-benign activity. Position matters as much as shape -- an
# adversary filename in a `has` clause is disqualifying, while a signed system
# binary in a `!in~` clause is good detection craft.
_NEGATION = re.compile(
    r"(!in~?|!has_any\b|!has\b|!contains\b|!startswith\b|!endswith\b|!=|\bnot\s*\()",
    re.I,
)
_JOIN = re.compile(r"\|\s*join\b", re.I)
_UNION = re.compile(r"\bunion\b", re.I)

# A body whose only operative statement is `print` is not a rule. detections.ai
# emits these when a technique is genuinely unobservable in the ingested
# telemetry, and the accompanying description names what instrumentation would
# be required. That is a coverage finding worth keeping, not a malformed rule --
# it just does not belong in a backtest queue.
_PRINT_ONLY = re.compile(r"^\s*print\b", re.I | re.M)

# A table opening a statement. Matches control_query._TABLE_STMT so the two
# modules agree on what counts as a runnable query.
_TABLE_OPENS = re.compile(
    r"(?:^|;|\blet\s+\w+\s*=)\s*([A-Z][A-Za-z0-9]{5,})\s*(?:\n|\s)*\|", re.M
)

# make_set/make_list inside a summarize, when grouped by a high-cardinality
# dimension, is a confirmed way to exceed the Log Analytics 5GB summarize
# memory budget (E_RUNAWAY_QUERY / E_LOW_MEMORY_CONDITION). Verified against
# two rules from this corpus that both failed with the identical engine error
# at query time -- this pattern is not hypothetical.
#
# Detection is deliberately coarse: it looks for a make_set/make_list call
# anywhere in the query and a summarize ... by clause naming a per-entity
# field, without trying to prove the two are in the same summarize block. A
# false positive here costs a flag on an otherwise-fine rule; a false negative
# costs a live query burning 20+ seconds to discover the same failure the hard
# way. The asymmetry favors over-flagging.
_MAKE_COLLECTION = re.compile(r"\b(make_set|make_list)\s*\(", re.I)
_SUMMARIZE_BY = re.compile(r"\bsummarize\b.*?\bby\b\s*(.+?)(?:\n\s*\||\Z)",
                           re.I | re.S)

# Per-entity fields whose cardinality scales with fleet size or event volume
# rather than staying bounded. Grouping a make_set/make_list by any of these
# is the combination that triggered the confirmed failures.
_HIGH_CARDINALITY_FIELDS = {
    "devicename", "deviceid", "initiatingprocessid", "processid",
    "accountname", "accountsid", "initiatingprocessaccountname",
    "initiatingprocessaccountsid", "reportid", "sha1", "sha256", "md5",
    "remoteip", "localip",
}

# A has_any() list longer than this, made of tokens the allowlist does not
# recognise, reads as an enumeration of observed indicators rather than a
# behavioural test.
ENUMERATION_THRESHOLD = 4


# ------------------------------------------------------------------ results

@dataclass
class Finding:
    code: str
    detail: str


@dataclass
class GateResult:
    artifact_id: str
    title: str
    language: str                     # kql | suricata | yara | unknown
    verdict: str                      # pass | reject
    findings: list[Finding] = field(default_factory=list)
    durability: float = 1.0           # 1.0 clean, lower is more incident-keyed
    join_count: int = 0
    table_count: int = 0
    tables: list[str] = field(default_factory=list)
    literals: list[str] = field(default_factory=list)

    @property
    def reasons(self) -> list[str]:
        return [f.code for f in self.findings]

    def to_row(self) -> dict:
        """Shape for the detection_backtests.static_verdict column."""
        return {
            "artifact_id": self.artifact_id,
            "language": self.language,
            "verdict": self.verdict,
            "findings": [{"code": f.code, "detail": f.detail} for f in self.findings],
            "durability": round(self.durability, 3),
            "join_count": self.join_count,
            "tables": self.tables,
        }


# ------------------------------------------------------------------ parsing

def strip_comments(text: str) -> str:
    """Remove KQL // line comments and /* */ block comments, leaving string
    literals intact.

    The detections.ai header block (Title, Description, MITRE ATT&CK, Author,
    Reference) is all comments and routinely names the adversary's filenames and
    domains. Counting those as literals would reject every rule, so comments are
    removed before any literal analysis.

    /* */ handling was added after a real, confirmed failure: an artifact
    carried a // header block, then a /* ... */ section containing text that
    read exactly like a real KQL query (DeviceFileEvents, where clauses), and
    only after that closed did the actual body appear -- a YARA `rule Name {`
    declaration. Only // being recognised meant the /* */ block passed
    through untouched, detect_language() saw KQL-shaped text at the front and
    classified the whole artifact as kql, the static gate passed it, a
    control probe was built against the commented-out query, and the
    backtest failed with a hard parse error -- the literal first character
    sent to Sentinel was `/`, from the unstripped `/*`. Stripping the block
    comment here means the real `rule Name {` body becomes visible to
    detect_language() and the artifact is correctly classified as YARA and
    rejected before ever reaching a live query.
    """
    out = []
    i = 0
    n = len(text)
    quote = ""
    verbatim = False
    while i < n:
        ch = text[i]
        if quote:
            if not verbatim and ch == "\\" and i + 1 < n:
                out.append(text[i:i + 2])
                i += 2
                continue
            if ch == quote:
                quote = ""
                verbatim = False
            out.append(ch)
            i += 1
            continue
        if ch == "@" and i + 1 < n and text[i + 1] in "\"'":
            quote = text[i + 1]
            verbatim = True
            out.append(text[i:i + 2])
            i += 2
            continue
        if ch in "\"'":
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2  # skip the closing */; safe past end-of-string on an
                     # unterminated block, since the outer while loop bounds i
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def extract_literals(text: str) -> list[tuple[str, int]]:
    """Collect (literal, start_offset) pairs from comment-stripped text.

    The offset lets the caller decide whether a literal sits inside a negated
    clause, which changes its meaning entirely.
    """
    lits = []
    i = 0
    n = len(text)
    while i < n:
        start = i
        ch = text[i]
        verbatim = False
        if ch == "@" and i + 1 < n and text[i + 1] in "\"'":
            verbatim = True
            i += 1
            ch = text[i]
        if ch in "\"'":
            quote = ch
            i += 1
            buf = []
            while i < n:
                c = text[i]
                if not verbatim and c == "\\" and i + 1 < n:
                    buf.append(text[i + 1])
                    i += 2
                    continue
                if c == quote:
                    i += 1
                    break
                buf.append(c)
                i += 1
            lits.append(("".join(buf), start))
            continue
        i += 1
    return lits


def negated_spans(text: str) -> list[tuple[int, int]]:
    """Character ranges that follow a negation operator, to end of line.

    Line-scoped rather than parsed. KQL statements are pipe-delimited and a
    negated clause almost always sits on one line, so this trades a little
    precision for not needing a parser. A negated clause wrapped across lines
    will have its continuation treated as non-negated.
    """
    spans = []
    pos = 0
    for line in text.splitlines(keepends=True):
        m = _NEGATION.search(line)
        if m:
            spans.append((pos + m.start(), pos + len(line)))
        pos += len(line)
    return spans


def _in_spans(offset: int, spans: list[tuple[int, int]]) -> bool:
    return any(a <= offset < b for a, b in spans)


def _looks_like_sigma(body: str) -> bool:
    """A Sigma rule is a YAML document (or `---`-separated set of them)
    whose top level has both a `logsource` and a `detection` key -- the
    two fields every Sigma rule requires regardless of log source or
    detection shape. Parsed for real (yaml.safe_load_all, never
    yaml.load), not regex-matched against the raw text: a KQL string
    literal that happens to contain the characters "logsource:" can't
    misfire this check, since it would need to actually parse as a YAML
    mapping with those keys at the top level, not merely contain them
    somewhere in the body."""
    try:
        docs = list(yaml.safe_load_all(body))
    except yaml.YAMLError:
        return False
    return any(
        isinstance(doc, dict) and "logsource" in doc and "detection" in doc
        for doc in docs
    )


def _looks_like_spl(body: str) -> bool:
    """See _SPL_LEADING_PIPE/_SPL_MARKERS' own comments for why this needs
    to be a positive check rather than relying on SPL merely failing to
    match anything else -- its `|` pipe chains read a lot like KQL's own
    at a glance."""
    first = body.splitlines()[0].strip() if body.splitlines() else ""
    return bool(_SPL_LEADING_PIPE.match(first) or _SPL_MARKERS.search(first))


def _looks_like_kql(body: str) -> bool:
    """Positive KQL detection -- checked only after Suricata/YARA/Sigma/
    SPL have all failed to match, so a `|`-shaped body reaching here is
    overwhelmingly likely to actually be KQL. Recognizes any of KQL's own
    pipe-operator keywords, a `let` statement, or an ASIM normalization-
    parser call (_Im_*/_ASim_*/im*) anywhere in the body -- deliberately
    not anchored to the first line the way the Suricata/YARA/SPL checks
    are, since real KQL routinely puts its first pipe stage on the line
    after a bare table name (`DeviceProcessEvents\\n| where ...`)."""
    return bool(
        _KQL_PIPE_OP.search(body)
        or _KQL_LET.search(body)
        or _ASIM_PARSER.search(body)
        or _PRINT_ONLY.search(body)
    )


def detect_language(content: str) -> str:
    """Classify by body shape, not by the language field the API reports.

    Suricata and YARA are checked first since both have an unambiguous,
    unmistakable opening shape. Everything else used to fall straight
    through to "kql" by default -- harmless on the AI-generation path
    (detections.ai only ever emits KQL, YARA, or Suricata, so the
    fallback was never actually exercised) but a real bug for local
    import, where a user's own folder is far more likely to contain
    Sigma rules or Splunk SPL than either Suricata or YARA. Content that
    doesn't positively match anything recognized is now classified
    "unrecognized" rather than silently guessed as "kql" -- callers must
    handle that case explicitly rather than let it default into KQL-only
    static analysis it was never meant to receive."""
    body = strip_comments(content).strip()
    if not body:
        return "unknown"
    first = body.splitlines()[0].strip()
    if _SURICATA_START.match(first):
        return "suricata"
    if _YARA_START.match(body):
        return "yara"
    # YARA imports may precede the rule with blank lines; check the raw head too.
    if _YARA_START.match(content.strip()):
        return "yara"
    if _looks_like_sigma(body):
        return "sigma"
    if _looks_like_spl(body):
        return "spl"
    if _looks_like_kql(body):
        return "kql"
    return "unrecognized"


def extract_tables(text: str, known: set[str]) -> list[str]:
    """Return the known table names referenced, in first-seen order.

    Includes underscore in the character class -- found while adding
    available_tables support for a real synced workspace catalog: every
    custom Log Analytics table is conventionally named with a `_CL` suffix
    (e.g. `MyCustomLogs_CL`), and `\\b` never matches between two `\\w`
    characters, so a regex without `_` in its class can never even
    tokenize such a name in the first place -- it would keep rejecting a
    genuinely synced, known custom table as `no_table` regardless of
    whether it's actually in `known`.
    """
    seen = []
    for tok in re.findall(r"\b[A-Z][A-Za-z0-9_]{3,}\b", text):
        if tok in known and tok not in seen:
            seen.append(tok)
    return seen


def extract_asim_parsers(text: str) -> list[str]:
    """Return the ASIM normalization-parser calls referenced, in first-seen
    order. See _ASIM_PARSER's comment for why these need a distinct check
    from extract_tables()'s allowlist-membership one."""
    seen = []
    for tok in _ASIM_PARSER.findall(text):
        if tok not in seen:
            seen.append(tok)
    return seen


# ------------------------------------------------------------------- checks

def _is_benign(lit: str) -> bool:
    low = lit.lower().strip()
    if not low:
        return True
    if low in BENIGN_TOKENS:
        return True
    return any(frag in low for frag in BENIGN_PATH_FRAGMENTS)


def _classify_literal(lit: str, iocs: set[str]) -> str | None:
    """Return a finding code if this literal looks adversary-chosen."""
    low = lit.lower().strip()
    if not low or _is_benign(lit):
        return None
    if low in iocs:
        return "ioc_literal"
    if _HEXBLOB.match(low):
        return "hash_literal"
    if _IPV4.match(low):
        return "ip_literal"
    if _FILENAME.match(low):
        return "filename_literal"
    if _DOMAIN.match(low) and "." in low:
        return "domain_literal"
    # A path fragment naming a user folder plus a specific file.
    if ("\\" in lit or "/" in lit) and re.search(r"\.[a-z0-9]{2,4}$", low):
        return "path_literal"
    return None


def check_memory_risk(text: str) -> list[Finding]:
    """Flag make_set/make_list aggregations grouped by high-cardinality fields.

    Confirmed against two rules in this corpus, both of which failed at query
    time with the identical Kusto engine error (E_RUNAWAY_QUERY, code
    -2133196799) when make_set was combined with a summarize ... by clause
    naming DeviceName/InitiatingProcessId-class fields over a wide window.
    This is a cost and reliability risk, not a correctness one -- the query may
    still be semantically right, so it is not a hard reject. A narrower window
    or a cardinality cap on the group-by often resolves it.
    """
    if not _MAKE_COLLECTION.search(text):
        return []
    findings = []
    for m in _SUMMARIZE_BY.finditer(text):
        by_clause = m.group(1)
        fields = {f.strip().split("=")[-1].strip().lower()
                  for f in by_clause.split(",") if f.strip()}
        hit = fields & _HIGH_CARDINALITY_FIELDS
        if hit:
            findings.append(Finding(
                "memory_risk",
                f"make_set/make_list grouped by {', '.join(sorted(hit))}: "
                f"known to exceed the summarize memory budget at scale",
            ))
    return findings


def check_hash_predicates(text: str) -> list[Finding]:
    """Hash equality is disqualifying; a wrong-length literal is also dead."""
    findings = []
    for field_name, value in _HASH_CMP.findall(text):
        want = HASH_FIELD_LENGTHS.get(field_name.upper())
        detail = f"{field_name} == {value[:12]}... (len {len(value)})"
        findings.append(Finding("hash_predicate", detail))
        if want and len(value) != want:
            findings.append(Finding(
                "dead_hash_predicate",
                f"{field_name} expects {want} hex chars, literal has {len(value)}",
            ))
    return findings


def check_enumerations(text: str, iocs: set[str],
                       spans: list[tuple[int, int]] | None = None) -> list[Finding]:
    """A long has_any() of unrecognised tokens is an indicator list.

    A negated one is an exclusion list and is skipped.
    """
    findings = []
    spans = spans or []
    for m in _HAS_ANY.finditer(text):
        # `!has_any` puts the bang immediately before the matched token, which
        # is outside any span starting at the negation operator.
        if text[max(0, m.start() - 1):m.start()] == "!":
            continue
        if _in_spans(m.start(), spans):
            continue
        args = m.group(1)
        items = [a.strip().strip("\"'") for a in args.split(",")]
        items = [i for i in items if i]
        suspect = [i for i in items
                   if not _is_benign(i) and (i.lower() in iocs
                                             or _classify_literal(i, iocs))]
        # Opaque tokens: not benign, not classifiable, but numerous.
        opaque = [i for i in items if not _is_benign(i) and not _classify_literal(i, iocs)]
        if len(suspect) >= 2 or len(opaque) > ENUMERATION_THRESHOLD:
            sample = ", ".join(items[:5])
            findings.append(Finding(
                "enumerated_literals",
                f"has_any with {len(items)} items: {sample}",
            ))
    return findings


# -------------------------------------------------------------------- gate

REJECT_CODES = {
    "not_kql",
    "empty_content",
    "empty_body",
    "telemetry_gap",
    "hash_predicate",
    "ioc_literal",
    "filename_literal",
    "domain_literal",
    "ip_literal",
    "path_literal",
    "hash_literal",
    "enumerated_literals",
    "no_table",
}

# unavailable_table is deliberately absent: without a real tenant probe the
# check cannot reliably tell an unlicensed table from a column reference, so it
# reports as an advisory flag rather than rejecting the artifact.

# Weight per finding code, subtracted from a starting durability of 1.0.
DURABILITY_COST = {
    "ioc_literal": 0.30,
    "hash_predicate": 0.30,
    "hash_literal": 0.30,
    "domain_literal": 0.25,
    "ip_literal": 0.25,
    "filename_literal": 0.20,
    "path_literal": 0.15,
    "enumerated_literals": 0.25,
    "dead_hash_predicate": 0.10,
    "deep_join": 0.05,
    # Cost, not correctness: confirmed to blow the summarize memory budget at
    # scale, but a reviewer may resolve it with a narrower window rather than
    # rejecting the rule's logic outright.
    "memory_risk": 0.15,
}


def evaluate(
    content: str,
    artifact_id: str = "",
    title: str = "",
    iocs: list[str] | None = None,
    available_tables: set[str] | None = None,
) -> GateResult:
    """Run the static gate over one detection artifact.

    iocs are the indicators the aggregator already extracted from the source
    article. Passing them makes literal detection precise rather than heuristic;
    omitting them falls back to shape-based classification alone.
    """
    tables_known = available_tables or DEFAULT_MDE_TABLES
    ioc_set = {i.lower().strip() for i in (iocs or []) if i and i.strip()}

    res = GateResult(artifact_id=artifact_id, title=title, language="unknown",
                     verdict="reject")

    if not content or not content.strip():
        res.findings.append(Finding("empty_content", "artifact has no content"))
        res.durability = 0.0
        return res

    res.language = detect_language(content)
    if res.language == "unknown":
        # detect_language returns unknown only when nothing survives comment
        # stripping. Reporting that as a language mismatch is misleading: there
        # is no query here at all, just the header block.
        res.findings.append(Finding(
            "empty_body", "comments only: no query after stripping comments"))
        res.durability = 0.0
        return res
    if res.language != "kql":
        res.findings.append(Finding("not_kql", f"body parses as {res.language}"))
        res.durability = 0.0
        return res

    body = strip_comments(content)

    # A print-only body is not a rule. detections.ai emits these when a
    # technique is genuinely unobservable in the ingested telemetry, and names
    # the instrumentation that would be required. Checked before any literal
    # analysis, since there are no predicates to analyse.
    stripped = body.strip()
    if _PRINT_ONLY.search(stripped) and not _TABLE_OPENS.search(stripped):
        res.findings.append(Finding(
            "telemetry_gap",
            "print-only: the technique is not observable in ingested telemetry",
        ))
        res.durability = 0.0
        return res

    res.join_count = len(_JOIN.findall(body))
    res.tables = extract_tables(body, tables_known)
    for parser in extract_asim_parsers(body):
        if parser not in res.tables:
            res.tables.append(parser)
    res.table_count = len(res.tables)

    if res.table_count == 0:
        res.findings.append(Finding("no_table", "no recognised MDE table referenced"))

    # Only an identifier that opens a statement is a candidate table. Matching
    # after `=` as well caught `| project X = InitiatingProcessAccountName`,
    # which is a column, and cost two otherwise-clean rules.
    for m in re.finditer(
        r"(?:^|;|\blet\s+\w+\s*=)\s*([A-Z][A-Za-z0-9]{5,})\s*\n?\s*\|", body, re.M
    ):
        tok = m.group(1)
        if tok not in tables_known and tok not in res.tables:
            res.findings.append(Finding("unavailable_table", tok))

    spans = negated_spans(body)

    res.findings.extend(check_hash_predicates(body))
    res.findings.extend(check_enumerations(body, ioc_set, spans))
    res.findings.extend(check_memory_risk(body))

    seen_literals = set()
    for lit, off in extract_literals(body):
        if _in_spans(off, spans):
            continue  # exclusion clause: suppressing benign noise, not keying on it
        code = _classify_literal(lit, ioc_set)
        if code and lit not in seen_literals:
            seen_literals.add(lit)
            res.literals.append(lit)
            res.findings.append(Finding(code, lit[:60]))

    if res.join_count >= 2:
        res.findings.append(Finding("deep_join", f"{res.join_count} joins"))

    score = 1.0
    for f in res.findings:
        score -= DURABILITY_COST.get(f.code, 0.0)
    res.durability = max(0.0, round(score, 3))

    res.verdict = "reject" if any(f.code in REJECT_CODES for f in res.findings) else "pass"
    return res


def rank(results: list[GateResult], stack_match: bool = False) -> list[GateResult]:
    """Order passing results for stage 6b when the budget binds."""
    def priority(r: GateResult) -> float:
        return (r.durability
                - 0.15 * r.join_count
                - 0.10 * max(0, r.table_count - 1)
                + (0.20 if stack_match else 0.0))
    return sorted([r for r in results if r.verdict == "pass"],
                  key=priority, reverse=True)


# ------------------------------------------------------------------ runner

def _load_dump(path: Path) -> tuple[str, str]:
    """Read a dump_project.py artifact: title, blank, description, blank, body."""
    text = path.read_text(encoding="utf-8")
    parts = text.split("\n\n", 2)
    if len(parts) == 3:
        return parts[0].strip(), parts[2]
    return path.stem, text


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: static_gate.py <dump_dir> [iocs.json]")
        return 2

    dump_dir = Path(argv[1])
    if not dump_dir.is_dir():
        print(f"not a directory: {dump_dir}")
        return 2

    iocs = []
    if len(argv) > 2:
        raw = json.loads(Path(argv[2]).read_text(encoding="utf-8"))
        iocs = raw if isinstance(raw, list) else raw.get("iocs", [])
        print(f"loaded {len(iocs)} IOCs")

    results = []
    for f in sorted(dump_dir.glob("*.txt")):
        title, body = _load_dump(f)
        results.append(evaluate(body, artifact_id=f.name, title=title, iocs=iocs))

    passed = [r for r in results if r.verdict == "pass"]
    print(f"\n{len(results)} artifacts -> {len(passed)} pass, "
          f"{len(results) - len(passed)} reject\n")

    for r in sorted(results, key=lambda x: (x.verdict != "pass", -x.durability)):
        mark = "PASS" if r.verdict == "pass" else "REJ "
        print(f"{mark} d={r.durability:<5} j={r.join_count} "
              f"[{r.language}] {r.title[:58]}")
        for f in r.findings:
            print(f"       {f.code}: {f.detail[:70]}")

    if passed:
        print("\nranked for backtest:")
        ranked = rank(results)
        for i, r in enumerate(ranked, 1):
            pri = r.durability - 0.15 * r.join_count - 0.10 * max(0, r.table_count - 1)
            print(f"  {i}. pri={pri:.2f} (d={r.durability} j={r.join_count}) {r.title[:55]}")
    return 0


# Text analysis, not parsing. Known limits, in rough order of how often they
# will matter:
#   - A union of a durable branch and a brittle branch is rejected whole. The
#     durable half is salvageable by hand; the gate does not split branches.
#   - Service names and mutex names are opaque strings with no distinguishing
#     shape. They are caught only via the IOC list or the has_any enumeration
#     heuristic, so a rule naming two or three of them may pass.
#   - unavailable_table is advisory only. It fires on any capitalised
#     identifier that opens a statement and is not in the known set. Override
#     available_tables with a real tenant probe before promoting it to a reject.
#   - Negation is detected per line. A negated clause whose literals wrap onto
#     the following line will have those literals scored as indicators.
#   - Dynamic KQL that builds predicates at runtime is not analysed.
KNOWN_LIMITS = True

if __name__ == "__main__":
    sys.exit(main(sys.argv))