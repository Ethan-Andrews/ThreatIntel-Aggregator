"""Static MITRE ATT&CK (Enterprise) technique -> tactic lookup.

Confirmed live 2026-08-31: Microsoft.SecurityInsights/hunts rejects any
attackTechniques entry that doesn't belong to at least one tactic listed in
the same request's attackTactics array ("Invalid AttackTechnique provided,
or no valid AttackTactic for the AttackTechniques provided" -- the same
validation documented for scheduled analytics rules' relevantTechniques/
tactics pair, see learn.microsoft.com/azure/sentinel/isv/
sentinel-analytic-rules-creation). sentinel_hunting.py's upsert_hunt() was
sending attackTechniques with no attackTactics at all, which always fails
this check -- hence the hunt container getting created via a *retried*,
attackTechniques-free... no: the actual failure mode observed was the
upsert_hunt call itself 400ing, so the Sentinel-side hunt was never created;
only the pre-existing (unrelated) hunts made it through, with 0 linked
queries because upsert_hunt's own failure aborted sync_hunt() before any
saved search was ever created for them.

Keyed by the *base* technique (sub-technique suffix, e.g. ".005", is
dropped before lookup) since MITRE sub-techniques inherit their parent's
tactics. Not exhaustive -- only the techniques this pipeline has actually
produced or is likely to; tactics_for_techniques() drops (with a warning,
never a failure) any technique missing from this map rather than guessing,
so an unmapped technique degrades to "not shown on the hunt" instead of
breaking the sync for every technique in the batch.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# PascalCase, no spaces -- the exact spelling ARM's AttackTactic enum requires.
TACTICS_BY_TECHNIQUE: dict[str, list[str]] = {
    "T1001": ["CommandAndControl"],
    "T1003": ["CredentialAccess"],
    "T1005": ["Collection"],
    "T1007": ["Discovery"],
    "T1008": ["CommandAndControl"],
    "T1010": ["Discovery"],
    "T1012": ["Discovery"],
    "T1014": ["DefenseEvasion"],
    "T1016": ["Discovery"],
    "T1018": ["Discovery"],
    "T1020": ["Exfiltration"],
    "T1021": ["LateralMovement"],
    "T1027": ["DefenseEvasion"],
    "T1029": ["Collection"],
    "T1030": ["Exfiltration"],
    "T1033": ["Discovery"],
    "T1036": ["DefenseEvasion"],
    "T1037": ["Persistence", "PrivilegeEscalation"],
    "T1040": ["CredentialAccess", "Discovery"],
    "T1041": ["Exfiltration"],
    "T1046": ["Discovery"],
    "T1047": ["Execution"],
    "T1048": ["Exfiltration"],
    "T1049": ["Discovery"],
    "T1052": ["Exfiltration"],
    "T1053": ["Execution", "Persistence", "PrivilegeEscalation"],
    "T1055": ["DefenseEvasion", "PrivilegeEscalation"],
    "T1056": ["Collection", "CredentialAccess"],
    "T1057": ["Discovery"],
    "T1059": ["Execution"],
    "T1560": ["Collection"],
    "T1561": ["Impact"],
    "T1562": ["DefenseEvasion"],
    "T1563": ["LateralMovement"],
    "T1564": ["DefenseEvasion"],
    "T1565": ["Impact"],
    "T1566": ["InitialAccess"],
    "T1567": ["Exfiltration"],
    "T1568": ["CommandAndControl"],
    "T1569": ["Execution"],
    "T1570": ["LateralMovement"],
    "T1071": ["CommandAndControl"],
    "T1072": ["Execution", "LateralMovement"],
    "T1074": ["Collection"],
    "T1078": ["DefenseEvasion", "InitialAccess", "Persistence", "PrivilegeEscalation"],
    "T1080": ["LateralMovement"],
    "T1082": ["Discovery"],
    "T1083": ["Discovery"],
    "T1087": ["Discovery"],
    "T1090": ["CommandAndControl"],
    "T1091": ["InitialAccess", "LateralMovement"],
    "T1092": ["CommandAndControl"],
    "T1095": ["CommandAndControl"],
    "T1098": ["Persistence"],
    "T1102": ["CommandAndControl"],
    "T1105": ["CommandAndControl"],
    "T1106": ["Execution"],
    "T1110": ["CredentialAccess"],
    "T1111": ["CredentialAccess"],
    "T1112": ["DefenseEvasion"],
    "T1113": ["Collection"],
    "T1114": ["Collection"],
    "T1115": ["Collection"],
    "T1119": ["Collection"],
    "T1120": ["Discovery"],
    "T1123": ["Collection"],
    "T1124": ["Discovery"],
    "T1125": ["Collection"],
    "T1127": ["DefenseEvasion", "Execution"],
    "T1129": ["Execution"],
    "T1132": ["CommandAndControl"],
    "T1133": ["InitialAccess", "Persistence"],
    "T1134": ["DefenseEvasion", "PrivilegeEscalation"],
    "T1135": ["Discovery"],
    "T1136": ["Persistence"],
    "T1137": ["Persistence"],
    "T1140": ["DefenseEvasion"],
    "T1176": ["Persistence"],
    "T1185": ["Collection"],
    "T1187": ["CredentialAccess"],
    "T1189": ["InitialAccess"],
    "T1190": ["InitialAccess"],
    "T1195": ["InitialAccess"],
    "T1197": ["DefenseEvasion", "Persistence"],
    "T1199": ["InitialAccess"],
    "T1200": ["InitialAccess", "Persistence"],
    "T1201": ["Discovery"],
    "T1202": ["DefenseEvasion", "Execution"],
    "T1203": ["Execution"],
    "T1204": ["Execution"],
    "T1205": ["CommandAndControl", "DefenseEvasion", "Persistence"],
    "T1207": ["DefenseEvasion"],
    "T1210": ["LateralMovement"],
    "T1211": ["DefenseEvasion"],
    "T1212": ["CredentialAccess"],
    "T1213": ["Collection"],
    "T1216": ["DefenseEvasion", "Execution"],
    "T1217": ["Discovery"],
    "T1218": ["DefenseEvasion"],
    "T1219": ["CommandAndControl"],
    "T1220": ["DefenseEvasion"],
    "T1221": ["DefenseEvasion"],
    "T1222": ["DefenseEvasion"],
    "T1480": ["DefenseEvasion"],
    "T1482": ["Discovery"],
    "T1484": ["DefenseEvasion", "PrivilegeEscalation"],
    "T1485": ["Impact"],
    "T1486": ["Impact"],
    "T1489": ["Impact"],
    "T1490": ["Impact"],
    "T1491": ["Impact"],
    "T1495": ["Impact"],
    "T1496": ["Impact"],
    "T1497": ["DefenseEvasion", "Discovery"],
    "T1498": ["Impact"],
    "T1499": ["Impact"],
    "T1505": ["Persistence"],
    "T1518": ["Discovery"],
    "T1526": ["Discovery"],
    "T1528": ["CredentialAccess"],
    "T1529": ["Impact"],
    "T1530": ["Collection"],
    "T1531": ["Impact"],
    "T1534": ["LateralMovement"],
    "T1535": ["DefenseEvasion"],
    "T1538": ["Discovery"],
    "T1539": ["CredentialAccess"],
    "T1542": ["DefenseEvasion", "Persistence"],
    "T1543": ["Execution", "Persistence", "PrivilegeEscalation"],
    "T1546": ["Execution", "Persistence", "PrivilegeEscalation"],
    "T1547": ["Persistence", "PrivilegeEscalation"],
    "T1548": ["DefenseEvasion", "PrivilegeEscalation"],
    "T1550": ["DefenseEvasion", "LateralMovement"],
    "T1552": ["CredentialAccess"],
    "T1553": ["DefenseEvasion"],
    "T1554": ["Persistence"],
    "T1555": ["CredentialAccess"],
    "T1556": ["CredentialAccess", "DefenseEvasion", "Persistence"],
    "T1557": ["CredentialAccess", "Collection"],
    "T1558": ["CredentialAccess"],
}


def base_technique(technique_id: str) -> str:
    """Strip a sub-technique suffix: 'T1053.005' -> 'T1053'."""
    return technique_id.split(".", 1)[0]


def tactics_for_techniques(technique_ids: list[str]) -> tuple[list[str], list[str]]:
    """Return (mapped_base_technique_ids, tactics).

    Confirmed live 2026-08-31: Microsoft.SecurityInsights/hunts' attackTechniques
    still 400s ("no valid AttackTactic for the AttackTechniques provided") even
    when a matching attackTactics entry is supplied, for every *sub-technique*
    id tested (T1566.001, T1195.001, T1553.002, ...) -- while a bare base
    technique with an empty attackTechniques array (nothing in our map) synced
    fine. That points to this API version's AttackTechnique enum not
    recognizing dotted sub-technique ids at all, unlike the relevantTechniques
    field documented for scheduled analytics rules. So this returns *base*
    technique ids (sub-technique suffix stripped, deduped), not the original
    ids -- callers must not assume mapped ids echo their input.

    Unmapped base techniques are dropped (logged), not raised: a hunt with
    fewer -- or zero -- attackTechniques is still valid to sync; a 400 from
    ARM for an unrecognized technique is not."""
    mapped: list[str] = []
    seen: set[str] = set()
    tactics: set[str] = set()
    for tid in technique_ids:
        base = base_technique(tid)
        found = TACTICS_BY_TECHNIQUE.get(base)
        if not found:
            logger.warning("MITRE_TACTIC_UNMAPPED technique_id=%s -- dropped from hunt sync", tid)
            continue
        if base not in seen:
            seen.add(base)
            mapped.append(base)
        tactics.update(found)
    return mapped, sorted(tactics)
