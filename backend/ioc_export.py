import csv
import io
import json
import uuid as _uuid
from datetime import datetime, timezone


def _norm_dt(dt_str: str) -> str:
    """Normalize SQLite datetime to STIX-compatible ISO 8601."""
    if not dt_str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    s = dt_str.replace(" ", "T")
    return s if s.endswith("Z") else s + "Z"


def iocs_to_csv(ioc_rows: list) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["type", "subtype", "value", "first_seen", "last_seen", "occurrence_count"],
    )
    writer.writeheader()
    for row in ioc_rows:
        writer.writerow({
            "type":             row["type"],
            "subtype":          row.get("subtype") or "",
            "value":            row["value"],
            "first_seen":       row["first_seen"],
            "last_seen":        row["last_seen"],
            "occurrence_count": row["occurrence_count"],
        })
    return output.getvalue()


def iocs_to_stix_bundle(ioc_rows: list) -> dict:
    """Generate a STIX 2.1 Bundle from ioc_ledger rows. Requires stix2 package."""
    from stix2 import Indicator, ThreatActor, Bundle  # type: ignore

    objects = []
    for row in ioc_rows:
        ioc_type = row["type"]
        value    = row["value"]
        subtype  = row.get("subtype") or ""
        valid_from = _norm_dt(row["first_seen"])
        modified   = _norm_dt(row["last_seen"])
        stable_id_key = f"{ioc_type}:{subtype}:{value}"

        try:
            if ioc_type == "threat-actor":
                obj = ThreatActor(
                    id=f"threat-actor--{_uuid.uuid5(_uuid.NAMESPACE_DNS, stable_id_key)}",
                    name=value,
                    created=valid_from,
                    modified=modified,
                )
            else:
                if ioc_type == "ipv4-addr":
                    pattern = f"[ipv4-addr:value = '{value}']"
                elif ioc_type == "domain-name":
                    pattern = f"[domain-name:value = '{value}']"
                elif ioc_type == "url":
                    pattern = f"[url:value = '{value}']"
                elif ioc_type == "file":
                    ht = subtype or "SHA-256"
                    pattern = f"[file:hashes.'{ht}' = '{value}']"
                elif ioc_type == "vulnerability":
                    pattern = f"[vulnerability:name = '{value}']"
                else:
                    continue

                kwargs = dict(
                    id=f"indicator--{_uuid.uuid5(_uuid.NAMESPACE_DNS, stable_id_key)}",
                    name=f"{ioc_type}: {value}",
                    pattern=pattern,
                    pattern_type="stix",
                    valid_from=valid_from,
                    created=valid_from,
                    modified=modified,
                    indicator_types=["malicious-activity"],
                )
                if ioc_type == "vulnerability":
                    kwargs["external_references"] = [
                        {"source_name": "cve", "external_id": value}
                    ]
                obj = Indicator(**kwargs, allow_custom=True)
            objects.append(obj)
        except Exception:
            continue

    if not objects:
        return {"type": "bundle", "id": f"bundle--{_uuid.uuid4()}", "objects": []}
    bundle = Bundle(*objects)
    return json.loads(bundle.serialize())
