# JSON output schema

`cloudcomply report nist --format json` writes a JSON **array** of finding objects to stdout. Each object represents one NIST SP 800-53 control.

## Fields

| Field | Type | Values | Description |
|---|---|---|---|
| `control_id` | string | e.g. `AC-2`, `SC-28(1)` | NIST SP 800-53 Rev. 5 control or enhancement ID |
| `title` | string | | Control title. Control characters are stripped. |
| `family` | string | `AC`, `AU`, `CM`, `IA`, `SC`, `SI`, … | Control family prefix of `control_id` |
| `status` | string | `PASSED` \| `FAILED` | `FAILED` if any finding mapped to this control failed (Security Hub `FAILED` or `WARNING`) |
| `severity` | string | `CRITICAL` \| `HIGH` \| `MEDIUM` \| `LOW` | Highest severity among failing findings. `INFORMATIONAL` maps to `LOW`. |
| `accounts_affected` | integer | `≥ 0` | Distinct AWS accounts with at least one failing finding for the control |
| `rmf_step` | string | `Assess` \| `Monitor` \| `Implement` | Suggested NIST RMF step. Live data uses `Assess` (failing) or `Monitor` (passing). |
| `min_impact_level` | string | `IL2` \| `IL4` \| `IL5` \| `IL6` | Lowest DoD Cloud Computing SRG Impact Level requiring the control (see note) |

!!! warning "`min_impact_level` in live mode"
    The NIST → DoD SRG crosswalk isn't built yet, so every **live** finding currently reports `IL2`. Demo data carries realistic values. Don't use this field from live output to decide scope until the [roadmap](../project/roadmap.md) item lands.

## Stability

Field names are snake_case and are a **compatibility contract**. They won't be renamed or removed without a major version bump. New fields may be added, so consumers should ignore fields they don't recognize.

The output is an empty array (`[]`), not `null`, when Security Hub returns no NIST findings.

## JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "cloudcomply report nist",
  "type": "array",
  "items": {
    "type": "object",
    "required": ["control_id", "title", "family", "status", "severity",
                 "accounts_affected", "rmf_step", "min_impact_level"],
    "properties": {
      "control_id":        { "type": "string" },
      "title":             { "type": "string" },
      "family":            { "type": "string" },
      "status":            { "enum": ["PASSED", "FAILED"] },
      "severity":          { "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"] },
      "accounts_affected": { "type": "integer", "minimum": 0 },
      "rmf_step":          { "type": "string" },
      "min_impact_level":  { "enum": ["IL2", "IL4", "IL5", "IL6"] }
    }
  }
}
```

## jq recipes

```bash
# Failed controls only
cloudcomply report nist --format json | jq '[.[] | select(.status == "FAILED")]'

# Count of failures by severity
cloudcomply report nist --format json \
  | jq 'map(select(.status=="FAILED")) | group_by(.severity) | map({(.[0].severity): length}) | add'

# Compliance percentage (same formula as the dashboard)
cloudcomply report nist --format json \
  | jq '(map(select(.status=="PASSED")) | length) * 100 / length | floor'

# Per-family pass rate
cloudcomply report nist --format json \
  | jq 'group_by(.family) | map({family: .[0].family, passed: map(select(.status=="PASSED"))|length, total: length})'

# CSV for spreadsheets / POA&M drafting
cloudcomply report nist --format json \
  | jq -r '["control","title","status","severity","accounts"], (.[] | [.control_id,.title,.status,.severity,.accounts_affected]) | @csv'
```
