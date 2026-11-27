# A3E-DNS manifest schemas

JSON Schemas (Draft 2020-12) for the manifests the extended suite
produces. Every manifest the Python modules write can be validated
against one of the schemas below; the validation script applies the
correct schema based on the manifest's file name and contents.

## Files

| Schema | Validates |
|--------|-----------|
| `manifest.schema.json` | The common envelope every manifest carries |
| `scenario_row.schema.json` | One row of the attack catalogue |
| `metrics.schema.json` | `core_metrics.json` and evaluation manifests |
| `byzantine_round.schema.json` | One round of the Byzantine sweep |
| `experiment_run.schema.json` | One entry in the orchestrator state file |

## Validating

```bash
python3 scripts/validate_manifests.py \
    --schemas schemas \
    --manifests runs/experiments
