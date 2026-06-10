# Rule false-positive review fixtures

Paired test fixtures for the source-code `threat-*` rules that produced false
positives when scanning the top 50 npm + top 50 PyPI packages (see
`rule_false_positives.html` at the repo root for the full analysis).

For every rule there is one directory under `fixtures/<rule>/` containing:

- `malicious.<ext>` - synthetic code that **should** match the rule (a true
  positive). Not actually harmful; it only carries the textual pattern the rule
  targets. This guards against a fix that is too aggressive and silently breaks
  detection.
- `benign.<ext>` - a real false-positive pattern observed on a trusted package.
  It **should not** match the rule. Until the rule is fixed it still matches,
  which the validator reports as `FP PRESENT`.

## Usage

```bash
# (Re)generate the fixture files from their definitions
uv run python tests/rule_fp_review/generate_fixtures.py

# Check every rule against its pair
uv run python tests/rule_fp_review/validate.py
```

(Use `poetry run python ...` instead of `uv run` if that is your setup.)

### Statuses

| Status       | Meaning                                                                 |
|--------------|-------------------------------------------------------------------------|
| `OK`         | malicious matches, benign does not - the rule behaves correctly         |
| `FP PRESENT` | malicious matches, benign also matches - the false positive still exists |
| `BROKEN`     | malicious no longer matches - a fix removed a real detection            |

The baseline (before any rule changes) is **every rule `FP PRESENT`**: the true
positive is detected and the false positive is reproduced. As each rule is
fixed, its row should flip to `OK`. A row must never become `BROKEN`.

`validate.py` exits non-zero if any rule is `BROKEN`. Pass `--strict` to also
fail while any `FP PRESENT` remains (useful once all fixes are expected to land).

The validator parses the public rule name(s) directly from each `.yar` file, so
it is correct even where the rule name differs from the filename (e.g.
`threat-process-sysinfo` defines `threat_process_spawn_sysinfo`, and
`threat-network-exfiltration` defines `threat_network_outbound`).

## Editing fixtures

Fixture content lives in `generate_fixtures.py` (one entry per rule). Edit there
and rerun the generator so the definitions stay the single source of truth.
