---
name: writing-guarddog-rules
description: Author, edit, and review GuardDog YARA source-code detection rules (.yar) that follow the capability/threat/risk model. Use when adding a new detection rule, changing an existing rule's patterns or metadata, splitting capabilities from threats, debugging false positives, or writing rule test cases under guarddog/analyzer/sourcecode/.
---

# Writing GuardDog Rules

GuardDog detects supply-chain malware with a two-layer model. The full reference,
including the philosophy, metadata schema, and worked examples, lives in
**`WRITING_RULES.md` at the repository root** (the skill directory is
`.claude/skills/writing-guarddog-rules/`, so the doc is three levels up). This
skill is the procedural layer: it captures the mental model and the workflow,
and it points to the reference for detail. Read `WRITING_RULES.md` when you need
the schema specifics, field definitions, or longer examples; do not duplicate it.

## The model (memorize this, skip the doc for simple calls)

- **Capability = "CAN DO"** — a function call that enables an action
  (`requests.get(`, `.readFileSync(`, `subprocess.Popen(`). Match calls, not imports.
- **Threat = "SUSPICIOUS"** — an attacker indicator (`/etc/passwd`, `discord.com/api/webhooks`,
  `base64.decode` + `exec` together). Not a bare function call.
- **Risk = capability + threat in the same file with matching category.** A capability
  alone is benign; a threat indicator alone is often a false positive; together they are a risk.
- **`identifies` format:** `{type}.{category}[.{detail}]` where type is `capability` or `threat`,
  category is one of `network`, `filesystem`, `process`, `runtime`, `system`, `metadata`.
- **Categories must match** for a risk to form. `capability.process.*` only pairs with
  `threat.process.*`. General detail matches specific (`threat.network` + `capability.network.outbound`),
  but conflicting details do not (`...outbound` + `...inbound`).
- **`threat.runtime.*` and `threat.metadata.*` auto-form risks** without needing a capability
  (obfuscation, install hooks, typosquatting, maintainer compromise).

When unsure whether a pattern is a capability or threat: does it show what code *can do* (capability)
or a *suspicious indicator* (threat)? Does it stand alone without a capability (runtime/metadata threat)?

## Authoring workflow

1. **Decide type and category.** Pick `capability` vs `threat`, then category and optional detail.
   Confirm the matching counterpart exists or will exist so a risk can form.
2. **Write patterns** as YARA (`.yar`). Source-code rules are YARA-only and language-agnostic
   (loaded for every ecosystem). Note that `WRITING_RULES.md` still shows a Semgrep `.yml` example;
   that path no longer exists in this codebase, so ignore it and write YARA. Follow the best
   practices in `WRITING_RULES.md` (word boundaries `\b`,
   match method calls not object names, require quote context for bare strings, establish context
   with private rules before matching threats). Extract shared building blocks (LOLBAS, hooks) into
   `.meta` files instead of repeating them.
3. **Add metadata.** Required: `identifies`, `severity`, `description`. Threat rules also need a
   single `mitre_tactics`. Optional `specificity`/`sophistication` default to `medium`. Also
   available: `max_hits`, `path_include`. See the schema section of `WRITING_RULES.md`.
4. **Name and place the file** under `guarddog/analyzer/sourcecode/` as `{type}-{category}-{detail}.yar`.
   `.meta` files (shared private rules) are `{pattern-name}.meta`.
5. **Write test cases** (see below).
6. **Run the checklist** at the end of `WRITING_RULES.md` before finishing.

## Testing rules (the real harness)

The testing section of `WRITING_RULES.md` is out of date for YARA. Use the actual harness in
`tests/analyzer/sourcecode/test_sourcecode_yara.py`:

- **The YARA rule's internal name must be the file id with hyphens replaced by underscores.**
  File `capability-filesystem-read.yar` must contain `rule capability_filesystem_read`. The
  no-false-positive test filters matches to this exact name, so a mismatch silently skips coverage.
- **Positive test:** add a file `tests/analyzer/sourcecode/<rule-id>.<ext>` containing code the rule
  should flag (e.g. `<rule-id>.py`, `.js`, `.go`, `.rb`). The harness asserts the rule matches it.
  These are matched by filename prefix, not by `# ruleid:` comments.
- **Negative test (false positives):** add `tests/analyzer/sourcecode/benign/<rule-id>.<ext>` with
  legitimate code that must NOT trigger the main rule. Every new or changed rule should have one.
- **Compilation:** all `.yar` files must compile, including `include "...meta"` references resolving.

Run the suite:

```bash
make test-yara-rules
# or directly:
uv run pytest tests/analyzer/sourcecode -k <rule-id>
```

Scan a real package or local path to sanity-check end to end (use `uv run`):

```bash
uv run guarddog pypi scan <package-name> --rules <rule-id>
uv run guarddog pypi scan /path/to/package --output-format json
```

## Common patterns and pitfalls

- **Install hooks are a capability, not a threat.** A hook is process-spawning ability like
  `subprocess.call()`. The threat is the LOLBAS tool *inside* the hook. Pair
  `capability.process.hooks` with `threat.process.hooks` (hook context + curl/wget). See the
  Advanced Patterns section of `WRITING_RULES.md`.
- **Split LOLBAS by purpose:** `lolbas-proc.meta` (bash, python, node) vs `lolbas-net.meta`
  (curl, wget, nc). YARA cannot reliably use multiple private rules from one include, so keep
  them separate and compose includes per rule.
- **Avoid false positives from shebangs, READMEs, and non-hook code** by establishing context
  with private rules rather than matching a bare keyword anywhere.
- After adding or editing rules, regenerate docs if the repo expects it: `make docs`.
