"""
Validates the false-positive review fixtures against the current YARA rules.

For each rule with a fixture pair under fixtures/<rule>/:
  - malicious.*  MUST match the rule  (true positive still detected)
  - benign.*     MUST NOT match the rule (false positive eliminated)

It parses the public (non-included) rule name(s) directly from each .yar file so
it works even when the YARA rule name differs from the filename (e.g.
threat-process-sysinfo -> threat_process_spawn_sysinfo).

Statuses:
  OK          malicious matches, benign does not  -> rule behaves correctly
  FP PRESENT  malicious matches, benign ALSO matches -> the false positive still
              exists (expected before the rule is fixed; should become OK after)
  BROKEN      malicious no longer matches -> a fix went too far, true positive lost

Run:  uv run python tests/rule_fp_review/validate.py
Exit code is non-zero if any rule is BROKEN, or (with --strict) if any FP remains.
"""
import os
import re
import sys
import glob

import yara  # type: ignore

from guarddog.analyzer.analyzer import SOURCECODE_RULES_PATH

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

RULE_DECL = re.compile(r"^\s*(?:private\s+)?rule\s+(\w+)", re.MULTILINE)


def own_rule_names(rule_id: str) -> set[str]:
    """Names of rules declared in the rule's own .yar file (excludes `include`d files)."""
    path = os.path.join(SOURCECODE_RULES_PATH, f"{rule_id}.yar")
    with open(path) as f:
        return set(RULE_DECL.findall(f.read()))


def compile_rule(rule_id: str):
    path = os.path.join(SOURCECODE_RULES_PATH, f"{rule_id}.yar")
    return yara.compile(filepaths={rule_id: path})


def matches_own(compiled, own: set[str], target_file: str) -> list[str]:
    hits = compiled.match(target_file)
    return [m.rule for m in hits if m.rule in own]


def main() -> int:
    strict = "--strict" in sys.argv
    rules = sorted(
        d for d in os.listdir(FIXTURES_DIR)
        if os.path.isdir(os.path.join(FIXTURES_DIR, d))
    )

    rows = []
    broken = 0
    fp_present = 0

    for rule_id in rules:
        d = os.path.join(FIXTURES_DIR, rule_id)
        mal = next(iter(glob.glob(os.path.join(d, "malicious.*"))), None)
        # A rule may have more than one benign sample (benign.*, benign_*.*) when
        # it has several distinct false-positive vectors. All must stay clean.
        bens = sorted(glob.glob(os.path.join(d, "benign*.*")))

        own = own_rule_names(rule_id)
        compiled = compile_rule(rule_id)

        mal_hit = bool(matches_own(compiled, own, mal)) if mal else False
        ben_hit = any(matches_own(compiled, own, b) for b in bens)

        if not mal_hit:
            status = "BROKEN"
            broken += 1
        elif ben_hit:
            status = "FP PRESENT"
            fp_present += 1
        else:
            status = "OK"

        rows.append((rule_id, mal_hit, ben_hit, status))

    width = max(len(r[0]) for r in rows)
    print(f"\n{'RULE'.ljust(width)}  MALICIOUS  BENIGN   STATUS")
    print("-" * (width + 30))
    for rule_id, mal_hit, ben_hit, status in rows:
        m = "match " if mal_hit else "MISS  "
        b = "match" if ben_hit else "clean"
        print(f"{rule_id.ljust(width)}  {m}     {b}    {status}")

    ok = sum(1 for r in rows if r[3] == "OK")
    print("-" * (width + 30))
    print(f"{ok} OK   {fp_present} FP PRESENT   {broken} BROKEN   ({len(rows)} rules)")

    if broken:
        print("\nBROKEN rules lost a true positive - a rule change went too far.")
    if fp_present:
        print("FP PRESENT rules still match the benign sample - apply the rule fix.")

    if broken:
        return 1
    if strict and fp_present:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
