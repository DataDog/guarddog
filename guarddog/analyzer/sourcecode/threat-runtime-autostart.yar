rule threat_runtime_autostart
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects .pth files shipped in a package (auto-processed at every Python startup)"
        identifies = "threat.runtime.autostart"
        severity = "medium"
        mitre_tactics = "persistence"
        specificity = "high"
        sophistication = "low"

        max_hits = 3
        path_include = "*.pth"

    strings:
        // Python's site module auto-processes every .pth file in site-packages at
        // interpreter startup: lines starting with "import" are executed, and even
        // path-only lines inject sys.path entries. A .pth shipped in a published
        // PyPI distribution is therefore itself a persistence mechanism (presence
        // is the risk - no inline indicators required).
        //
        // Presence-based: match any non-empty content. The analyzer records
        // findings per matched string, so the rule must reference a string that
        // actually matches the file - a condition-only rule (externals alone)
        // would match but yield no finding.
        $any_content = /.+/
        // setuptools editable installs are the only benign .pth generator and are
        // pattern-excluded below: their files are artifacts of local development
        // installs ("import __editable___..._finder; ...install()"), never
        // published wheels.
        //
        // Accepted trade-off: legacy pre-PEP-420 namespace-package .pth files with
        // path-only lines would also match. These are rare and legacy enough to
        // accept for a medium-severity persistence signal.
        $editable_marker = "__editable___" nocase

    condition:
        ecosystem == "pypi" and $any_content and not $editable_marker
}
