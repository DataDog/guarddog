include "hooks.meta"
include "lolbas-proc.meta"
include "lolbas-net.meta"

private rule has_only_build_compilers
{
    // Only allowlist tools that compile/transform code and cannot execute
    // arbitrary packages. Excludes npm/npx/yarn/pnpm (can run arbitrary
    // packages), shx (shell wrapper), and other generic command runners.
    strings:
        $tsc = /"\s*tsc\b/ nocase
        $tshy = /"\s*tshy\b/ nocase
        $rollup = /"\s*rollup\s/ nocase
        $husky = /"\s*husky\b/ nocase
        $npmignore = /"\s*npmignore\s/ nocase

    condition:
        any of them
}

rule threat_process_hooks
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects LOLBAS usage in install hooks (execution and network tools)"
        identifies = "threat.process.hooks"
        severity = "medium"
        mitre_tactics = "execution"
        specificity = "medium"
        sophistication = "low"

        max_hits = 1
        path_include = "*/package.json,*/setup.py"

    condition:
        (has_npm_hook or has_python_hook) and (lolbas_proc or lolbas_net) and not has_only_build_compilers
}
