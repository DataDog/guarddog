include "hooks.meta"
include "lolbas-proc.meta"
include "lolbas-net.meta"

private rule has_benign_hook_command
{
    strings:
        // Standard JS/TS build tooling
        $npm_run = /"\s*(npm|npx)\s+run\s/ nocase
        $yarn_cmd = /"\s*yarn\s/ nocase
        $pnpm_cmd = /"\s*pnpm\s/ nocase
        $jlpm_cmd = /"\s*jlpm\s/ nocase
        $tsc_cmd = /"\s*tsc\b/ nocase
        $tshy_cmd = /"\s*tshy\b/ nocase
        $rollup_cmd = /"\s*rollup\s/ nocase
        $husky_cmd = /"\s*husky\b/ nocase
        $npmignore = /"\s*npmignore\s/ nocase
        $shx_cmd = /"\s*shx\s/ nocase

        // Python build tooling
        $pip_install = /\bpython[0-9]?\s+-m\s+pip\s+install\b/ nocase
        $pip_setup = /\bpython[0-9]?\s+setup\.py\b/ nocase

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
        (has_npm_hook or has_python_hook) and (lolbas_proc or lolbas_net) and not has_benign_hook_command
}
