include "hooks.meta"
include "lolbas-proc.meta"
include "lolbas-net.meta"

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
        (has_npm_hook or has_python_hook) and (lolbas_proc or lolbas_net)
}
