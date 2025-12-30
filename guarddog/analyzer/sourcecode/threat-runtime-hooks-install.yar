rule threat_runtime_hooks_install
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects installation hooks that execute code during package install"
        identifies = "threat.runtime.hooks.install"
        severity = "high"
        mitre_tactics = "execution,initial-access"
        specificity = "medium"
        sophistication = "low"

        max_hits = 3
        path_include = "*/package.json,*/setup.py"
    strings:
        // Python - setup.py cmdclass overrides
        $py_cmdclass = "cmdclass" nocase
        $py_install = "install" nocase
        $py_develop = "develop" nocase
        $py_egg_info = "egg_info" nocase

        // JavaScript/Node.js - package.json scripts
        $npm_preinstall = /"preinstall"[\s]*:/ nocase
        $npm_install = /"install"[\s]*:/ nocase
        $npm_postinstall = /"postinstall"[\s]*:/ nocase
        $npm_prepack = /"prepack"[\s]*:/ nocase
        $npm_prepare = /"prepare"[\s]*:/ nocase

    condition:
        ($py_cmdclass and ($py_install or $py_develop or $py_egg_info)) or
        any of ($npm_*)
}
