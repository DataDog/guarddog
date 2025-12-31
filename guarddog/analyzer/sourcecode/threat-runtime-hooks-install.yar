rule threat_runtime_hooks_install
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects installation hooks that execute code during package install"
        identifies = "threat.runtime.hooks.install"
        severity = "high"
        mitre_tactics = "initial-access"
        specificity = "medium"
        sophistication = "low"

        max_hits = 3
        path_include = "*/package.json,*/setup.py"
    strings:
        // Python - setup.py cmdclass overrides (require dict-like syntax)
        $py_cmdclass_install = /cmdclass\s*=\s*\{[^}]*['"]install['"]\s*:/ nocase
        $py_cmdclass_develop = /cmdclass\s*=\s*\{[^}]*['"]develop['"]\s*:/ nocase
        $py_cmdclass_egg_info = /cmdclass\s*=\s*\{[^}]*['"]egg_info['"]\s*:/ nocase

        // JavaScript/Node.js - package.json scripts (require script value)
        $npm_preinstall = /"preinstall"[\s]*:[\s]*"[^"]+/ nocase
        $npm_install = /"install"[\s]*:[\s]*"[^"]+/ nocase
        $npm_postinstall = /"postinstall"[\s]*:[\s]*"[^"]+/ nocase
        $npm_prepack = /"prepack"[\s]*:[\s]*"[^"]+/ nocase
        $npm_prepare = /"prepare"[\s]*:[\s]*"[^"]+/ nocase

    condition:
        any of ($py_cmdclass*) or
        any of ($npm_*)
}
