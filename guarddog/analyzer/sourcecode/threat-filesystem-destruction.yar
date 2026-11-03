rule threat_filesystem_destruction
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects destructive operations (recursive deletion, wiping)"
        identifies = "threat.filesystem.destruction"
        severity = "high"
        mitre_tactics = "impact"
        specificity = "high"
        sophistication = "medium"
        max_hits = 3
        path_include = "*.py,*.pyx,*.pyi,*.pth,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs"

    strings:
        // Recursive/dangerous deletions
        $dangerous_rm = /rm\s+-rf\s+\// nocase
        $dangerous_rmtree_root = /rmtree\s*\(\s*['"]\/[^'"]*['"]/ nocase
        $py_rmtree_home = /rmtree\s*\(\s*['"]~/ nocase
        $py_rmtree_user = /rmtree\s*\(\s*os\.path\.expanduser/ nocase

        // Wiping specific important directories. The 'rm' must be a whole
        // word close to the quoted path: an unbounded 'rm.*' also matched
        // substrings like 'terminated' in minified bundles followed by a
        // '/home' string hundreds of bytes away (pdf.js Emscripten runtime,
        // issue #903).
        $wipe_home = /\brm\b.{0,40}['"]\/home[\/'"]/ nocase
        $wipe_users = /\brm\b.{0,40}['"]\/Users[\/'"]/ nocase
        $wipe_root = /\brm\b.{0,40}['"]\/['"]\s*$/ nocase

        // Disk wiping utilities
        $dd_zero = "dd if=/dev/zero" nocase
        $dd_random = "dd if=/dev/urandom" nocase
        $shred = "shred -" nocase

        // Node.js - recursive deletion of a hardcoded root/absolute path
        $js_rimraf_root = /rimraf\s*\(\s*['"]\/[^'"]*['"]/ nocase

    condition:
        any of them
}
