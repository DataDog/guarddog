rule capability_filesystem_read
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects filesystem read capabilities"
        identifies = "capability.filesystem.read"
        severity = "low"
        specificity = "low"
        sophistication = "low"

        max_hits = 1
        path_include = "*.py,*.pyx,*.pyi,*.pth,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs,*.go"
    strings:
        // Python
        $py_open = /\bopen\s*\([^)]*['"][^'"]*['"]\s*,\s*['"]r/
        $py_read = /\.(read|readlines|readline)\s*\(/
        $py_path = /Path\([^)]*\)\.read_(text|bytes)\(/

        // JavaScript/TypeScript
        $js_read = /fs\.(readFile|readFileSync)/
        $js_stream = /fs\.createReadStream/
        // Same calls reached through a destructured or named import, which
        // carries no `fs.` prefix at the call site. Keyed on the import so a
        // local helper that happens to be called readFileSync is not matched.
        $js_named_require = /\{[^}]{0,200}\b(readFile|readFileSync|createReadStream)\b[^}]{0,200}\}\s*=\s*require\s*\(\s*['"](node:)?fs(\/promises)?['"]/
        $js_named_import = /import\s*\{[^}]{0,200}\b(readFile|readFileSync|createReadStream)\b[^}]{0,200}\}\s*from\s*['"](node:)?fs(\/promises)?['"]/

        // Go
        $go_read = /ioutil\.ReadFile/
        $go_open = /os\.Open\(/

    condition:
        any of them
}
