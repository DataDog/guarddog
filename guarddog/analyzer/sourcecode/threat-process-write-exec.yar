rule threat_process_write_exec
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects code that writes a script or payload to disk and then executes it"
        identifies = "threat.process.spawn"
        severity = "high"
        mitre_tactics = "execution"
        // medium, not high: YARA matches per file with no dataflow, so the rule
        // cannot prove the file that was written is the file that gets run. Dev
        // tooling that legitimately generates and runs scripts still matches —
        // measured at 2 hits over 2392 real site-packages files (pytest's
        // pytester, click's editor helper).
        specificity = "medium"
        sophistication = "medium"
        max_hits = 3
        path_include = "*.py,*.pyx,*.pyi,*.pth"

    strings:
        // --- Obtaining a scratch path to drop the payload into ---
        // Creation primitives only. `import tempfile` or a bare `gettempdir()` are
        // not evidence that anything was dropped, and WRITING_RULES.md warns that
        // import-only strings drive false positives — they matched guarddog's own
        // evals/cluster_worker.py, which writes results and spawns workers.
        $tmp_named = /\bNamedTemporaryFile\s*\(/ nocase
        $tmp_mkstemp = /\bmkstemp\s*\(/ nocase
        $tmp_mktemp = /\bmktemp\s*\(/ nocase

        // Aliased tempfile import. Malware renames the primitives so that literal
        // `tempfile.NamedTemporaryFile(` never appears in the source.
        $tmp_alias = /\bfrom\s+tempfile\s+import\s+\w+\s+as\s+\w+/ nocase

        // --- Writing the payload out ---
        $write_call = /\.write\s*\(\s*[bfru]{0,2}["']/ nocase
        $write_open = /\bopen\s*\([^)]*["'][wa]b?\+?["']/ nocase

        // --- Executing what was just written ---
        $run_os_system = /\bos\.(system|popen|startfile)\s*\(/ nocase
        $run_subprocess = /\bsubprocess\.(run|call|Popen|check_call|check_output)\s*\(/ nocase
        $run_executable = /\bsys\.executable\b/ nocase

        // Aliased execution primitives. The sample in issue #205 uses
        // `from os import system as _ssystem`, which defeats every rule that
        // only looks for a literal `os.system(`.
        $run_alias_os = /\bfrom\s+os\s+import\s+(system|popen|startfile)\s+as\s+\w+/ nocase
        $run_alias_subprocess = /\bfrom\s+subprocess\s+import\s+(run|call|Popen|check_call|check_output)\s+as\s+\w+/ nocase
        $run_alias_executable = /\bfrom\s+sys\s+import\s+executable\s+as\s+\w+/ nocase

        // --- Referring to the dropped file when launching it ---
        // `.name` closing an f-string placeholder or a call argument, `start <file>`,
        // and `python <file>` are the three shapes seen in the wild.
        $ref_name = /\.name\s*[\)\},]/
        $ref_start_cmd = /["']start\s/ nocase
        // Must name a .py file or interpolate the dropped path. A bare
        // /python\s+\w/ also matches ordinary prose such as "Python library",
        // which fired on guarddog's own evals/cluster_worker.py.
        $ref_python_script = /\bpython[w0-9.]*(\.exe)?\s+[^\s"']*\.py\b/ nocase
        $ref_python_interp = /\bpython[w0-9.]*(\.exe)?\s+\{/ nocase

    condition:
        any of ($tmp_*) and
        any of ($write_call, $write_open) and
        (
            // Shell or interpreter launch aimed at the path that was just written.
            (
                any of ($run_os_system, $run_alias_os, $run_executable, $run_alias_executable)
                and any of ($ref_*)
            )
            or
            // subprocess is only suspicious here when it launches an interpreter.
            // Handing a temp file to an unrelated binary — `subprocess.run(["ffmpeg", ..., f.name])`
            // — is ordinary and must not match.
            (
                any of ($run_subprocess, $run_alias_subprocess)
                and any of ($run_executable, $run_alias_executable, $ref_python_script, $ref_python_interp, $ref_start_cmd)
            )
        )
}
