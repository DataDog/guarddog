#!/usr/bin/env python3
"""
Worker for fingerprinting a single malicious package ZIP.

Extracts and processes the malicious code inside a Nono sandbox (via
sandboxed_exec) with no network access and restricted filesystem.
Called by cluster.py orchestrator as a subprocess.

For malicious_intent packages: hashes the full normalized source code.
For compromised_lib packages: runs guarddog, then hashes the threat code snippets.

Usage (called by cluster.py, not directly):
    python cluster_worker.py --zip-path /path/to.zip --ecosystem pypi \
        --category malicious_intent --package-name advpruebitaa --output-path /tmp/fp.json
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import zipfile

import tlsh


MAX_EXTRACTED_FILES = 5000
MAX_EXTRACTED_BYTES = 500 * 1024 * 1024  # 500MB

SOURCE_EXTENSIONS = {".py", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}
SKIP_PATTERNS = {"PKG-INFO", "METADATA", "RECORD", "WHEEL", "entry_points.txt", "top_level.txt"}
SKIP_DIR_SEGMENTS = {".egg-info", "__pycache__", "node_modules", ".git"}

VERSION_RE = re.compile(r"\b\d+\.\d+(?:\.\d+)?(?:[-.]\w+)?\b")


def canonicalize_tmp():
    tmp = tempfile.gettempdir()
    return os.path.realpath(tmp)


# ---------------------------------------------------------------------------
# ZIP extraction
# ---------------------------------------------------------------------------

def extract_zip(zip_path: str, dest: str):
    total_bytes = 0
    total_files = 0

    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            if total_files >= MAX_EXTRACTED_FILES:
                raise RuntimeError(f"Too many files in archive (>{MAX_EXTRACTED_FILES})")
            if info.is_dir():
                continue
            if info.external_attr >> 16 & 0o120000 == 0o120000:
                continue

            target = os.path.realpath(os.path.join(dest, info.filename))
            if not target.startswith(os.path.realpath(dest)):
                continue

            total_bytes += info.file_size
            if total_bytes > MAX_EXTRACTED_BYTES:
                raise RuntimeError(f"Archive too large (>{MAX_EXTRACTED_BYTES} bytes)")

            total_files += 1
            zf.extract(info, dest, pwd=b"infected")


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------

def _should_skip_path(rel_path: str) -> bool:
    parts = rel_path.replace("\\", "/").split("/")
    basename = parts[-1]
    if basename in SKIP_PATTERNS:
        return True
    if basename.endswith(".pyc"):
        return True
    for seg in parts:
        if seg in SKIP_DIR_SEGMENTS:
            return True
    return False


def _normalize_name_variants(package_name: str) -> list[str]:
    """Return all common forms of a package name (hyphens, underscores, dots, case)."""
    base = package_name.lower()
    variants = {base, base.replace("-", "_"), base.replace("_", "-"), base.replace("-", "."),
                base.replace(".", "-"), base.replace("_", ".")}
    variants.add(package_name)
    return sorted(variants, key=len, reverse=True)


def normalize_content(content: str, package_name: str) -> str:
    for variant in _normalize_name_variants(package_name):
        content = content.replace(variant, "__PKG__")
    content = VERSION_RE.sub("__VER__", content)
    content = re.sub(r"\n{3,}", "\n\n", content)
    return content.strip()


def normalize_path(rel_path: str, package_name: str) -> str:
    # Strip the first path component: it's the ZIP wrapper directory
    # (e.g. "2023-02-27-pkgname-v8.82/pkgname-8.82/setup.py" -> "pkgname-8.82/setup.py")
    parts = rel_path.replace("\\", "/").split("/")
    if len(parts) > 1:
        rel_path = "/".join(parts[1:])
    normalized = rel_path
    for variant in _normalize_name_variants(package_name):
        normalized = normalized.replace(variant, "__PKG__")
    normalized = VERSION_RE.sub("__VER__", normalized)
    return normalized


# ---------------------------------------------------------------------------
# Fingerprinting logic
# ---------------------------------------------------------------------------

def _fingerprint_package_json_scripts(extracted_dir: str, package_name: str) -> dict | None:
    """Fallback fingerprint: hash the 'scripts' field from package.json.

    Many malicious npm packages have no JS files -- the payload is a one-liner
    in preinstall/postinstall. Returns None if no scripts found.
    """
    for root, _dirs, files in os.walk(extracted_dir):
        if "package.json" not in files:
            continue
        try:
            raw = open(os.path.join(root, "package.json"), "r", errors="replace").read()
            pkg_json = json.loads(raw)
        except (json.JSONDecodeError, OSError):
            continue

        scripts = pkg_json.get("scripts", {})
        if not scripts:
            continue

        # Normalize: sort keys, replace package name
        normalized = json.dumps(scripts, sort_keys=True)
        normalized = normalize_content(normalized, package_name)
        encoded = normalized.encode("utf-8")

        tlsh_hash = tlsh.hash(encoded)
        if tlsh_hash == "TNULL":
            tlsh_hash = ""

        return {
            "fingerprint": hashlib.sha256(encoded).hexdigest(),
            "tlsh": tlsh_hash,
            "file_count": 1,
            "total_bytes": len(encoded),
            "error": None,
        }

    return None


def fingerprint_source(extracted_dir: str, package_name: str) -> dict:
    """Hash the full normalized source code (for malicious_intent packages)."""
    file_entries = []
    total_bytes = 0

    for root, _dirs, files in os.walk(extracted_dir):
        for fname in files:
            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, extracted_dir)

            if _should_skip_path(rel_path):
                continue

            ext = os.path.splitext(fname)[1].lower()
            if ext not in SOURCE_EXTENSIONS:
                continue

            try:
                content = open(full_path, "r", errors="replace").read()
            except Exception:
                continue

            norm_path = normalize_path(rel_path, package_name)
            norm_content = normalize_content(content, package_name)
            total_bytes += len(norm_content)
            file_entries.append((norm_path, norm_content))

    if not file_entries:
        # Fallback: for npm packages with no source files, the malicious payload
        # is often a one-liner in package.json's "scripts" field (preinstall etc.)
        scripts_result = _fingerprint_package_json_scripts(extracted_dir, package_name)
        if scripts_result:
            return scripts_result
        return {"fingerprint": "", "tlsh": "", "file_count": 0, "total_bytes": 0, "error": "no source files found"}

    file_entries.sort(key=lambda x: x[0])

    hasher = hashlib.sha256()
    content_blob = b""
    for path, content in file_entries:
        encoded = content.encode("utf-8")
        hasher.update(path.encode("utf-8"))
        hasher.update(b"\x00")
        hasher.update(encoded)
        hasher.update(b"\x00")
        content_blob += encoded

    tlsh_hash = tlsh.hash(content_blob)
    if tlsh_hash == "TNULL":
        tlsh_hash = ""

    return {
        "fingerprint": hasher.hexdigest(),
        "tlsh": tlsh_hash,
        "file_count": len(file_entries),
        "total_bytes": total_bytes,
        "error": None,
    }


def fingerprint_threats(extracted_dir: str, ecosystem: str, guarddog_bin: str | None) -> dict:
    """Run guarddog, then hash the threat code snippets (for compromised_lib packages)."""
    import subprocess as sp

    if not guarddog_bin:
        guarddog_bin = shutil.which("guarddog")
    if not guarddog_bin:
        return {"fingerprint": "", "tlsh": "", "file_count": 0, "total_bytes": 0, "error": "guarddog not found"}

    try:
        proc = sp.run(
            [guarddog_bin, ecosystem, "scan", extracted_dir, "--output-format", "json", "--no-sandbox"],
            capture_output=True, text=True, timeout=90,
        )
        stdout = proc.stdout.strip()
        if not stdout:
            return {"fingerprint": "", "tlsh": "", "file_count": 0, "total_bytes": 0,
                    "error": f"guarddog exit {proc.returncode}: {proc.stderr[:300]}"}
        scan_output = json.loads(stdout)
    except sp.TimeoutExpired:
        return {"fingerprint": "", "tlsh": "", "file_count": 0, "total_bytes": 0, "error": "guarddog timeout"}
    except Exception as e:
        return {"fingerprint": "", "tlsh": "", "file_count": 0, "total_bytes": 0, "error": str(e)[:300]}

    snippets = []
    results = scan_output.get("results", {})
    for rule_name, findings in results.items():
        if not rule_name.startswith("threat-"):
            continue
        if not isinstance(findings, list):
            continue
        for finding in findings:
            code = finding.get("code", "").strip()
            if code:
                snippets.append(code)

    if not snippets:
        return {"fingerprint": "", "tlsh": "", "file_count": 0, "total_bytes": 0,
                "error": "no threat findings from guarddog"}

    snippets.sort()
    combined = "\n".join(snippets)
    combined_bytes = combined.encode("utf-8")

    tlsh_hash = tlsh.hash(combined_bytes)
    if tlsh_hash == "TNULL":
        tlsh_hash = ""

    return {
        "fingerprint": hashlib.sha256(combined_bytes).hexdigest(),
        "tlsh": tlsh_hash,
        "file_count": len(snippets),
        "total_bytes": len(combined),
        "error": None,
    }


# ---------------------------------------------------------------------------
# Sandbox wrapper
# ---------------------------------------------------------------------------

def _build_sandbox_caps(tmp_dir: str, zip_dir: str, output_dir: str,
                        guarddog_bin: str | None = None):
    """Build a CapabilitySet for the sandboxed child process."""
    import nono_py as nono

    caps = nono.CapabilitySet()
    caps.allow_path(tmp_dir, nono.AccessMode.READ_WRITE)
    caps.allow_path(zip_dir, nono.AccessMode.READ)
    caps.allow_path(output_dir, nono.AccessMode.READ_WRITE)

    # The sandboxed child needs to read this script to execute it
    script_dir = os.path.dirname(os.path.realpath(__file__))
    caps.allow_path(script_dir, nono.AccessMode.READ)

    python_prefix = os.path.realpath(sys.prefix)
    caps.allow_path(python_prefix, nono.AccessMode.READ)

    base_prefix = os.path.realpath(sys.base_prefix)
    if base_prefix != python_prefix:
        caps.allow_path(base_prefix, nono.AccessMode.READ)

    if guarddog_bin:
        gd_dir = os.path.realpath(os.path.dirname(guarddog_bin))
        caps.allow_path(gd_dir, nono.AccessMode.READ)

    # Guarddog's YARA/semgrep rules and editable-install metadata may live
    # outside the venv (in the project root). Allow the whole project tree
    # as read-only -- the sandbox still restricts writes to tmp_dir only.
    try:
        import guarddog as _gd
        gd_pkg_dir = os.path.realpath(os.path.dirname(_gd.__file__))
        # For editable installs, the project root is one level up from the package
        project_root = os.path.dirname(gd_pkg_dir)
        caps.allow_path(project_root, nono.AccessMode.READ)
    except ImportError:
        pass

    caps.block_network()
    return caps


def run_sandboxed(zip_path: str, ecosystem: str, category: str, package_name: str,
                  output_path: str, guarddog_bin: str | None, timeout: int):
    """Extract and fingerprint inside a Nono-sandboxed child process."""
    import nono_py as nono

    tmp_base = canonicalize_tmp()
    tmp_dir = tempfile.mkdtemp(dir=tmp_base, prefix="guarddog_cluster_")

    try:
        caps = _build_sandbox_caps(
            tmp_dir, os.path.dirname(zip_path), os.path.dirname(output_path), guarddog_bin)

        # The child runs this same script with --_sandboxed to do the actual work
        cmd = [
            sys.executable, os.path.realpath(__file__),
            "--_sandboxed",
            "--zip-path", zip_path,
            "--ecosystem", ecosystem,
            "--category", category,
            "--package-name", package_name,
            "--output-path", output_path,
            "--tmp-dir", tmp_dir,
        ]
        if guarddog_bin:
            cmd.extend(["--guarddog-bin", guarddog_bin])

        result = nono.sandboxed_exec(caps, cmd, timeout_secs=timeout)

        if result.exit_code != 0:
            # Child failed; write error if it didn't manage to write output
            if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
                stderr = result.stderr
                if isinstance(stderr, bytes):
                    stderr = stderr.decode("utf-8", errors="replace")
                error_msg = stderr[:500] if stderr else f"exit code {result.exit_code}"
                with open(output_path, "w") as f:
                    json.dump({"fingerprint": "", "tlsh": "", "file_count": 0, "total_bytes": 0,
                               "error": error_msg}, f)
    except Exception as e:
        try:
            with open(output_path, "w") as f:
                json.dump({"fingerprint": "", "tlsh": "", "file_count": 0, "total_bytes": 0,
                           "error": str(e)[:500]}, f)
        except Exception:
            pass
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def run_unsandboxed(zip_path: str, ecosystem: str, category: str, package_name: str,
                    output_path: str, guarddog_bin: str | None):
    """Extract and fingerprint without sandbox (for testing only)."""
    tmp_base = canonicalize_tmp()
    tmp_dir = tempfile.mkdtemp(dir=tmp_base, prefix="guarddog_cluster_")

    try:
        extract_zip(zip_path, tmp_dir)

        if category == "malicious_intent":
            result = fingerprint_source(tmp_dir, package_name)
        else:
            result = fingerprint_threats(tmp_dir, ecosystem, guarddog_bin)

        with open(output_path, "w") as f:
            json.dump(result, f, indent=2)

    except Exception as e:
        try:
            with open(output_path, "w") as f:
                json.dump({"fingerprint": "", "tlsh": "", "file_count": 0, "total_bytes": 0,
                           "error": str(e)[:500]}, f)
        except Exception:
            pass
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Entry point for the sandboxed child (called via --_sandboxed)
# ---------------------------------------------------------------------------

def run_sandboxed_child(args):
    """Runs inside the Nono sandbox. Extracts ZIP and fingerprints."""
    try:
        extract_zip(args.zip_path, args.tmp_dir)

        if args.category == "malicious_intent":
            result = fingerprint_source(args.tmp_dir, args.package_name)
        else:
            guarddog_bin = getattr(args, "guarddog_bin", None) or shutil.which("guarddog")
            result = fingerprint_threats(args.tmp_dir, args.ecosystem, guarddog_bin)

        with open(args.output_path, "w") as f:
            json.dump(result, f, indent=2)

    except Exception as e:
        try:
            with open(args.output_path, "w") as f:
                json.dump({"fingerprint": "", "tlsh": "", "file_count": 0, "total_bytes": 0,
                           "error": str(e)[:500]}, f)
        except Exception:
            pass
        sys.exit(1)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Package fingerprinting worker")
    parser.add_argument("--zip-path", required=True)
    parser.add_argument("--ecosystem", required=True, choices=["pypi", "npm"])
    parser.add_argument("--category", required=True, choices=["malicious_intent", "compromised_lib"])
    parser.add_argument("--package-name", required=True)
    parser.add_argument("--output-path", required=True)
    parser.add_argument("--guarddog-bin", default=None)
    parser.add_argument("--no-sandbox", action="store_true")
    parser.add_argument("--timeout", type=int, default=120)
    # Internal flag: set by run_sandboxed when re-invoking inside the sandbox
    parser.add_argument("--_sandboxed", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--tmp-dir", default=None, help=argparse.SUPPRESS)
    args = parser.parse_args()

    zip_path = os.path.realpath(args.zip_path)
    output_path = os.path.realpath(args.output_path)
    guarddog_bin = args.guarddog_bin or shutil.which("guarddog")

    if args._sandboxed:
        # We're inside the sandbox -- just do the work
        args.zip_path = zip_path
        args.output_path = output_path
        args.tmp_dir = os.path.realpath(args.tmp_dir) if args.tmp_dir else canonicalize_tmp()
        run_sandboxed_child(args)
    elif args.no_sandbox:
        run_unsandboxed(zip_path, args.ecosystem, args.category, args.package_name,
                        output_path, guarddog_bin)
    else:
        run_sandboxed(zip_path, args.ecosystem, args.category, args.package_name,
                      output_path, guarddog_bin, args.timeout)


if __name__ == "__main__":
    main()
