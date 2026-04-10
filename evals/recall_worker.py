#!/usr/bin/env python3
"""
Sandboxed worker for scanning a single malicious package ZIP.

Runs inside a Nono sandbox with no network access and restricted filesystem.
Called by recall.py orchestrator as a subprocess.

Usage (called by recall.py, not directly):
    python recall_worker.py --zip-path /path/to.zip --ecosystem pypi --output-path /path/to/result.json
"""

import argparse
import json
import os
import platform
import shutil
import sys
import tempfile
import zipfile


MAX_EXTRACTED_FILES = 5000
MAX_EXTRACTED_BYTES = 500 * 1024 * 1024  # 500MB


def canonicalize_tmp():
    """On macOS, /tmp is a symlink to /private/tmp. Nono needs the real path."""
    tmp = tempfile.gettempdir()
    return os.path.realpath(tmp)


def setup_sandbox(tmp_dir: str, zip_path: str, output_path: str):
    try:
        import nono_py as nono
    except ImportError:
        print("ERROR: nono-py not installed. Refusing to scan malicious packages without sandbox.", file=sys.stderr)
        sys.exit(1)

    if not nono.is_supported():
        print("ERROR: Nono sandbox not supported on this platform. Refusing to run.", file=sys.stderr)
        sys.exit(1)

    caps = nono.CapabilitySet()
    caps.allow_path(tmp_dir, nono.AccessMode.READ_WRITE)
    caps.allow_path(zip_path, nono.AccessMode.READ)
    caps.allow_path(output_path, nono.AccessMode.READ_WRITE)

    # Allow Python runtime + site-packages (guarddog, semgrep, yara, etc.)
    python_prefix = os.path.realpath(sys.prefix)
    caps.allow_path(python_prefix, nono.AccessMode.READ)

    # Also allow the real base prefix (for system Python libs)
    base_prefix = os.path.realpath(sys.base_prefix)
    if base_prefix != python_prefix:
        caps.allow_path(base_prefix, nono.AccessMode.READ)

    caps.block_network()

    # Dry-run validation
    ctx = nono.QueryContext(caps)
    checks = [
        (tmp_dir, nono.AccessMode.READ_WRITE, "tmp_dir"),
        (zip_path, nono.AccessMode.READ, "zip_path"),
        (output_path, nono.AccessMode.READ_WRITE, "output_path"),
    ]
    for path, mode, label in checks:
        result = ctx.query_path(path, mode)
        status = result.get("status") if isinstance(result, dict) else getattr(result, "status", None)
        if status == "denied":
            print(f"ERROR: sandbox validation failed for {label} ({path})", file=sys.stderr)
            sys.exit(1)

    nono.apply(caps)


def extract_zip(zip_path: str, dest: str):
    """Extract ZIP with safety limits."""
    total_bytes = 0
    total_files = 0

    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            if total_files >= MAX_EXTRACTED_FILES:
                raise RuntimeError(f"Too many files in archive (>{MAX_EXTRACTED_FILES})")

            # Skip symlinks and directories
            if info.is_dir():
                continue
            if info.external_attr >> 16 & 0o120000 == 0o120000:
                continue

            # Path traversal check
            target = os.path.realpath(os.path.join(dest, info.filename))
            if not target.startswith(os.path.realpath(dest)):
                continue

            total_bytes += info.file_size
            if total_bytes > MAX_EXTRACTED_BYTES:
                raise RuntimeError(f"Archive too large (>{MAX_EXTRACTED_BYTES} bytes)")

            total_files += 1
            zf.extract(info, dest, pwd=b"infected")


def scan_package(extracted_dir: str, ecosystem: str) -> dict:
    """Run guarddog scan on the extracted directory via CLI."""
    import subprocess as sp

    guarddog_bin = shutil.which("guarddog")
    if not guarddog_bin:
        return {"results": {}, "error": "guarddog not found on PATH"}

    try:
        proc = sp.run(
            [guarddog_bin, ecosystem, "scan", extracted_dir, "--output-format", "json"],
            capture_output=True, text=True, timeout=90,
        )
        stdout = proc.stdout.strip()
        if stdout:
            return {"results": json.loads(stdout), "error": None}
        return {"results": {}, "error": f"Exit {proc.returncode}: {proc.stderr[:500]}"}
    except sp.TimeoutExpired:
        return {"results": {}, "error": "guarddog scan timeout"}
    except Exception as e:
        return {"results": {}, "error": str(e)[:500]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--zip-path", required=True)
    parser.add_argument("--ecosystem", required=True, choices=["pypi", "npm"])
    parser.add_argument("--output-path", required=True)
    parser.add_argument("--no-sandbox", action="store_true", help="Skip sandbox (DANGEROUS, for testing only)")
    args = parser.parse_args()

    zip_path = os.path.realpath(args.zip_path)
    output_path = os.path.realpath(args.output_path)

    tmp_base = canonicalize_tmp()
    tmp_dir = tempfile.mkdtemp(dir=tmp_base, prefix="guarddog_recall_")

    try:
        if not args.no_sandbox:
            setup_sandbox(tmp_dir, zip_path, output_path)

        extract_zip(zip_path, tmp_dir)
        scan_result = scan_package(tmp_dir, args.ecosystem)

        with open(output_path, "w") as f:
            json.dump(scan_result, f, indent=2)

    except Exception as e:
        error_result = {"results": {}, "error": str(e)[:500]}
        try:
            with open(output_path, "w") as f:
                json.dump(error_result, f, indent=2)
        except Exception:
            pass
        sys.exit(1)

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
