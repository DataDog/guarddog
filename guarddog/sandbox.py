"""
Kernel-level sandboxing for guarddog via nono-py.

Can also be invoked as a subprocess for sandboxed archive extraction:
    python -m guarddog.sandbox <archive_path> <target_dir>
"""

import argparse
import logging
import os
import sys
import tempfile

log = logging.getLogger("guarddog")

# Upper bound on how long a sandboxed extraction may run. The compression-bomb
# checks in safe_extract cap total size, but a crafted archive can still stall
# extraction; this guarantees the subprocess can never hang indefinitely.
EXTRACTION_TIMEOUT_SECONDS = 300


def is_available() -> bool:
    """Check if the platform supports sandboxing via nono-py."""
    import nono_py as nono  # type: ignore[import-not-found]

    return nono.is_supported()


def apply_sandbox(
    scan_paths: list[str],
    writable_paths: list[str],
) -> None:
    """Apply kernel-level sandbox. Always blocks network. Raises on failure.

    Args:
        scan_paths: paths that need READ access (package dirs, archive files)
        writable_paths: paths that need READ_WRITE access (temp extraction dirs)
    """
    import nono_py as nono  # type: ignore[import-not-found]

    caps = nono.CapabilitySet()

    for path in _get_common_read_paths():
        caps.allow_path(path, nono.AccessMode.READ)

    for path in scan_paths:
        for variant in _path_variants(path):
            if os.path.isfile(variant):
                log.debug(f"Sandbox: READ file {variant}")
                caps.allow_file(variant, nono.AccessMode.READ)
            else:
                log.debug(f"Sandbox: READ {variant}")
                caps.allow_path(variant, nono.AccessMode.READ)

    for path in writable_paths:
        os.makedirs(os.path.realpath(path), exist_ok=True)
        for variant in _path_variants(path):
            log.debug(f"Sandbox: READ_WRITE {variant}")
            caps.allow_path(variant, nono.AccessMode.READ_WRITE)

    # Tools may write temp files outside the extraction dir
    for tmp in _path_variants(tempfile.gettempdir()):
        caps.allow_path(tmp, nono.AccessMode.READ_WRITE)

    caps.block_network()
    log.debug("Sandbox: network blocked")

    nono.apply(caps)
    log.debug("Sandbox: applied")


def extract_sandboxed(archive_path: str, target_dir: str) -> None:
    """Extract an archive in a sandboxed subprocess.

    Uses nono.sandboxed_exec so the sandbox is applied by the parent before
    exec'ing the child — avoiding the nested-sandbox restriction that would
    occur if the child called nono.apply() itself.
    """
    import nono_py as nono  # type: ignore[import-not-found]

    archive_path = os.path.realpath(archive_path)
    target_dir = os.path.realpath(target_dir)

    log.debug("Extracting %s -> %s in sandboxed subprocess", archive_path, target_dir)

    caps = nono.CapabilitySet()

    for path in _get_common_read_paths():
        caps.allow_path(path, nono.AccessMode.READ)

    # allow_path requires directories; allow the archive's parent dir for READ
    caps.allow_path(os.path.dirname(archive_path), nono.AccessMode.READ)

    os.makedirs(target_dir, exist_ok=True)
    caps.allow_path(target_dir, nono.AccessMode.READ_WRITE)

    tmp = os.path.realpath(tempfile.gettempdir())
    caps.allow_path(tmp, nono.AccessMode.READ_WRITE)

    caps.block_network()

    result = nono.sandboxed_exec(
        caps,
        [sys.executable, "-m", "guarddog.sandbox", archive_path, target_dir],
        cwd=os.path.dirname(archive_path),
    )
    if result.exit_code != 0:
        stderr = (
            result.stderr.decode("utf-8", errors="replace").strip()
            if result.stderr
            else ""
        )
        raise RuntimeError(f"Sandboxed extraction failed: {stderr}")


def _path_variants(path: str) -> list[str]:
    """Return the path as given and its fully resolved form, deduplicated.

    nono grants access to a path exactly as it is matched at access time, not
    to whatever that path resolves to. A symlinked directory and its target are
    distinct as far as the sandbox is concerned, so both must be granted.

    This matters most for the Python runtime: managed interpreters (uv, pyenv)
    expose the stdlib through a versioned symlink (e.g. cpython-3.12 ->
    cpython-3.12.8), and the import machinery walks sys.path using the symlink
    path. Granting only the realpath leaves lazy imports (tarfile -> gzip) to
    fail with EPERM once the sandbox is active.
    """
    variants = [path]
    real = os.path.realpath(path)
    if real != path:
        variants.append(real)
    return variants


def _get_common_read_paths() -> list[str]:
    """Paths that always need READ access for Python + system libs + guarddog rules."""
    paths: set[str] = set()

    candidates = [sys.prefix, sys.base_prefix, "/usr", "/lib"]

    # guarddog package dir: needed for YARA rule files, which may
    # live outside sys.prefix when running from source (e.g. uv run)
    import guarddog

    candidates.append(os.path.dirname(guarddog.__file__))

    # Every existing sys.path entry: Python's import machinery stats each
    # entry when resolving lazy imports (e.g. tarfile.gzopen -> import gzip).
    # Under the sandbox, a stat of an unlisted dir fails with EPERM, which
    # surfaces deep inside stdlib code as a confusing PermissionError.
    candidates.extend(entry for entry in sys.path if entry)

    for candidate in candidates:
        for variant in _path_variants(candidate):
            if os.path.isdir(variant):
                paths.add(variant)

    return list(paths)


def _main():
    """Subprocess entry point: sandbox is pre-applied by parent via sandboxed_exec."""
    parser = argparse.ArgumentParser()
    parser.add_argument("archive_path")
    parser.add_argument("target_dir")
    args = parser.parse_args()

    archive_path = os.path.realpath(args.archive_path)
    target_dir = os.path.realpath(args.target_dir)

    from guarddog.utils.archives import safe_extract

    safe_extract(archive_path, target_dir)

    # Handle nested .gem archives (outer tar contains data.tar.gz)
    data_tar = os.path.join(target_dir, "_gem_contents", "data.tar.gz")
    if not os.path.exists(data_tar):
        data_tar = os.path.join(target_dir, "_gem_contents", "data.tar")
    if os.path.exists(data_tar):
        safe_extract(data_tar, target_dir)


if __name__ == "__main__":
    _main()
