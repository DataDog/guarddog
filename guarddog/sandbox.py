"""
Kernel-level sandboxing for guarddog via nono-py.

Can also be invoked as a subprocess for sandboxed archive extraction:
    python -m guarddog.sandbox <archive_path> <target_dir>
"""

import argparse
import logging
import os
import subprocess
import sys
import tempfile

log = logging.getLogger("guarddog")


def is_available() -> bool:
    """Check if nono-py is importable and the platform supports sandboxing."""
    try:
        import nono_py as nono

        return nono.is_supported()
    except ImportError:
        return False


def apply_sandbox(
    scan_paths: list[str],
    writable_paths: list[str],
) -> None:
    """Apply kernel-level sandbox. Always blocks network. Raises on failure.

    Args:
        scan_paths: paths that need READ access (package dirs, archive files)
        writable_paths: paths that need READ_WRITE access (temp extraction dirs)
    """
    import nono_py as nono

    caps = nono.CapabilitySet()

    for path in _get_common_read_paths():
        caps.allow_path(path, nono.AccessMode.READ)

    for path in scan_paths:
        real = os.path.realpath(path)
        if os.path.isfile(real):
            real = os.path.dirname(real)
        log.info(f"Sandbox: READ {real}")
        caps.allow_path(real, nono.AccessMode.READ)

    for path in writable_paths:
        real = os.path.realpath(path)
        os.makedirs(real, exist_ok=True)
        log.info(f"Sandbox: READ_WRITE {real}")
        caps.allow_path(real, nono.AccessMode.READ_WRITE)

    # Semgrep and other tools may write temp files outside the extraction dir
    tmp = os.path.realpath(tempfile.gettempdir())
    caps.allow_path(tmp, nono.AccessMode.READ_WRITE)

    caps.block_network()
    log.info("Sandbox: network blocked")
    log.debug("Sandbox capabilities: READ %s | READ_WRITE %s | network=blocked",
              [os.path.realpath(p) for p in scan_paths] + _get_common_read_paths(),
              [os.path.realpath(p) for p in writable_paths] + [tmp])

    nono.apply(caps)
    log.info("Sandbox: applied")


def extract_sandboxed(archive_path: str, target_dir: str) -> None:
    """Extract an archive in a sandboxed subprocess.

    Spawns a child process that applies a nono sandbox (blocking network,
    restricting filesystem to archive + target dir) before calling safe_extract.
    This closes the TOCTOU gap for remote scans where the main process needs
    network access after extraction.
    """
    archive_path = os.path.realpath(archive_path)
    target_dir = os.path.realpath(target_dir)

    log.debug("Extracting %s -> %s in sandboxed subprocess", archive_path, target_dir)
    result = subprocess.run(
        [sys.executable, "-m", "guarddog.sandbox", archive_path, target_dir],
        capture_output=True,
        text=True,
        cwd=os.path.dirname(archive_path),
    )
    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise RuntimeError(f"Sandboxed extraction failed: {stderr}")


def _get_common_read_paths() -> list[str]:
    """Paths that always need READ access for Python + system libs."""
    paths = set()

    paths.add(os.path.realpath(sys.prefix))

    base = os.path.realpath(sys.base_prefix)
    if base != os.path.realpath(sys.prefix):
        paths.add(base)

    for system_dir in ["/usr", "/lib"]:
        real = os.path.realpath(system_dir)
        if os.path.isdir(real):
            paths.add(real)

    return list(paths)


def _main():
    """Subprocess entry point: apply sandbox then extract archive."""
    parser = argparse.ArgumentParser()
    parser.add_argument("archive_path")
    parser.add_argument("target_dir")
    args = parser.parse_args()

    archive_path = os.path.realpath(args.archive_path)
    target_dir = os.path.realpath(args.target_dir)

    apply_sandbox(
        scan_paths=[],
        writable_paths=[target_dir],
    )

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
