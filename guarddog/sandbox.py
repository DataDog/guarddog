import logging
import os
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

    # Common read paths: Python runtime + system binaries
    for path in _get_common_read_paths():
        caps.allow_path(path, nono.AccessMode.READ)

    # Caller-specified read paths
    for path in scan_paths:
        real = os.path.realpath(path)
        log.info(f"Sandbox: READ {real}")
        caps.allow_path(real, nono.AccessMode.READ)

    # Caller-specified writable paths
    for path in writable_paths:
        real = os.path.realpath(path)
        log.info(f"Sandbox: READ_WRITE {real}")
        caps.allow_path(real, nono.AccessMode.READ_WRITE)

    # Semgrep and other tools may write temp files outside the extraction dir
    tmp = os.path.realpath(tempfile.gettempdir())
    caps.allow_path(tmp, nono.AccessMode.READ_WRITE)

    caps.block_network()
    log.info("Sandbox: network blocked")

    # Dry-run validation before locking down
    ctx = nono.QueryContext(caps)
    for path in writable_paths:
        real = os.path.realpath(path)
        result = ctx.query_path(real, nono.AccessMode.READ_WRITE)
        status = result.get("status") if isinstance(result, dict) else getattr(result, "status", None)
        if status == "denied":
            raise RuntimeError(f"Sandbox validation failed: READ_WRITE denied for {real}")

    nono.apply(caps)
    log.info("Sandbox: applied")


def _get_common_read_paths() -> list[str]:
    """Paths that always need READ access for Python + system libs."""
    paths = set()

    paths.add(os.path.realpath(sys.prefix))

    base = os.path.realpath(sys.base_prefix)
    if base != os.path.realpath(sys.prefix):
        paths.add(base)

    # System binaries needed by subprocess spawning (semgrep, etc.)
    for system_dir in ["/usr", "/lib"]:
        real = os.path.realpath(system_dir)
        if os.path.isdir(real):
            paths.add(real)

    return list(paths)
