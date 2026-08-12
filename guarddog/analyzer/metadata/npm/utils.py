import os

PACKAGE_DIR_NAME = "package"


def get_package_directory(path: str) -> str:
    """Resolve the top-level content dir of an extracted npm tarball.

    npm conventionally packs into ``package/`` but some packages deviate
    (e.g. ``@types/node`` -> ``node/``). Only ``package/`` is documented
    (https://docs.npmjs.com/cli/install); the single-subdir fallback below
    is an inference, not a documented rule.

    Examples:
        >>> # conventional: <tmp>/package/package.json
        >>> get_package_directory("<tmp>")  # doctest: +SKIP
        '<tmp>/package'

        >>> # @types/node: <tmp>/node/package.json
        >>> get_package_directory("<tmp>")  # doctest: +SKIP
        '<tmp>/node'
    """
    conventional = os.path.join(path, PACKAGE_DIR_NAME)
    if os.path.isdir(conventional):
        return conventional

    try:
        # Top-level subdirs (skipping dotfiles); npm tarballs wrap content in
        # a single such dir, which may not be named ``package``.
        entries = [
            os.path.join(path, entry)
            for entry in os.listdir(path)
            if not entry.startswith(".")
            and os.path.isdir(os.path.join(path, entry))
        ]
    except (FileNotFoundError, NotADirectoryError):
        return conventional

    if len(entries) == 1:
        return entries[0]

    return conventional


NPM_API_MAINTAINER_EMAIL_WARNING = (
    "note that NPM's API may not provide accurate information regarding the maintainer's email, "
    "so this detector may cause false positives for NPM packages. "
    "see https://www.theregister.com/2022/05/10/security_npm_email/"
)


def get_email_addresses(package_info: dict) -> set[str]:
    return {m["email"] for m in package_info.get("maintainers", []) if "email" in m} - {
        None,
        "",
    }
