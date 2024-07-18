import logging
import os
import zipfile

import tarsafe  # type:ignore

log = logging.getLogger("guarddog")


def is_supported_archive(path: str) -> bool:
    """
    Decide whether a file contains a supported archive.

    Args:
        path (str): The local filesystem path to examine

    Returns:
        bool: Represents the decision reached for the file
    """
    return is_tar_archive(path) or is_zip_archive(path)


def is_tar_archive(path: str) -> bool:
    """
    Decide whether a file contains a tar archive.

    Args:
        path (str): The local filesystem path to examine

    Returns:
        bool: Represents the decision reached for the file
    """
    return any(path.endswith(ext) for ext in [".tar.gz", ".tgz"])


def is_zip_archive(path: str) -> bool:
    """
    Decide whether a file contains a zip, whl or egg archive.

    Args:
        path (str): The local filesystem path to examine

    Returns:
        bool: Represents the decision reached for the file
    """
    return any(path.endswith(ext) for ext in [".zip", ".whl", ".egg"])


def safe_extract(source_archive: str, target_directory: str) -> None:
    """
    safe_extract safely extracts archives to a target directory.

    This function does not clean up the original archive and does not
    create the target directory if it does not exist.  It also assumes
    the source archive argument is a path to a regular file on the
    local filesystem.

    @param source_archive:      The archive to extract
    @param target_directory:    The directory where to extract the archive to
    @raise ValueError           If the archive type is unsupported

    """
    log.debug(f"Extracting archive {source_archive} to directory {target_directory}")
    if is_tar_archive(source_archive):
        tarsafe.open(source_archive).extractall(target_directory)
    elif is_zip_archive(source_archive):
        with zipfile.ZipFile(source_archive, 'r') as zip:
            for file in zip.namelist():
                # Note: zip.extract cleans up any malicious file name
                # such as directory traversal attempts This is not the
                # case of zipfile.extractall
                zip.extract(file, path=os.path.join(target_directory, file))
    else:
        raise ValueError(f"unsupported archive extension: {source_archive}")
