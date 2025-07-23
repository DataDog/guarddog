import logging
import os
import stat
import zipfile

import tarsafe  # type:ignore

log = logging.getLogger("guarddog")


def is_supported_archive(path: str) -> bool:
    """
    Decide whether a file contains a supported archive based on its
    file extension.

    Args:
        path (str): The local filesystem path to examine

    Returns:
        bool: Represents the decision reached for the file

    """
    def is_tar_archive(path: str) -> bool:
        tar_exts = [".bz2", ".bzip2", ".gz", ".gzip", ".tgz", ".xz"]

        return any(path.endswith(ext) for ext in tar_exts)

    def is_zip_archive(path: str) -> bool:
        return any(path.endswith(ext) for ext in [".zip", ".whl", ".egg"])

    return is_tar_archive(path) or is_zip_archive(path)


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
    if tarsafe.is_tarfile(source_archive):

        def add_exec(path):
            st = os.stat(path)
            os.chmod(path, st.st_mode | stat.S_IEXEC)

        def add_read(path):
            st = os.stat(path)
            os.chmod(path, st.st_mode | stat.S_IREAD)

        def recurse_add_perms(path):
            add_exec(path)
            for root, dirs, files in os.walk(path):
                for d in dirs:
                    add_exec(os.path.join(root, d))
                for f in files:
                    add_read(os.path.join(root, f))

        tarsafe.open(source_archive).extractall(target_directory)
        recurse_add_perms(target_directory)

    elif zipfile.is_zipfile(source_archive):
        with zipfile.ZipFile(source_archive, 'r') as zip:
            for file in zip.namelist():
                # Note: zip.extract cleans up any malicious file name
                # such as directory traversal attempts This is not the
                # case of zipfile.extractall
                zip.extract(file, path=os.path.join(target_directory, file))
    else:
        raise ValueError(f"unsupported archive extension: {source_archive}")
