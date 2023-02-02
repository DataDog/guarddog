import os
import zipfile

import tarsafe  # type:ignore


def safe_extract(source_archive: str, target_directory: str) -> None:
    """
    safe_extract safely extracts archives to a target directory.

    This function does not clean up the original archive, and does not create the target directory if it does not exist.

    @param source_archive:      The archive to extract
    @param target_directory:    The directory where to extract the archive to
    @raise ValueError           If the archive type is unsupported
    """
    if source_archive.endswith('.tar.gz') or source_archive.endswith('.tgz'):
        tarsafe.open(source_archive).extractall(target_directory)
    elif source_archive.endswith('.zip') or source_archive.endswith('.whl'):
        with zipfile.ZipFile(source_archive, 'r') as zip:
            for file in zip.namelist():
                # Note: zip.extract cleans up any malicious file name such as directory traversal attempts
                # This is not the case of zipfile.extractall
                zip.extract(file, path=os.path.join(target_directory, file))
    else:
        raise ValueError("unsupported archive extension: " + target_directory)
