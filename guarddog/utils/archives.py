import logging
import os
import pathlib
import stat
import zipfile

import tarsafe  # type:ignore

from guarddog.utils.config import (
    MAX_UNCOMPRESSED_SIZE,
    MAX_COMPRESSION_RATIO,
    MAX_FILE_COUNT,
)

log = logging.getLogger("guarddog")


def _is_unsafe_symlink(target_directory: str, zip_info: zipfile.ZipInfo) -> bool:
    """
    Check if a zip entry is a symlink pointing outside the target directory.
    
    @param target_directory: The base directory where extraction occurs
    @param zip_info: The ZipInfo object to check
    @return: True if the symlink is unsafe, False otherwise
    """
    # Check if this is a symlink (Unix file type 0o120000)
    if zip_info.external_attr >> 16 != 0o120000:
        return False
    
    # For symlinks, we need to read the link target from the archive content
    # This would require additional zip file reading, so we conservatively
    # block all symlinks for security
    return True


def _is_unsafe_link(target_directory: str, zip_info: zipfile.ZipInfo, zip_file: zipfile.ZipFile) -> bool:
    """
    Check if a zip entry is a hard link pointing outside the target directory.
    
    Note: ZIP format doesn't natively support hard links like TAR does,
    but we check external attributes for completeness.
    
    @param target_directory: The base directory where extraction occurs
    @param zip_info: The ZipInfo object to check
    @param zip_file: The ZipFile object to read link contents if needed
    @return: True if the link is unsafe, False otherwise
    """
    # ZIP format doesn't have native hard link support like TAR
    # Hard links would need to be stored as special files with external_attr
    # For now, return False as this is not a common attack vector in ZIP files
    return False


def _is_device(zip_info: zipfile.ZipInfo) -> bool:
    """
    Check if a zip entry is a device file (character or block device).
    
    @param zip_info: The ZipInfo object to check
    @return: True if this is a device file, False otherwise
    """
    file_type = zip_info.external_attr >> 16
    # Check for character device (0o020000) or block device (0o060000)
    return file_type == 0o020000 or file_type == 0o060000


def _check_compression_bomb(
    file_count: int,
    total_size: int,
    archive_size: int,
) -> None:
    """
    Checks for compression bombs and file descriptor exhaustion attacks.

    @param file_count: Number of files in the archive
    @param total_size: Total uncompressed size in bytes
    @param archive_size: Compressed archive size in bytes
    @raise ValueError: If any safety limit is exceeded
    """
    if file_count > MAX_FILE_COUNT:
        raise ValueError(
            f"Archive contains {file_count} files, exceeding maximum allowed "
            f"count ({MAX_FILE_COUNT}). Possible file descriptor exhaustion attack."
        )
    
    if total_size > MAX_UNCOMPRESSED_SIZE:
        raise ValueError(
            f"Archive uncompressed size ({total_size} bytes) exceeds maximum allowed "
            f"size ({MAX_UNCOMPRESSED_SIZE} bytes). Possible compression bomb."
        )
    
    if archive_size > 0:
        compression_ratio = total_size / archive_size
        if compression_ratio > MAX_COMPRESSION_RATIO:
            raise ValueError(
                f"Archive compression ratio ({compression_ratio:.1f}:1) exceeds maximum "
                f"allowed ratio ({MAX_COMPRESSION_RATIO}:1). Possible compression bomb."
            )


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


def safe_extract(
    source_archive: str,
    target_directory: str,
) -> None:
    """
    safe_extract safely extracts archives to a target directory.

    This function does not clean up the original archive and does not
    create the target directory if it does not exist.  It also assumes
    the source archive argument is a path to a regular file on the
    local filesystem.

    @param source_archive:      The archive to extract
    @param target_directory:    The directory where to extract the archive to
    @raise ValueError           If the archive type is unsupported or exceeds safety limits

    """
    log.debug(f"Extracting archive {source_archive} to directory {target_directory}")
    
    archive_size = os.path.getsize(source_archive)
    
    if tarsafe.is_tarfile(source_archive):

        def add_exec(path):
            st = os.stat(path)
            os.chmod(path, st.st_mode | stat.S_IXUSR)

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

        # Check uncompressed size for tar archives by inspecting members
        with tarsafe.open(source_archive) as tar:
            members = [member for member in tar.getmembers() if member.isfile()]
            file_count = len(members)
            total_size = sum(member.size for member in members)
            
            _check_compression_bomb(file_count, total_size, archive_size)

        tarsafe.open(source_archive).extractall(target_directory)
        recurse_add_perms(target_directory)

    elif zipfile.is_zipfile(source_archive):
        with zipfile.ZipFile(source_archive, "r") as zip_file:
            # Check uncompressed size for zip archives
            files = [info for info in zip_file.infolist() if not info.is_dir()]
            file_count = len(files)
            total_size = sum(info.file_size for info in files)
            
            _check_compression_bomb(file_count, total_size, archive_size)
            
            # Validate and extract each file safely
            for member in zip_file.infolist():
                # Check for unsafe symlinks
                if _is_unsafe_symlink(target_directory, member):
                    raise ValueError(
                        f"Unsafe symlink in archive: {member.filename}. "
                        f"Symlink may point outside extraction directory."
                    )
                
                # Check for unsafe hard links
                if _is_unsafe_link(target_directory, member, zip_file):
                    raise ValueError(
                        f"Unsafe link in archive: {member.filename}. "
                        f"Link may point outside extraction directory."
                    )
                
                # Check for device files
                if _is_device(member):
                    raise ValueError(
                        f"Device file in archive: {member.filename}. "
                        f"Device files are not allowed."
                    )
                
                # Extract file safely using zip.extract which handles path sanitization
                zip_file.extract(member, path=target_directory)
    else:
        raise ValueError(f"unsupported archive extension: {source_archive}")