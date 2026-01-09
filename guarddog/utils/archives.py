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

    def _is_unsafe_symlink(
        zip_info: zipfile.ZipInfo, zip_file: zipfile.ZipFile
    ) -> bool:
        """
        Check if a zip entry is a symlink pointing outside the target directory.

        Follows the same logic as tarsafe: reads the symlink target and checks if
        the resolved path would be outside the extraction directory.

        @param zip_info: The ZipInfo object to check
        @param zip_file: The ZipFile object to read the symlink target
        @return: True if the symlink is unsafe, False otherwise
        """
        # Check if this is a symlink
        # external_attr stores Unix file mode in upper 16 bits
        attr = zip_info.external_attr >> 16
        # Mask with 0o170000 to get just the file type bits
        # 0o120000 = symbolic link
        if (attr & 0o170000) != 0o120000:
            return False

        linkname = zip_file.read(zip_info).decode("utf-8")

        symlink_file = pathlib.Path(
            os.path.normpath(os.path.join(target_directory, linkname))
        )
        if not os.path.abspath(os.path.join(target_directory, symlink_file)).startswith(
            target_directory
        ):
            return True

        return False

    def _is_device(zip_info: zipfile.ZipInfo) -> bool:
        """
        Check if a zip entry is a device file (character or block device).

        @param zip_info: The ZipInfo object to check
        @return: True if this is a device file, False otherwise
        """
        # external_attr stores Unix file mode in upper 16 bits
        # Mask with 0o170000 to get just the file type bits
        attr = zip_info.external_attr >> 16
        file_type = attr & 0o170000
        # Check for character device (0o020000) or block device (0o060000)
        return file_type == 0o020000 or file_type == 0o060000

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
                # Check for unsafe symlinks (zip don't supports hardlinks)
                if _is_unsafe_symlink(member, zip_file):
                    # we avoid unsafe files extraction but scan the rest of the package
                    log.warning(f"Archived file {member.filename} is an unsafe symlink. Skipping extraction")
                    continue

                # Check for device files
                if _is_device(member):
                    # we avoid unsafe files extraction but scan the rest of the package
                    log.warning(f"Archived file {member.filename} is a device file type. Skipping extraction")
                    continue

                # Extract file safely using zip.extract which handles path sanitization
                zip_file.extract(member, path=target_directory)
    else:
        raise ValueError(f"unsupported archive extension: {source_archive}")
