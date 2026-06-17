"""Helpers for fetching packages from S3 so they can be scanned locally.

boto3 is imported lazily inside each function so that a normal (non-S3) scan never
pays the cost of importing it. boto3 has no built-in directory sync (`aws s3 sync`
lives in awscli), so folder syncs iterate objects under the prefix and download each
one; the per-object transfers still use boto3's managed multipart + retries.
"""

import logging
import os
from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple
from urllib.parse import urlparse

from guarddog.utils.archives import is_supported_archive

log = logging.getLogger("guarddog")

# S3 syncs of real packages are dominated by per-object request latency, so objects
# are downloaded concurrently. This work is I/O-bound, not CPU-bound, so the worker
# count is a fixed fan-out rather than a function of core count. The botocore HTTP
# connection pool must be sized to match, otherwise excess workers stall waiting for
# a free connection (botocore defaults the pool to 10).
MAX_DOWNLOAD_WORKERS = 16


def is_s3_url(identifier: str) -> bool:
    """Return True when the scan target is an S3 URL (s3://bucket/key)."""
    return identifier.startswith("s3://")


def parse_s3_uri(uri: str) -> Tuple[str, str]:
    """Split an s3://bucket/key URI into (bucket, key)."""
    parsed = urlparse(uri)
    bucket = parsed.netloc
    key = parsed.path.lstrip("/")
    if not bucket:
        raise ValueError(f"Invalid S3 URI (missing bucket): {uri}")
    return bucket, key


def verify_aws_authentication() -> None:
    """Confirm the caller is authenticated to AWS, raising RuntimeError otherwise.

    Uses STS GetCallerIdentity, which requires no specific permissions beyond a valid
    set of credentials. The CLI turns the RuntimeError into a clean error + exit.
    """
    import boto3  # type: ignore
    from botocore.exceptions import (  # type: ignore
        BotoCoreError,
        ClientError,
        NoCredentialsError,
    )

    try:
        boto3.client("sts").get_caller_identity()
    except NoCredentialsError as e:
        raise RuntimeError(
            "no AWS credentials found. Configure credentials (env vars, ~/.aws, "
            f"SSO, or an IAM role) before scanning an S3 path. ({e})"
        )
    except (ClientError, BotoCoreError) as e:
        raise RuntimeError(f"could not verify AWS identity via STS: {e}")


def _safe_join(dest_dir: str, relative_path: str) -> str:
    """Join dest_dir and an S3-derived relative path, refusing to escape dest_dir.

    S3 keys can contain '..' segments; without this guard a crafted key could write
    outside the temp directory.
    """
    dest_dir = os.path.realpath(dest_dir)
    target = os.path.realpath(os.path.join(dest_dir, relative_path))
    if target != dest_dir and not target.startswith(dest_dir + os.sep):
        raise ValueError(f"S3 key escapes destination directory: {relative_path}")
    return target


def download_from_s3(s3_uri: str, dest_dir: str) -> Tuple[str, str]:
    """Download an S3 object or prefix into dest_dir.

    Returns (kind, local_path):
      - ("archive", <file path>) when the URI points at a single supported archive
      - ("folder", dest_dir) when the URI is a prefix (or a single non-archive object)
    """
    import boto3  # type: ignore
    from botocore.config import Config  # type: ignore
    from botocore.exceptions import ClientError  # type: ignore

    bucket, key = parse_s3_uri(s3_uri)
    # Size the connection pool to the download fan-out so workers don't stall on it.
    client = boto3.client(
        "s3", config=Config(max_pool_connections=MAX_DOWNLOAD_WORKERS)
    )

    if key and not key.endswith("/"):
        try:
            client.head_object(Bucket=bucket, Key=key)
            local_path = _safe_join(dest_dir, os.path.basename(key))
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            log.debug(f"Downloading s3://{bucket}/{key} -> {local_path}")
            client.download_file(bucket, key, local_path)
            if is_supported_archive(local_path):
                return "archive", local_path
            return "folder", dest_dir
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code")
            if error_code not in ("404", "NoSuchKey", "NotFound"):
                raise
            # Not a single object: fall through and treat the key as a prefix.

    _download_prefix(client, bucket, key, dest_dir)
    return "folder", dest_dir


def _download_prefix(client, bucket: str, prefix: str, dest_dir: str) -> None:
    """Download every object under prefix into dest_dir, preserving relative paths.

    Objects are downloaded concurrently via a thread pool; the boto3 low-level client
    is thread-safe and shared across workers.
    """
    paginator = client.get_paginator("list_objects_v2")
    jobs: List[Tuple[str, str]] = []  # (object_key, local_path)
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            object_key = obj["Key"]
            if object_key.endswith("/"):
                continue
            relative_path = (
                os.path.relpath(object_key, prefix) if prefix else object_key
            )
            jobs.append((object_key, _safe_join(dest_dir, relative_path)))

    if not jobs:
        raise RuntimeError(f"no objects found at s3://{bucket}/{prefix}")

    # Create parent directories up front so parallel downloads don't race on mkdir.
    for _, local_path in jobs:
        os.makedirs(os.path.dirname(local_path), exist_ok=True)

    def _download(job: Tuple[str, str]) -> None:
        object_key, local_path = job
        log.debug(f"Downloading s3://{bucket}/{object_key} -> {local_path}")
        client.download_file(bucket, object_key, local_path)

    worker_count = min(MAX_DOWNLOAD_WORKERS, len(jobs))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        # Consume the iterator so the first download error propagates.
        for _ in executor.map(_download, jobs):
            pass
