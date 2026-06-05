import os
from copy import deepcopy
from unittest.mock import MagicMock

from guarddog.analyzer.metadata.pypi import PypiIntegrityMismatchDetector
from tests.analyzer.metadata.resources.sample_project_info import PYPI_PACKAGE_INFO


def test_no_github_links():
    current_info = deepcopy(PYPI_PACKAGE_INFO)
    current_info["info"]["home_page"] = ""
    current_info["info"]["project_urls"]["Homepage"] = ""
    detector = PypiIntegrityMismatchDetector()
    match, message = detector.detect(current_info, name="", path="")
    assert not match
    assert message == "Could not find a GitHub URL in the package metadata"


def test_no_good_homepage_link():
    current_info = deepcopy(PYPI_PACKAGE_INFO)
    current_info["info"]["home_page"] = ""
    current_info["info"]["project_urls"] = {
        "Download": "UNKNOWN",
        "Homepage": "https://github.com/pypa/samplproject",
        },
    current_info["info"]["summary"] = "https://github.com/pypa/sampleproject"
    detector = PypiIntegrityMismatchDetector()
    match, message = detector.detect(current_info, name="mypackage", path="")
    assert not match
    assert message == "Could not find a GitHub URL in the package metadata"

def test_no_good_github_links():
    current_info = deepcopy(PYPI_PACKAGE_INFO)
    current_info["info"]["home_page"] = ""
    current_info["info"]["project_urls"]["Homepage"] = ""
    current_info["info"]["summary"] = "https://github.com/pypa/sampleproject"
    detector = PypiIntegrityMismatchDetector()
    match, message = detector.detect(current_info, name="mypackage", path="")
    assert not match
    assert message == "Could not find a GitHub URL in the package metadata"


def test_empty_homepage_urls():
    """
    Regression test for https://github.com/DataDog/guarddog/issues/190
    """
    current_info = deepcopy(PYPI_PACKAGE_INFO)
    current_info["info"]["project_urls"] = None
    detector = PypiIntegrityMismatchDetector()
    match, _ = detector.detect(current_info, name="mypackage", path="")
    assert not match


def test_file_where_directory_expected_does_not_crash(tmp_path):
    """
    Regression test for https://github.com/DataDog/guarddog/issues/531

    A path name can be a directory in the package but a regular file in the
    repository (for example a "LICENSE" file vs a "LICENSE" directory). When
    os.walk descends into the package directory, the matching repository path
    exists but is a file, so listing it used to raise
    NotADirectoryError: [Errno 20] Not a directory. The walk must skip such
    paths instead of crashing.
    """
    base_path = tmp_path / "pkg"
    repo_path = tmp_path / "repo"

    # Package side: a directory named LICENSE containing a file.
    (base_path / "LICENSE").mkdir(parents=True)
    (base_path / "LICENSE" / "inner.py").write_text("x = 1\n")

    # Repository side: a regular file named LICENSE at the same relative path.
    repo_path.mkdir()
    (repo_path / "LICENSE").write_text("license text\n")

    detector = PypiIntegrityMismatchDetector()
    # repo.checkout is the only pygit2 call in find_mismatch_for_tag; stub it
    # out so the filesystem walk can be exercised without a real clone.
    repo = MagicMock()

    mismatch = detector.find_mismatch_for_tag(
        repo, "v1.0.0", str(base_path), str(repo_path)
    )

    # No crash, and nothing to compare for that subtree (repo side is a file).
    assert mismatch == []


def test_genuine_mismatch_still_detected(tmp_path):
    """
    The fix for issue #531 must not suppress real integrity mismatches: a file
    present on both sides with differing content is still flagged.
    """
    base_path = tmp_path / "pkg"
    repo_path = tmp_path / "repo"
    base_path.mkdir()
    repo_path.mkdir()

    (base_path / "code.py").write_text("MALICIOUS\n")
    (repo_path / "code.py").write_text("benign\n")

    detector = PypiIntegrityMismatchDetector()
    repo = MagicMock()

    mismatch = detector.find_mismatch_for_tag(
        repo, "v1.0.0", str(base_path), str(repo_path)
    )

    assert [os.path.basename(entry["file"]) for entry in mismatch] == ["code.py"]