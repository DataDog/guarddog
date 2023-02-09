import os
import unittest.mock

import guarddog.cli


def test_is_local_target():
    assert guarddog.cli.is_local_target("/tmp/foo")
    assert guarddog.cli.is_local_target("./foo")
    assert not guarddog.cli.is_local_target("foo")

    os.path.exists = unittest.mock.MagicMock(return_value=True)
    assert guarddog.cli.is_local_target("foo.tar.gz")

    os.path.exists = unittest.mock.MagicMock(return_value=False)
    assert not guarddog.cli.is_local_target("foo.tar.gz")

