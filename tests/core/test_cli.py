import os
import unittest.mock

import guarddog.cli


def test_is_local_target():
    assert guarddog.cli.is_local_target("/tmp/foo")
    assert guarddog.cli.is_local_target("./foo")
    assert guarddog.cli.is_local_target("../foo")
    assert guarddog.cli.is_local_target(".")
    assert not guarddog.cli.is_local_target("foo")

    with unittest.mock.patch('os.path.exists') as mock:
        mock.return_value = True
        assert guarddog.cli.is_local_target("foo.tar.gz")

    with unittest.mock.patch('os.path.exists') as mock:
        mock.return_value = False
        assert not guarddog.cli.is_local_target("foo.tar.gz")

