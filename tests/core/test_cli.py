import os
import unittest.mock
from guarddog.ecosystems import ECOSYSTEM

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


def test_get_rule_param_include():
    assert len(guarddog.cli._get_rule_param(("shady-links",), (), ECOSYSTEM.NPM)) == 1

def test_get_rule_param_exclude():
    rules = guarddog.cli._get_rule_param((), ("shady-links",), ECOSYSTEM.PYPI)
    assert len(rules) != 1
    assert "shady-links" not in rules




