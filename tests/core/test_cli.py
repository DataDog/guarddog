import unittest.mock

import guarddog.cli
from guarddog.ecosystems import ECOSYSTEM


def test_is_local_target():
    assert guarddog.cli.is_local_target("/tmp/foo")
    assert guarddog.cli.is_local_target("./foo")
    assert guarddog.cli.is_local_target("../foo")
    assert guarddog.cli.is_local_target(".")
    assert not guarddog.cli.is_local_target("foo")

    with unittest.mock.patch("os.path.exists") as mock:
        mock.return_value = True
        assert guarddog.cli.is_local_target("foo.tar.gz")

    with unittest.mock.patch("os.path.exists") as mock:
        mock.return_value = False
        assert not guarddog.cli.is_local_target("foo.tar.gz")


def test_get_rule_param_include():
    """
    Test the parsing function returns the included parameter
    """
    rules = guarddog.cli._get_rule_param(("shady-links",), (), ECOSYSTEM.NPM)
    assert rules
    assert len(rules) == 1

def test_get_rule_param_exclude():
    """
    Test the parsing function returns returns a list without the excluded parameter
    """
    rules = guarddog.cli._get_rule_param((), ("shady-links",), ECOSYSTEM.PYPI)
    assert rules
    assert len(rules) != 1
    assert "shady-links" not in rules

def test_get_rule_param_empty():
    """
    Test the parsing function returns returns a list without the excluded parameter
    """
    rules = guarddog.cli._get_rule_param((), (), ECOSYSTEM.PYPI)
    assert rules is None
