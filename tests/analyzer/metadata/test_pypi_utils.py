from guarddog.analyzer.metadata.pypi.utils import get_email_addresses


def test_get_email_addresses_returns_both_author_and_maintainer():
    package_info = {
        "info": {
            "author_email": "realdev@example.com",
            "maintainer_email": "maintainer@example.org",
        }
    }
    emails = get_email_addresses(package_info)
    assert emails == {"realdev@example.com", "maintainer@example.org"}


def test_get_email_addresses_drops_none_and_empty():
    package_info = {"info": {"author_email": "realdev@example.com", "maintainer_email": ""}}
    assert get_email_addresses(package_info) == {"realdev@example.com"}
