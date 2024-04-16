from guarddog.analyzer.metadata.unclaimed_maintainer_email_domain import UnclaimedMaintainerEmailDomainDetector

from .utils import get_email_addresses

class NPMUnclaimedMaintainerEmailDomainDetector(UnclaimedMaintainerEmailDomainDetector):
    def __init__(self):
        super().__init__("npm")

    def get_email_addresses(self, package_info: dict):
        return get_email_addresses(package_info)
