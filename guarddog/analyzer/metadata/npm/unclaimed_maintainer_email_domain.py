from typing import Optional
from guarddog.analyzer.metadata.unclaimed_maintainer_email_domain import UnclaimedMaintainerEmailDomainDetector

from .utils import NPM_API_MAINTAINER_EMAIL_WARNING, get_email_addresses


class NPMUnclaimedMaintainerEmailDomainDetector(UnclaimedMaintainerEmailDomainDetector):
    def __init__(self):
        super().__init__("npm")

        self.description += "; " + NPM_API_MAINTAINER_EMAIL_WARNING

    def get_email_addresses(self, package_info: dict):
        return get_email_addresses(package_info)

    def detect(self, package_info, path: Optional[str] = None, name: Optional[str] = None,
               version: Optional[str] = None) -> tuple[bool, str]:
        has_issues, message = super().detect(package_info, path, name, version)

        if has_issues:
            message += "\n\n" + NPM_API_MAINTAINER_EMAIL_WARNING

        return has_issues, message

