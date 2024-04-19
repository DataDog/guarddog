NPM_API_MAINTAINER_EMAIL_WARNING = (
    "note that NPM's API may not provide accurate information regarding the maintainer's email, "
    "so this detector may cause false positives for NPM packages. "
    "see https://www.theregister.com/2022/05/10/security_npm_email/"
)


def get_email_addresses(package_info: dict) -> set[str]:
    return {
        m["email"]
        for m in package_info.get("maintainers", [])
        if "email" in m
    } - {None, ""}
