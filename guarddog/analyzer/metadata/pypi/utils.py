def get_email_addresses(package_info: dict) -> set[str]:
    info = package_info.get("info", {})

    return {
        info.get("author_email")
        or info.get("maintainer_email")
    } - {None}
