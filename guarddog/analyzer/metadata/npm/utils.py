def get_email_addresses(package_info: dict) -> list[str]:
    if package_info.get("maintainers"):
        return list(map(lambda x: x["email"], package_info["maintainers"]))
    else:
        return []
