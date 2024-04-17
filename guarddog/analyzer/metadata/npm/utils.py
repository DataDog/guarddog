def get_email_addresses(package_info: dict) -> set[str]:
    return {
        m["email"]
        for m in package_info.get("maintainers", [])
        if "email" in m
    } - {None, ""}
