def get_email_addresses(package_info: dict) -> list[str]:
    author_email = package_info["info"]["author_email"]
    maintainer_email = package_info["info"]["maintainer_email"]
    email = author_email or maintainer_email
    if email is not None:
        return [email]
    else:
        return []
