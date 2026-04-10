# Legitimate code that should NOT trigger capability-filesystem-browser

from http.cookies import SimpleCookie
from http.cookiejar import CookieJar

# Standard HTTP cookie handling
def extract_cookies(response):
    cookies = response.headers.get("Set-Cookie")
    jar = CookieJar()
    jar.extract_cookies(response, request)
    return jar

# Cookie parameter in function signatures
def make_request(url, cookies=None):
    pass

# Mentioning cookies in documentation strings
class SessionManager:
    """Manages HTTP sessions and cookies for the API client."""

    def clear_cookies(self):
        """Clear all session cookies."""
        self.cookie_jar.clear()

# Django cookie configuration
COOKIE_SECRET = "not-a-browser-path"
signing_secret = config.get_option("server.cookieSecret")
