# Legitimate code that should NOT trigger threat-runtime-obfuscation-api

# Standard getattr with string literal (configuration access)
host = getattr(settings, 'STATSD_HOST', 'localhost')
advisory = getattr(instrument, "_advisory", None)
sigwinch = getattr(signal, "SIGWINCH", None)

# Standard setattr
class OAuthSession:
    def configure(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self._client, k, v)

# __getattribute__ override (standard Python pattern)
class Proxy:
    def __getattribute__(self, name: str):
        return super().__getattribute__(name)

# getattr with string literal to access a known attribute
value = getattr(node, "value")
