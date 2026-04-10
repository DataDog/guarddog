# Legitimate code that should NOT trigger threat-runtime-obfuscation-api

# Standard __dict__ access (very common in Python)
value = self.__dict__['name']
cls.__dict__[attr_name]
properties = [p for p in cls.__dict__ if isinstance(cls.__dict__[p], property)]

# Standard getattr with string literal
host = getattr(settings, 'STATSD_HOST', 'localhost')
advisory = getattr(instrument, "_advisory", None)

# Standard getattr with variable (not targeting dangerous builtins)
method = getattr(MaskedArray, methodname)

# Standard setattr
for k, v in kwargs.items():
    setattr(self._client, k, v)

# __getattribute__ override
class Proxy:
    def __getattribute__(self, name):
        return super().__getattribute__(name)
