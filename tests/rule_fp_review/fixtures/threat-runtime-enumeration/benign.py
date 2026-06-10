# FALSE POSITIVE: $nmap matches the "nMap" substring of ChainMap, and $py_ip_addr
# matches "IP Address" in the docstring. Neither is network enumeration.
from collections import ChainMap

def merge_configs(a, b):
    """Merge configs into a ChainMap. Also validates the IP Address fields."""
    return ChainMap(a, b)
