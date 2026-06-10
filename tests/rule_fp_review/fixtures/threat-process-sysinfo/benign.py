# FALSE POSITIVE: 'hostname' here is an endpoint dictionary key (botocore-style),
# not the hostname command being spawned.
def resolve_endpoint(resolved):
    return resolved["hostname"]
