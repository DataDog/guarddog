# Benign regression test for threat-process-sysinfo.
# The words "hostname"/"whoami" appear as dict keys, XML element lookups and
# API paths, not as commands being executed.
# (FPs from botocore, censys, mistralai.)
def resolve(result, element):
    endpoint = result["hostname"]
    resolved_host = result.get("hostname")
    host_elements = element.findall("hostname")
    whoami_path = "/v1/workflows/workers/whoami"
    return endpoint, resolved_host, host_elements, whoami_path
