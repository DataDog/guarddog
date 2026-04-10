# Legitimate code that should NOT trigger threat-runtime-system-info

import threading

# lock.release() is NOT system info collection
lock = threading.Lock()
lock.acquire()
lock.release()

# field.type() is schema introspection
column_type = field.type()

# version getter is not os info
api_version = client.version()
