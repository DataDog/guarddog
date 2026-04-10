# Legitimate code that should NOT trigger threat-runtime-system-info

import threading

# lock.release() is NOT system info collection
lock = threading.Lock()
lock.acquire()
lock.release()

# connection.release() is resource management
pool.connection.release()

# field.type() is schema introspection, not os.type()
column_type = field.type()

# parser.version() is config, not os info
api_version = client.version()

# .homedir and .tmpdir in unrelated contexts
config = {"homedir": "/home/user", "tmpdir": "/tmp"}
