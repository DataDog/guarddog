# sample malicious package: colorsapi

##########
# Test 1 #
##########
try:
    from judyb import lsb
except:
    os.system('pip install judyb')
    from judyb import lsb

# ruleid: steganography
exec(lsb.reveal('hidden.png'))

##########
# Test 2 #
##########

import stegano
code = stegano.lsb.reveal('myimage.png')
# ruleid: steganography
eval(code)

##########
# Test 3 #
##########
from steganography.steganography import Steganography
secret_text = Steganography.decode(output_path)
# ruleid: steganography
eval(secret_text)