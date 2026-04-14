# GuardDog Rules Reference

This document lists all detection rules available in GuardDog, organized by ecosystem.

Rules are categorized by their `identifies` field which determines how they participate in risk scoring:

- **`capability.*`** - Detects what code *can* do (function calls, APIs). Requires a matching threat to form a risk.
- **`threat.*`** - Detects suspicious indicators. Forms risks when paired with matching capabilities.
- **`threat.runtime.*`** - Standalone threats that auto-form risks without needing a capability.
- **`threat.metadata.*`** - Package metadata threats that auto-form risks without needing a capability.

<!-- BEGIN_RULE_LIST -->
## Capability rules

| **Rule** | **Identifies** | **Description** | **Severity** | **PyPI** | **npm** | **go** | **GitHub Action** | **Extension** | **RubyGems** |
|:---------|:---------------|:----------------|:------------:|:---:|:---:|:---:|:---:|:---:|:---:|
| capability-process-schedule | `capability.process.schedule` | Detects ability to create scheduled tasks (cron, at, schtasks) | medium | :white_check_mark: | :white_check_mark: | | :white_check_mark: | :white_check_mark: | |
| capability-network-outbound | `capability.network.outbound` | Detects network request capabilities (HTTP, sockets, etc.) | low | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| capability-network-download | `capability.network.download` | Detects downloading files from network | low | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | |
| capability-network-lolbas | `capability.network` | Detects usage of LOLBAS network tools (curl, wget, nc, etc.) | low | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | |
| capability-filesystem-write-executable | `capability.filesystem.write.executable` | Detects writing executable files or changing file permissions to executable | medium | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | |
| capability-filesystem-read | `capability.filesystem.read` | Detects filesystem read capabilities | low | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | |
| capability-process-spawn | `capability.process.spawn` | Detects process execution and spawning | low | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| capability-filesystem-delete | `capability.filesystem.delete` | Detects file/directory deletion capabilities | low | :white_check_mark: | :white_check_mark: | | :white_check_mark: | :white_check_mark: | |
| capability-filesystem-browser | `capability.filesystem.browser` | Detects browser credential and cookie access capabilities | medium | :white_check_mark: | :white_check_mark: | | :white_check_mark: | :white_check_mark: | |
| capability-process-hooks | `capability.process.hooks` | Detects install hooks that can execute code during package installation | low | :white_check_mark: | :white_check_mark: | | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| capability-runtime-clipboard | `capability.runtime.clipboard` | Detects clipboard access operations | low | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | |

## Threat rules (source code)

| **Rule** | **Identifies** | **Description** | **Severity** | **PyPI** | **npm** | **go** | **GitHub Action** | **Extension** | **RubyGems** |
|:---------|:---------------|:----------------|:------------:|:---:|:---:|:---:|:---:|:---:|:---:|
| threat-filesystem-read | `threat.filesystem.read` | Detects access to sensitive files (credentials, configs, keys) | high | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| threat-runtime-obfuscation-chr | `threat.runtime.obfuscation` | Detects chr-based code obfuscation: exec/eval of chr() sequences | high | :white_check_mark: | | | | | |
| threat-npm-preinstall-script | `threat.process.hooks` | Detects npm preinstall scripts, which are almost exclusively used for malware delivery | high | | :white_check_mark: | | :white_check_mark: | :white_check_mark: | |
| threat-runtime-obfuscation-steganography | `threat.runtime.obfuscation.steganography` | Detects steganography decode followed by code execution | high | :white_check_mark: | :white_check_mark: | | :white_check_mark: | :white_check_mark: | |
| threat-runtime-keylogging | `threat.runtime.keylogging` | Detects keylogging and input capture patterns | high | :white_check_mark: | :white_check_mark: | | :white_check_mark: | :white_check_mark: | |
| threat-runtime-dynamic-loader | `threat.runtime.obfuscation` | Detects dynamic code loading: downloading and importing/executing code at runtime | high | :white_check_mark: | | | | | |
| threat-process-cryptomining | `threat.process.cryptomining` | Detects cryptocurrency mining activity | high | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| threat-process-powershell-encoded | `threat.process.spawn` | Detects PowerShell encoded commands, hidden windows, and download cradles | high | :white_check_mark: | :white_check_mark: | | :white_check_mark: | :white_check_mark: | |
| threat-network-reverse-shell | `threat.network.outbound` | Detects reverse shell patterns and remote access tools | high | :white_check_mark: | :white_check_mark: | | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| threat-runtime-obfuscation-general | `threat.runtime.obfuscation.general` | Detects heavy code obfuscation techniques | medium | :white_check_mark: | :white_check_mark: | | :white_check_mark: | :white_check_mark: | |
| threat-filesystem-destruction | `threat.filesystem.destruction` | Detects destructive operations (recursive deletion, wiping) | high | :white_check_mark: | :white_check_mark: | | :white_check_mark: | :white_check_mark: | |
| threat-setup-suspicious-imports | `threat.setup.import.aliasing` | Detects suspicious imports in setup.py: network, system, or crypto libraries that have no place in a build script | high | :white_check_mark: | | | | | |
| threat-runtime-obfuscation-pyarmor | `threat.runtime.obfuscation.pyarmor` | Detects PyArmor obfuscation, a commercial tool commonly used to hide malicious code in Python packages | medium | :white_check_mark: | | | | | |
| threat-network-exfiltration | `threat.network.outbound` |  | high | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| threat-runtime-enumeration | `threat.runtime.enumeration` | Detects extensive system/network enumeration activities | medium | :white_check_mark: | :white_check_mark: | | :white_check_mark: | :white_check_mark: | |
| threat-runtime-environment-read | `threat.runtime.environment.read` | Detects reading of environment variables (credential access, often contains secrets) | low | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| threat-process-memory | `threat.process.memory` | Detects memory scraping and credential dumping from process memory | high | :white_check_mark: | :white_check_mark: | | :white_check_mark: | :white_check_mark: | |
| threat-process-hooks | `threat.process.hooks` | Detects LOLBAS usage in install hooks (execution and network tools) | medium | :white_check_mark: | :white_check_mark: | | :white_check_mark: | :white_check_mark: | |
| threat-runtime-obfuscation | `threat.runtime.obfuscation` | Detects heavy obfuscation techniques commonly used by malware | low | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | |
| threat-npm-http-dependency | `threat.npm.http.dependency` | Detects HTTP/HTTPS URL dependencies in package.json (dependency confusion, untrusted sources) | high | | :white_check_mark: | | :white_check_mark: | :white_check_mark: | |
| threat-network-outbound-shady-links | `threat.network.outbound.shady_links` | Detects URLs to URL shorteners, file sharing, and suspicious services | medium | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| threat-runtime-obfuscation-unicode | `threat.runtime.obfuscation.unicode` | Detects unicode homoglyphs and uncommon characters used for obfuscation | medium | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | |
| threat-process-sysinfo | `threat.process.spawn.sysinfo` |  | medium | :white_check_mark: | :white_check_mark: | | :white_check_mark: | :white_check_mark: | |
| threat-network-exfil-messenger | `threat.network.outbound` | Detects hardcoded messaging platform tokens/webhooks used for data exfiltration | high | :white_check_mark: | :white_check_mark: | | :white_check_mark: | :white_check_mark: | |
| threat-network-dns-exfil | `threat.network.outbound` | Detects DNS-based data exfiltration: encoding data in DNS queries | high | :white_check_mark: | :white_check_mark: | | :white_check_mark: | :white_check_mark: | |
| threat-setup-import-aliasing | `threat.setup.import.aliasing` | Detects suspicious import aliasing of dangerous functions in setup.py | high | :white_check_mark: | | | | | |
| threat-runtime-obfuscation-import-exec | `threat.runtime.obfuscation` | Detects dynamic import chains used to obfuscate code execution | high | :white_check_mark: | | | | | |
| threat-setup-network-in-install | `threat.network.outbound` | Detects network operations or hostname/system info collection in setup.py, which is suspicious at install time | high | :white_check_mark: | | | | | |
| threat-runtime-obfuscation-api | `threat.runtime.obfuscation.api` | Detects advanced API call obfuscation using introspection and reflection techniques | medium | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | |
| threat-filesystem-autostart | `threat.filesystem.autostart` | Detects suspicious autostart persistence mechanisms | high | :white_check_mark: | :white_check_mark: | | :white_check_mark: | :white_check_mark: | |
| threat-npm-dependency-confusion | `threat.npm.http.dependency` | Detects dependency confusion indicators: self-referencing dependencies or DNS exfil in scripts | high | | :white_check_mark: | | :white_check_mark: | :white_check_mark: | |
| threat-process-download-exec | `threat.process.spawn` | Detects download-and-execute patterns: fetching a remote file then executing it | high | :white_check_mark: | :white_check_mark: | | :white_check_mark: | :white_check_mark: | |
| threat-runtime-obfuscation-base64exec | `threat.runtime.obfuscation.base64exec` | Detects base64 decoding followed by code execution | high | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| threat-network-exfil-sysinfo | `threat.network.outbound` | Detects system info collection combined with network exfiltration (hostname/user in HTTP requests) | high | :white_check_mark: | :white_check_mark: | | :white_check_mark: | :white_check_mark: | |
| threat-runtime-obfuscation-js-mangling | `threat.runtime.obfuscation.js.mangling` | Detects JavaScript variable name mangling (_0x pattern) used by obfuscation tools | medium | | :white_check_mark: | | :white_check_mark: | :white_check_mark: | |
| threat-process-spawn-silent | `threat.process.spawn.silent` | Detects fully silent process execution (suppressing all output channels) | low | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | |
| threat-runtime-system-info | `threat.runtime.system.info` | Detects active collection of system information (hostname, platform, architecture, user) | low | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| threat-process-injection-dll | `threat.process.injection.dll` | Detects DLL injection and process injection techniques | high | :white_check_mark: | :white_check_mark: | | :white_check_mark: | :white_check_mark: | |
| threat-runtime-screencapture | `threat.runtime.screencapture` |  | medium | :white_check_mark: | | | | | |

## Threat rules (metadata)

| **Rule** | **Identifies** | **Description** | **Severity** | **MITRE Tactic** | **PyPI** | **npm** | **go** | **GitHub Action** | **Extension** | **RubyGems** |
|:---------|:---------------|:----------------|:------------:|:----------------:|:---:|:---:|:---:|:---:|:---:|:---:|
| typosquatting | `threat.metadata.typosquatting` | Identify packages that are named closely to an highly popular package | high | initial-access | :white_check_mark: | :white_check_mark: | :white_check_mark: | | | :white_check_mark: |
| potentially_compromised_email_domain | `threat.metadata.compromised-email` | Identify when a package maintainer e-mail domain (and therefore package manager account) might have been compromised | high | initial-access | :white_check_mark: | :white_check_mark: | | | | |
| unclaimed_maintainer_email_domain | `threat.metadata.unclaimed-email` | Identify when a package maintainer e-mail domain (and therefore npm account) is unclaimed and can be registered by an attacker | high | initial-access | :white_check_mark: | :white_check_mark: | | | | |
| repository_integrity_mismatch | `threat.metadata.integrity-mismatch` | Identify packages with a linked GitHub repository where the package has extra unexpected files | high | initial-access | :white_check_mark: | | | | | :white_check_mark: |
| bundled_binary | `threat.metadata.bundled-binary` | Identify packages bundling binaries | medium | defense-evasion | :white_check_mark: | :white_check_mark: | | | | :white_check_mark: |
| deceptive_author | `threat.metadata.deceptive-author` | This heuristic detects when an author is using a disposable email | medium | initial-access | :white_check_mark: | :white_check_mark: | | | | |
| metadata_mismatch | `threat.metadata.manifest-mismatch` | Identify packages with mismatches between registry metadata and the actual package manifest | medium | execution | :white_check_mark: | :white_check_mark: | | | | |
| direct_url_dependency | `threat.metadata.direct-url-dep` | Identify packages with direct URL dependencies. Dependencies fetched this way are not immutable and can be used to inject untrusted code or reduce the likelihood of a reproducible install. | medium | initial-access | | :white_check_mark: | | | | |

<!-- END_RULE_LIST -->
