# Writing GuardDog Rules

This document explains how to write effective detection rules for GuardDog that follow our risk-based detection model.

## Core Philosophy

GuardDog uses a **two-layer detection model** where **capabilities** and **threats** work together to identify actual risks:

### Capabilities: "CAN DO"

Capabilities detect what code **can** do - the technical ability to perform an action.

**Focus on:** Function calls to known methods that enable an action
- Example: `.readFile()` or `.readFileSync()` shows a Node.js app **can** read files
- Example: `requests.get()` shows a Python app **can** make HTTP requests
- Example: `subprocess.Popen()` shows code **can** spawn processes

**Avoid:**
- ❌ Relying solely on imports (e.g., `import fs` alone is too broad and leads to high false positive rates)
- ❌ Detecting threat indicators (that's what threat rules do)

**Good Capability Examples:**
```python
# ✅ capability.filesystem.read
$py_read = /\.read\s*\(/          # Detects .read() method
$py_readfile = /\.readFile\s*\(/  # Detects .readFile() method

# ✅ capability.network.outbound
$py_requests = /requests\.get\s*\(/  # Detects HTTP GET capability
$js_fetch = /\bfetch\s*\(/           # Detects fetch() API
```

**Bad Capability Examples:**
```python
# ❌ Too broad - just importing doesn't mean it's used
$py_import_fs = /import\s+os/

# ❌ This is a threat indicator, not a capability
$sensitive_file = "/etc/passwd"
```

### Threats: "SUSPICIOUS"

Threats detect **suspicious indicators** - patterns that suggest malicious intent.

**Focus on:** Clear threat indicators that attackers target
- Example: `/etc/passwd` is a file attackers commonly target
- Example: `bit.ly` domains are commonly used for malicious redirection
- Example: `base64.decode() + exec()` is an obfuscation technique used by malware

**Avoid:**
- ❌ Relying on function calls alone (that's what capability rules do)
- ❌ Generic patterns that appear in legitimate code

**Good Threat Examples:**
```python
# ✅ threat.filesystem.read (targets sensitive files)
$passwd = "/etc/passwd"
$shadow = "/etc/shadow"
$ssh_key = ".ssh/id_rsa"

# ✅ threat.network.outbound (suspicious domains)
$pastebin = /pastebin\.com/
$discord_webhook = /discord\.com\/api\/webhooks/

# ✅ threat.runtime.obfuscation (evasion technique)
# Requires BOTH decode AND exec together
condition: ($base64_decode and $exec)
```

**Bad Threat Examples:**
```python
# ❌ Just a capability, not suspicious on its own
$file_read = /\.read\s*\(/

# ❌ Too generic - common in legitimate code
$env_read = "process.env"
```

### Risks: Capability + Threat

Risks form when a **capability** and **threat** are found **in the same file** with matching categories.

**Example Risk Formation:**
```
capability.filesystem.read (can read files)
    +
threat.filesystem.read (reads /etc/passwd)
    =
risk.filesystem.read (credential-access)
```

**Why This Works:**
- **Capability alone** isn't malicious (file system libraries should read files)
- **Threat indicator alone** might be a false positive (test fixtures, documentation)
- **Capability + Threat together** indicates actual risk (code that can *and will* do something malicious)

## Rule Structure

### Identifies Field Format

```
{type}.{category}[.{detail}]
```

**Type:** `capability` or `threat`

**Category** (system resources):
- `network` - Network operations
- `filesystem` - File system operations
- `process` - Process/command execution
- `runtime` - Runtime operations (no capability needed)
- `system` - System information APIs

**Detail** (optional specificity):
- Examples: `outbound`, `read`, `write`, `obfuscation`, `collection`

**Special Case - Runtime Category:**

`threat.runtime.*` rules automatically form risks **without needing a capability**. Use this for:
- Obfuscation techniques (base64 decode + exec)
- Install hooks (run code during installation)
- Standalone suspicious patterns that don't need enabling capabilities

### Risk Formation Rules

Capabilities and threats form risks when:

1. **Same category**: Both must have matching category
   - ✅ `capability.network` + `threat.network` → `risk.network`
   - ✅ `capability.process.hooks` + `threat.process.hooks` → `risk.process.hooks`
   - ❌ `capability.filesystem` + `threat.network` → NO RISK (categories don't match)
   - ❌ `capability.process.hooks` + `threat.network.outbound` → NO RISK (categories don't match)

2. **Detail compatibility**:
   - General matches specific: `threat.network` + `capability.network.outbound` ✅
   - Exact match: `threat.network.outbound` + `capability.network.outbound` ✅
   - Conflict: `threat.network.outbound` + `capability.network.inbound` ❌

3. **Exception**: `threat.runtime.*` rules skip this - they auto-form risks

**CRITICAL:** Risks only form when categories match. A `capability.process.*` rule can only form risks with `threat.process.*` rules, never with `threat.network.*` or other categories. This is by design to ensure accurate risk assessment.

## Metadata Schema

### Required Fields

```yaml
identifies: "capability.{category}[.{detail}]"  # or "threat.{category}[.{detail}]"
severity: "low" | "medium" | "high"
description: "Human-readable description"
```

For **threat rules only**:
```yaml
mitre_tactics: "tactic"  # Single MITRE ATT&CK tactic
```

### Optional Fields (default to `medium`)

```yaml
specificity: "low" | "medium" | "high"      # Pattern specificity
sophistication: "low" | "medium" | "high"    # Technique advancement level
```

### YARA-Specific Fields

```yaml
max_hits: 3                                  # Limit findings per file
path_include: "*.py,*.js,*.go"              # File patterns to scan
```

### Field Definitions

**Severity** (impact of finding):
- `low`: Minor concern, common patterns
- `medium`: Moderately suspicious
- `high`: Clearly malicious or high impact

**Specificity** (how specific the pattern is to malware vs legitimate code):
- `low`: Generic patterns that appear in legitimate code frequently
- `medium`: Reasonably specific, some false positives expected
- `high`: Very specific to malicious behavior, minimal false positives

**Sophistication** (technique advancement level):
- `low`: Basic/common techniques used by script kiddies
- `medium`: Moderate evasion or complexity
- `high`: Advanced techniques, APT-level tradecraft

**MITRE Tactics** (attack stage - **single tactic only**):
- **Early stage**: `initial-access`, `execution`, `reconnaissance`, `resource-development`
- **Mid stage**: `defense-evasion`, `credential-access`, `persistence`, `privilege-escalation`, `discovery`
- **Late stage**: `command-and-control`, `exfiltration`, `impact`, `lateral-movement`, `collection`

Note: Only threats have MITRE tactics. Choose the **primary** tactic that best represents the malicious intent.

## Rule Examples

### YARA Capability Rule

```yara
rule capability_filesystem_read
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects file reading capabilities"
        identifies = "capability.filesystem.read"
        severity = "low"
        specificity = "low"
        sophistication = "low"

        max_hits = 1
        path_include = "*.py,*.pyx,*.pyi,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs"

    strings:
        // Python - file reading methods
        $py_read = /\.read\s*\(/
        $py_readfile = /\.readFile\s*\(/
        $py_open = /\bopen\s*\(/

        // JavaScript - file reading methods
        $js_readfile = /\.readFile(Sync)?\s*\(/
        $js_read = /\.read\s*\(/

    condition:
        any of them
}
```

### YARA Threat Rule

```yara
rule threat_filesystem_read
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects access to sensitive files (credentials, configs, keys)"
        identifies = "threat.filesystem.read"
        severity = "high"
        mitre_tactics = "credential-access"
        specificity = "high"
        sophistication = "low"

        max_hits = 5

    strings:
        // Sensitive system files
        $passwd = "/etc/passwd"
        $shadow = "/etc/shadow"

        // SSH keys - use regex to match .ssh structure
        $ssh_rsa = ".ssh/id_rsa"
        $ssh_ed25519 = ".ssh/id_ed25519"

        // Cloud credentials
        $aws = ".aws/credentials"
        $gcp = "gcloud/credentials"

    condition:
        any of them
}
```

### Semgrep Rule Example

```yaml
rules:
  - id: threat-network-suspicious-domain
    languages:
      - python
      - javascript
    message: Detects connection to suspicious domain
    metadata:
      identifies: "threat.network.outbound"
      severity: "high"
      mitre_tactics: "exfiltration"
      specificity: "high"
      sophistication: "low"
      description: "Detects URLs to suspicious domains used for exfiltration"
    patterns:
      - pattern-regex: '(pastebin\.com|transfer\.sh|discord\.com/api/webhooks)'
    severity: WARNING
```

## Pattern Writing Best Practices

### 1. Use Word Boundaries

Avoid matching partial words and ensure proper spacing:

```yara
// ❌ Bad - matches "myrequests.get()" or "requests.getall()"
$bad = /requests\.get/

// ✅ Good - only matches "requests.get()" with word boundaries
$good = /\brequests\.get\s*\(/
```

### 2. Match Method Calls, Not Object Names

The object can be named anything:

```yara
// ❌ Bad - only works if object is named "dns"
$bad = "dns.lookup("

// ✅ Good - matches .lookup() on any object
$good = /\.lookup\s*\(/
```

### 3. Require Context for Strings

Match patterns within quoted strings when appropriate:

```yara
// ❌ Bad - matches "curl" anywhere, even in variable names
$bad = "curl"

// ✅ Good - matches "curl" only within strings
$good = /['"][^'"]*\bcurl\b[^'"]*['"]/
```

### 4. Detect Patterns in Specific Context

Use private rules to establish context and avoid false positives:

```yara
// ❌ Bad - matches LOLBAS anywhere (shebangs, READMEs, code files)
rule threat_process_hooks {
    strings: $node = /\bnode\b/
    condition: $node
}

// ✅ Good - only matches LOLBAS within install hooks
include "hooks.meta"
include "lolbas-proc.meta"
rule threat_process_hooks {
    condition: (has_npm_hook or has_python_hook) and lolbas_proc
}
```

**Key principle:** Establish context with private rules, then detect threats within that context.

### 5. Use Private Rules and Meta Files for Reusable Logic (DRY Principle)

**Don't Repeat Yourself (DRY):** Extract common patterns into reusable private rules in `.meta` files.

**Create a `.meta` file** for shared patterns:

```yara
// lolbas-net.meta
rule lolbas_net
{
    strings:
        $curl = /\bcurl\b/ nocase
        $wget = /\bwget\b/ nocase
        $nc = /\bnc\b/ nocase
        $netcat = /\bnetcat\b/ nocase
    condition:
        any of them
}
```

**Use in multiple rules:**

```yara
// capability-network-lolbas.yar
include "lolbas-net.meta"

rule capability_network_lolbas
{
    ...
    condition:
        has_process_spawn and lolbas_net
}
```

```yara
// threat-process-hooks.yar
include "lolbas-net.meta"
include "hooks.meta"

rule threat_process_hooks
{
    ...
    condition:
        (has_npm_hook or has_python_hook) and lolbas_net
}
```

**Benefits:**
- Single source of truth for common patterns
- Easier maintenance (update once, applies everywhere)
- Consistent detection logic across rules
- Prevents drift between similar patterns

**When to use `.meta` files:**
- Patterns used in 2+ rules
- Common detection building blocks (LOLBAS, hooks, spawning)
- Shared context validators (e.g., detecting if we're in a hook)

## Testing Rules

### Unit Testing

Create test files in `tests/analyzer/sourcecode/` following this structure:

```
tests/analyzer/sourcecode/
  ruleset_test_<rule-id>/
    <rule-id>.py        # Test case for Python
    <rule-id>.js        # Test case for JavaScript
    <rule-id>.go        # Test case for Go
```

Test file should contain patterns that **should** and **should not** match:

```python
# tests/analyzer/sourcecode/ruleset_test_capability-network-outbound/capability-network-outbound.py

# ruleid: capability-network-outbound
import requests
requests.get("https://example.com")

# ok: capability-network-outbound
# Just importing shouldn't match
import requests
```

### Manual Testing

```bash
# Test on a specific package
guarddog pypi scan package-name --rules my-rule

# Test with specific rules only
guarddog pypi scan package-name --rules rule1 --rules rule2

# Exclude specific rules
guarddog pypi scan package-name --exclude-rules my-rule

# Test on local directory
guarddog pypi scan /path/to/package/

# Output JSON for analysis
guarddog pypi scan package-name --output-format json
```

### Validation Checklist

Before submitting a rule:

- [ ] Rule filename matches rule ID
- [ ] `identifies` field follows `{type}.{category}[.{detail}]` format
- [ ] Category is one of: `network`, `filesystem`, `process`, `runtime`, `system`
- [ ] Category matches between capability and threat (for risk formation)
- [ ] Severity is appropriate (`low`/`medium`/`high`)
- [ ] Threat rules have single `mitre_tactics` value
- [ ] Capability rules focus on function calls, not imports
- [ ] Threat rules focus on indicators, not capabilities
- [ ] Patterns use word boundaries (`\b`) where appropriate
- [ ] No partial string matches that cause false positives
- [ ] Context-aware detection used where needed (e.g., hooks + LOLBAS, not just LOLBAS anywhere)
- [ ] Duplicated patterns extracted to `.meta` files
- [ ] Include paths are correct and `.meta` files exist
- [ ] Private rules cannot be used together from same file (split if needed)
- [ ] Test cases created with positive and negative examples
- [ ] Rule tested manually on real packages
- [ ] Verified no false positives from shebangs, READMEs, or non-hook code

## Advanced Patterns

### Install Hooks: Capability vs Threat

Install hooks are a special case that demonstrates the capability/threat separation:

**✅ Correct Approach:**

Install hooks themselves are a **capability**, not a threat:

```yara
// capability-process-hooks.yar
include "hooks.meta"

rule capability_process_hooks
{
    meta:
        identifies = "capability.process.hooks"
        severity = "low"
    condition:
        has_npm_hook or has_python_hook
}
```

**Why?** Many legitimate packages use install hooks for:
- Compiling native modules (`node-gyp rebuild`)
- Building assets (`npm run build`)
- Setting up git hooks (`husky install`)
- Post-install messages

The **threat** is what LOLBAS tools are being used in the hooks:

```yara
// threat-process-hooks.yar
include "hooks.meta"
include "lolbas-net.meta"

rule threat_process_hooks
{
    meta:
        identifies = "threat.process.hooks"
        severity = "medium"
        mitre_tactics = "execution"
    condition:
        (has_npm_hook or has_python_hook) and lolbas_net
}
```

**Risk Formation:**
```
capability.process.hooks (has install hook)
    +
threat.process.hooks (uses curl/wget)
    =
risk.process.hooks (malicious install hook)
```

**Key Insight:** Install hooks are equivalent to `subprocess.call()` - they're a process spawning capability. The same threats that apply to `capability.process.spawn` should also apply to `capability.process.hooks`.

### LOLBAS Detection Pattern

Living Off The Land Binaries and Scripts (LOLBAS) are legitimate tools used maliciously:

**Split by Purpose:**
- `lolbas-proc.meta` - Execution tools (bash, python, node, perl, ruby)
- `lolbas-net.meta` - Network tools (curl, wget, nc, netcat)

**Why split?** YARA has limitations using multiple private rules from the same include. Splitting allows flexible composition:

```yara
// Use execution tools only
include "lolbas-proc.meta"

// Use network tools only
include "lolbas-net.meta"

// Use both if needed
include "lolbas-proc.meta"
include "lolbas-net.meta"
```

**Pattern:**
```yara
// lolbas-net.meta
rule lolbas_net
{
    strings:
        $curl = /\bcurl\b/ nocase
        $wget = /\bwget\b/ nocase
        $nc = /\bnc\b/ nocase
        $netcat = /\bnetcat\b/ nocase
        $telnet = /\btelnet\b/ nocase
    condition:
        any of them
}
```

Use word boundaries (`\b`) to avoid false positives from substring matches.

## Support Formats

GuardDog supports two rule formats:

### YARA Rules (`.yar`)
- **Language-agnostic**: All YARA rules are loaded regardless of ecosystem
- **Binary-safe**: Can scan any file type
- **Pattern matching**: Great for byte patterns, strings, regex
- **Best for**: Cross-language patterns, obfuscation detection, binary analysis

### Semgrep Rules (`.yml`)
- **Language-aware**: Only loaded when language matches ecosystem
- **AST-based**: Understands code structure
- **Metavariables**: Can match and reuse code fragments
- **Best for**: Complex code patterns, language-specific detection

Choose YARA for broad pattern matching across all files. Choose Semgrep for language-specific code analysis.

## File Organization

Place rules under `guarddog/analyzer/sourcecode/`:

```
guarddog/analyzer/sourcecode/
  # Capability rules
  capability-filesystem-read.yar
  capability-network-outbound.yar
  capability-network-lolbas.yar
  capability-process-hooks.yar
  capability-process-spawn.yar

  # Threat rules
  threat-filesystem-read.yar
  threat-network-outbound-shady-links.yar
  threat-process-hooks.yar
  threat-runtime-obfuscation-base64exec.yar
  threat-runtime-system-info.yar
  threat-runtime-environment-read.yar

  # Meta files (reusable private rules)
  hooks.meta
  lolbas-net.meta
  lolbas-proc.meta
```

**Naming conventions:**

**Rule files (`.yar`):** `{type}-{category}-{detail}.yar`
- Examples:
  - `capability-network-outbound.yar`
  - `threat-filesystem-read.yar`
  - `threat-runtime-obfuscation-base64exec.yar`

**Meta files (`.meta`):** `{pattern-name}.meta`
- Examples:
  - `hooks.meta` - Install hook detection patterns
  - `lolbas-net.meta` - LOLBAS network tools (curl, wget, nc)
  - `lolbas-proc.meta` - LOLBAS execution tools (bash, python, node)

**Meta file guidelines:**
- Use `.meta` extension for files containing only private rules
- Name describes what patterns it contains
- Single responsibility - one concern per meta file
- Split related patterns if they can't be used together (e.g., `lolbas-proc.meta` and `lolbas-net.meta` instead of combined `lolbas.meta`)

## Key Takeaways

### Rule Writing Principles

1. **Capabilities detect CAN DO** - Focus on function calls, not imports
2. **Threats detect SUSPICIOUS** - Focus on attacker indicators, not generic patterns
3. **Categories must match** - `capability.process.*` + `threat.process.*` = risk
4. **Runtime bypasses capabilities** - `threat.runtime.*` auto-forms risks
5. **Context matters** - Detect patterns where they matter (hooks + LOLBAS, not just LOLBAS anywhere)

### DRY Principle

- Extract common patterns to `.meta` files
- Split incompatible private rules (`lolbas-proc.meta` vs `lolbas-net.meta`)
- Single source of truth prevents pattern drift

### Install Hooks Pattern

- **Hooks are capabilities** (like `subprocess.call()`)
- **LOLBAS in hooks are threats** (process category)
- Same threats apply to both `capability.process.spawn` and `capability.process.hooks`

### Avoid False Positives

- Use word boundaries (`\b`)
- Require context (private rules for "where" detection)
- Test against shebangs, READMEs, legitimate code

## Questions?

If you're unsure whether a pattern should be a capability or threat, ask:

1. **Does this pattern show what code CAN do?** → Capability
2. **Does this pattern show suspicious/malicious indicators?** → Threat
3. **Does this pattern work standalone without needing other capabilities?** → Runtime threat
4. **Will it form risks with the right category?** → Check category matching

When in doubt, err on the side of being more specific. It's better to have separate capability and threat rules that form risks correctly than to have overly broad rules with high false positive rates.
