rules:
  - id: insecure-shutil-unpack-archive-use
    message: The Python 'shutil' shutil.extract_archive is vulnerable to
      arbitrary file overwrites
    languages:
      - python
    severity: ERROR
    metadata:
      category: security
      technology:
        - python
      owasp:
        - A06:2017 - Security Misconfiguration
        - A05:2021 - Security Misconfiguration
      cwe:
        - "CWE-22: Improper Limitation of a Pathname to a Restricted Directory
          ('Path Traversal')"
      license: Commons Clause License Condition v1.0[LGPL-2.1-only]
    pattern-either:
      - pattern: |
          shutil.unpack_archive(...)