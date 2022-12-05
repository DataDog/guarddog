name: Semgrep scan

on:
  push:
    branches: ["main"]
  pull_request:
    branches: [ "main" ]

permissions:
  contents: read

jobs:
  semgrep:
    permissions:
      contents: read # for actions/checkout to fetch code
      security-events: write # for github/codeql-action/upload-sarif to upload SARIF results
    name: Scan
    runs-on: ubuntu-latest
    container:
      image: returntocorp/semgrep

    # Skip any PR created by dependabot to avoid permission issues:
    if: (github.actor != 'dependabot[bot]')

    steps:
      - uses: actions/checkout@v3

      - run: semgrep --config auto --sarif --output semgrep.sarif ./guarddog
      - run: semgrep --config .github/semgrep-rules --sarif --output semgrep-custom.sarif ./guarddog

      - name: Upload SARIF file for GitHub Advanced Security Dashboard
        uses: github/codeql-action/upload-sarif@v2
        with:
          category: semgrep-builtin
          sarif_file: semgrep.sarif

      - name: Upload SARIF file for custom Semgrep rules for GitHub Advanced Security Dashboard
        uses: github/codeql-action/upload-sarif@v2
        with:
          category: semgrep-custom
          sarif_file: semgrep-custom.sarif
          
