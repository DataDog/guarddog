import json

tool = {
    "driver": {
        "name": "semgrep",
        "rules": [
            {
                "defaultConfiguration": {
                    "level": "warning"
                },
                "fullDescription": {
                    "text": "Found user controlled content in `run_string`. This is dangerous because it allows a malicious actor to run arbitrary Python code."
                },
                "helpUri": "https://semgrep.dev/r/python.lang.security.dangerous-subinterpreters-run-string.dangerous-subinterpreters-run-string",
                "id": "python.lang.security.dangerous-subinterpreters-run-string.dangerous-subinterpreters-run-string",
                "name": "python.lang.security.dangerous-subinterpreters-run-string.dangerous-subinterpreters-run-string",
                "properties": {
                    "precision": "very-high",
                    "tags": [
                        "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
                        "OWASP-A03:2021 - Injection",
                        "security"
                    ]
                },
                "shortDescription": {
                    "text": "Found user controlled content in `run_string`. This is dangerous because it allows a malicious actor to run arbitrary Python code."
                }
            },
            {
                "defaultConfiguration": {
                    "level": "warning"
                },
                "fullDescription": {
                    "text": "Queue $X is missing encryption at rest. Add \"encryption: $Y.QueueEncryption.KMS\" or \"encryption: $Y.QueueEncryption.KMS_MANAGED\" to the queue props to enable encryption at rest for the queue."
                },
                "helpUri": "https://semgrep.dev/r/typescript.aws-cdk.security.audit.awscdk-sqs-unencryptedqueue.awscdk-sqs-unencryptedqueue",
                "id": "typescript.aws-cdk.security.audit.awscdk-sqs-unencryptedqueue.awscdk-sqs-unencryptedqueue",
                "name": "typescript.aws-cdk.security.audit.awscdk-sqs-unencryptedqueue.awscdk-sqs-unencryptedqueue",
                "properties": {
                    "precision": "very-high",
                    "tags": [
                        "CWE-311: Missing Encryption of Sensitive Data",
                        "OWASP-A03:2017 - Sensitive Data Exposure",
                        "OWASP-A04:2021 - Insecure Design",
                        "security"
                    ]
                },
                "shortDescription": {
                    "text": "Queue $X is missing encryption at rest. Add \"encryption: $Y.QueueEncryption.KMS\" or \"encryption: $Y.QueueEncryption.KMS_MANAGED\" to the queue props to enable encryption at rest for the queue."
                }
            }
        ]
    }
}


def _get_npm_region(package_raw: str, package: str) -> dict:
    start_line = 0
    start_column = 0
    end_column = 0
    for idx, val in enumerate(package_raw.split("\n")):
        if package in val:
            start_line = idx + 1
            start_column = val.index(package)
            end_column = start_line + len(package)

    return {
        "startLine": start_line,
        "endLine": start_line,
        "startColumn": start_column,
        "endColumn": end_column,
    }


def report_npm_verify_sarif(package_path: str, rules: list[str], scan_results: list[dict]) -> str:
    results = []
    with open(package_path, "r") as file:
        package_raw = file.read()
    for entry in scan_results:
        if entry["result"]["issues"] == 0:
            continue
        region = _get_npm_region(package_raw, entry["dependency"])
        fingerprint = json.dumps(entry)  # TODO: hash

        results.append({
            "fingerprints": {
                "guarddogfindings/v1": fingerprint
            },
            "partialFingerprints": {
                "guarddogfindings/v1": fingerprint
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": package_path
                        },
                        "region": region
                    }
                }
            ],
            "message": {
                "text": json.dumps(entry)  # FIXME
            },
            "ruleId": json.dumps(entry)  # FIXME
        })

    res = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": []
                    }
                ],
                "results": results,
                "tool": tool
            }
        ]
    }

    return json.dumps(res, indent=2)
