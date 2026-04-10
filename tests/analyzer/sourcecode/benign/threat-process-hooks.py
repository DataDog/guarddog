# Legitimate setup.py that should NOT trigger threat-process-hooks

from setuptools import setup

setup(
    name="my-awesome-lib",
    version="1.0.0",
    description="A Python library for data processing",
    url="https://github.com/myorg/my-awesome-python-sdk",
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.25.0",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
    ],
)

# Mentioning python, node, ruby in comments and strings is normal
SUPPORTED_RUNTIMES = ["python", "node", "ruby"]
pyimpl = "pypy" if False else "python"
