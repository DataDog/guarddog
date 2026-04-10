# Legitimate setup.py -- does not alias dangerous imports
from setuptools import setup, find_packages

setup(
    name="my-package",
    version="1.0.0",
    packages=find_packages(),
    install_requires=["requests>=2.25.0"],
    python_requires=">=3.8",
    description="A normal package",
    author="Normal Author",
)
