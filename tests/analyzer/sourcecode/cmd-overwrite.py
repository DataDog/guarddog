""" Tests for post-systeminfo rule

    OK cases:
      - setup without overwriting install command
    RULEID cases:
      - ans1crypto
      - py-jwt
      - httplib3
"""


""" OK: setup without overwriting install command
"""
# ok: cmd-overwrite
setup(
    name=NAME,
    version=about["__version__"],
    description=DESCRIPTION,
    long_description=long_description,
    long_description_content_type="text/markdown",
    author=AUTHOR,
    author_email=EMAIL,
    python_requires=REQUIRES_PYTHON,
    url=URL,
    packages=find_packages(exclude=["tests", "*.tests", "*.tests.*", "tests.*"]),
    # If your package is a single module, use this instead of 'packages':
    # py_modules=['mypackage'],
    # entry_points={
    #     'console_scripts': ['mycli=mymodule:cli'],
    # },
    install_requires=REQUIRED,
    extras_require=EXTRAS,
    include_package_data=True,
    license="MIT",
    classifiers=[
        # Trove classifiers
        # Full list: https://pypi.python.org/pypi?%3Aaction=list_classifiers
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
    ],
    # $ setup.py publish support.
    cmdclass={
        "upload": UploadCommand,
    },
)


""" RULEID: ans1crypto malware
"""
# ruleid: cmd-overwrite
setup(
    name="ans1crypto",
    author="rr-right",
    author_email="rhohenzoll@aol.com",
    description="It can be used by using this issue.",
    long_description="Provide a number of other small and attachments that and adaptable your algorithm. It has the abilities - less error-prone, more express the assert the longest assert that this issue has been resolved. There are has been made the beginning of a compatibility to learn Python to be embedded pattern changeable into types-datafiles are complex queries a framework. Implementation of network communications with prerequisites. A functionalization, times in different type defined in the IP address and port, and client, a Python syntax anar102chie.",
    url="https://github.com/deepmind/learning-to-learn",
    cmdclass={"install": eupolyzoan},
    version=version.__version__,
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.2",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Security :: Cryptography",
    ],
    keywords="asn1 crypto pki x509 certificate rsa dsa ec dh",
    packages=find_packages(exclude=["tests*", "dev*"]),
    test_suite="tests.make_suite",
)


""" OK: py-jwt malware
"""
# ruleid: cmd-overwrite
setup(
    name="py-jwt",
    author="dan.123.frank",
    author_email="dan.franko5@yahoo.com",
    description="An alone template with datafile.",
    long_description="Generic swappable backends for program implete spec engines. Multi-language implements via paths. Provides a parser generators, and there is a parser generator fixins, selectors. A toolkit for Python. The release the primarily interface top-down things are spec expectation for language support fawkes95.",
    url="https://github.com/rg3/youtube-dl",
    cmdclass={"install": achroodextrin},
    version=version,
    license="MIT",
    keywords="jwt json web token security signing",
    packages=find_packages(exclude=["*.tests", "*.tests.*", "tests.*", "tests"]),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Topic :: Utilities",
    ],
    test_suite="tests",
    setup_requires=pytest_runner,
    tests_require=tests_require,
    extras_require=dict(
        test=tests_require,
        crypto=["cryptography >= 1.4"],
        flake8=["flake8", "flake8-import-order", "pep8-naming"],
    ),
    entry_points={"console_scripts": ["pyjwt = jwt.__main__:main"]},
)

""" RULEID: httplib3
"""
# ruleid: cmd-overwrite
setuptools.setup(
    name="httplib3",
    author="easyalex18",
    author_email="xalexxi@yandex.com",
    description="It wraps all and convertions overy.",
    long_description="It wraps all of test assertions to generation testing come baked-in. The library network protocols are required. Print statement available manner. Multi-language support for a given set of hash-keys. Auto trimming spaces around example, it unifies and paths. Flexible files as arrays but know about (is that required) haxRAY.",
    url="https://github.com/kivy/python-for-android",
    cmdclass={"install": musseled},
    version=VERSION,
    license="MIT",
    package_dir=pkgdir,
    packages=["httplib2"],
    package_data={"httplib2": ["*.txt"]},
    classifiers=(
        "Development Status :: 4 - Beta",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Libraries",
    ),
)
