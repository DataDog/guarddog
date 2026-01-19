## Releasing a new version of GuardDog

We're using a tag-based release process, following [semantic versioning](https://semver.org/) (semver) conventions.

1. Bump version in `pyproject.toml` preferably using `poetry version` accordingly (patch, minor, major)
2. Submit a pull-request and merge, this will automatically build and publish accordingly

This will automatically:
* Create a new Git tag
* Create a new Github release
* Trigger a [Docker image push](https://github.com/DataDog/guarddog/blob/main/.github/workflows/docker-release.yml) to the GitHub Container Registry
* Trigger a [new PyPI release](https://github.com/DataDog/guarddog/blob/main/.github/workflows/pypi-release.yml)

3. Release notes will be automatically generated, re-organize them following the template below, removing any unnecessary section:

```
### Breaking changes

* Change XYZ by @user (#123)

### New features

* Implement XYZ by @user (#123)
* Implement XYZ by @user (#123)

### Bug fixes and improvements

* Fix XYZ by @user (#123)

### Chores

* Bump XYZ to XYZ
```
