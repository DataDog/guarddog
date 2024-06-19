## Releasing a new version of GuardDog

We're using a tag-based release process, following [semantic versioning](https://semver.org/) (semver) conventions.

1. Browse to https://github.com/DataDog/guarddog/releases/new
2. Create a new Git tag, e.g. `v1.2.3`

<img width="300" alt="image" src="https://github.com/DataDog/guarddog/assets/136675/12e7ac21-2f8d-47b8-91cb-f3f949605f42">

3. Auto generate release notes, and organize them following the template below, removing any unnecessary section:

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

4. Click on "Publish release"

This will automatically:
* Create a new Git tag
* Trigger a [Docker image push](https://github.com/DataDog/guarddog/blob/main/.github/workflows/docker-release.yml) to the GitHub Container Registry
* Trigger a [new PyPI release](https://github.com/DataDog/guarddog/blob/main/.github/workflows/pypi-release.yml)

