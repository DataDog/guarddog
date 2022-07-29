# Contributing to Pysecurity

### Getting Started
To open the development environment for pysecurity: first make sure pip and pipenv are installed.

```sh
$ pip install pipenv
```

To install all dependencies for Pysecurity, open the virtual environment, and add the root of the repository to PYTHONPATH:

```sh
$ export PYTHONPATH=$PYTHONPATH:/$(pwd)
$ pipenv install
$ pipenv shell
```

You're ready to start developing!

### :bug: Creating Issues 
If you found a bug, search if an issue already exists [search if an issue already exists](https://docs.github.com/en/github/searching-for-information-on-github/searching-on-github/searching-issues-and-pull-requests#search-by-the-title-body-or-comments). If it doesn't, you can create a new issue with the bug label. Likewise, if you would like to suggest an enhancement, first see if a similar issue was already created. Then, create a new issue with the enhancement label.

### :white_check_mark: Solving Issues
Create a new branch with the form: `<username>/<branch-function>`. After changing the repo locally and pushing to your branch's remote origin, create a pull request with a short description of your changes.