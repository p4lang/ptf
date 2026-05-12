<!--
SPDX-FileCopyrightText: 2026 Andy Fingerhut

SPDX-License-Identifier: Apache-2.0
-->

# Notes on publishing new version of Python package for ptf

Prerequisites: You must have a Github user account that has privileges
to push new tags to this repository.  This might only be Github
accounts with administration privileges on the repository.

Run these commands:
```
git clone git@github.com:p4lang/ptf
cd ptf
git tag -a v<version-string> -m "Version <version-string> - <version description>"
git push origin v<version-string>
```

Example for releasing version 0.0.5 with comment "Version 0.0.5 - Add
eburst":
```
git clone git@github.com:p4lang/ptf
cd ptf
git tag -a v0.12.0 -m "Version 0.12.0 - Set up a uv-native project structure."
git push origin v0.12.0
```

To verify whether this successfully triggers creating a new release on
PyPI:

+ Go to https://github.com/p4lang/ptf
+ Click the "Actions" link near the top of the page.
+ Verify that the most recent workflow was started near the time you
  did the `git push` command above, that it has the
  `v<version-string>` in the column to the left of the start time, and
  to the left of that is a reasonable-looking commit description for
  the commit with that version.
+ After a few minutes, check the pypi.org page for the ptf
  package and verify that the new version is the most recent one
  mentioned: https://pypi.org/project/ptf/

If you further wish to test installing this package on a development
system that has the Python3 `venv` virtual environment package
installed:

```bash
python3 -m venv $HOME/venv-test-ptf-install
source $HOME/venv-test-ptf-install/bin/activate
pip list
pip install ptf
pip list
```

The `ptf` with the new latest version should have been
installed, along with many packages it depends upon.

Note: The reason that pushing a tag to this repository causes a new
release to be published to pypi.org is because of the Github action
defined in the file
[`.github/workflows/pypi.yml`](.github/workflows/pypi.yml) of this
repository.
