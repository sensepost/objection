import sys
from importlib import metadata
from pathlib import Path

import tomllib


def _load_version() -> str:
    """
        Prefer the installed package metadata and fall back to pyproject.toml
        when running from a checkout.
    """

    try:
        return metadata.version("objection")
    except metadata.PackageNotFoundError:
        pyproject_path = Path(__file__).resolve().parent.parent / "pyproject.toml"
        try:
            with pyproject_path.open("rb") as f:
                return tomllib.load(f)["project"]["version"]
        except Exception:
            return "0.0.0"


__version__ = _load_version()

# helper containing a python 3 related warning
# if this is run with python 2
if sys.version_info < (3,):
    raise ImportError(
        '''
    You are running objection {0} on Python 2

    Unfortunately objection {0} and above are not compatible with Python 2.
    That's a bummer; sorry about that.  Make sure you have Python 3, pip >= and
    setuptools >= 24.2 to avoid these kinds of issues in the future:

     $ pip install pip setuptools --upgrade

    You could also setup a virtual Python 3 environment.

     $ pip install pip setuptools --upgrade
     $ pip install virtualenv
     $ virtualenv --python=python3 ~/virt-python3
     $ source ~/virt-python3/bin/activate

    This will make an isolated Python 3 installation available and active, ready
    to install and use objection.
    '''.format(__version__))
