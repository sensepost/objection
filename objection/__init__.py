import sys

__version__ = '1.2.5'

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
