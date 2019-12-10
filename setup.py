import os

from setuptools import setup, find_packages

from objection.__init__ import __version__


def _package_files(directory: str, suffix: str) -> list:
    """
        Get all of the file paths in the directory specified by suffix.

        :param directory:
        :return:
    """

    paths = []

    for (path, directories, filenames) in os.walk(directory):
        for filename in filenames:
            if filename.endswith(suffix):
                paths.append(os.path.join('..', path, filename))

    return paths


# here - where we are.
here = os.path.abspath(os.path.dirname(__file__))

# read the package requirements for install_requires
with open(os.path.join(here, 'requirements.txt'), 'r') as f:
    requirements = f.readlines()

# setup!
setup(
    name='objection',
    description='Instrumented Mobile Pentest Framework',
    license='GPL v3',

    author='Leon Jacobs',
    author_email='leon@sensepost.com',

    url='https://github.com/sensepost/objection',
    download_url='https://github.com/sensepost/objection/archive/' + __version__ + '.tar.gz',

    keywords=['mobile', 'instrumentation', 'pentest', 'frida', 'hook'],
    version=__version__,

    # include other files
    package_data={
        '': _package_files(os.path.join(here, 'objection/console/helpfiles'), '.txt') +
            _package_files(os.path.join(here, 'objection/utils/assets'), '.jks') +
            _package_files(os.path.join(here, 'objection/utils/assets'), '.js') +
            _package_files(os.path.join(here, 'objection/utils/assets'), '.xml') +
            [os.path.join(here, 'objection/agent.js')],  # Frida agent
    },
    packages=find_packages(),
    install_requires=requirements,
    python_requires='>=3.5',
    classifiers=[
        'Operating System :: OS Independent',
        'Natural Language :: English',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: JavaScript',
    ],
    entry_points={
        'console_scripts': [
            'objection=objection.console.cli:cli',
        ],
    },
)
